//! `rqz mount`: browse an archive as a read-only drive (Linux, via FUSE).
//!
//! Other platforms: use `rqz serve` and map the address as a network drive.

use anyhow::Result;
use rqz_core::archive::Archive;
use rqz_core::fsops::Source;
use std::path::Path;
use std::sync::Arc;

#[cfg(not(target_os = "linux"))]
pub fn run(_a: Arc<Archive<Source>>, _mountpoint: &Path, _snapshot: Option<u32>) -> Result<()> {
    anyhow::bail!(
        "`rqz mount` is built for Linux (FUSE). On Windows and macOS run `rqz serve <archive>` and \
         map the address as a network drive (see README)"
    )
}

#[cfg(target_os = "linux")]
pub fn run(a: Arc<Archive<Source>>, mountpoint: &Path, snapshot: Option<u32>) -> Result<()> {
    use anyhow::Context;
    use fuser::{
        Config, Errno, FileAttr, FileHandle, FileType, Filesystem, Generation, INodeNo, MountOption, OpenAccMode,
        OpenFlags, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry, ReplyOpen, Request,
    };
    use rqz_core::vfs::{Node, NodeKind, Vfs};
    use std::ffi::OsStr;
    use std::os::unix::fs::MetadataExt;
    use std::time::{Duration, UNIX_EPOCH};

    const TTL: Duration = Duration::from_secs(300);

    struct Fs {
        vfs: Vfs<Source>,
        uid: u32,
        gid: u32,
    }

    impl Fs {
        fn attr(&self, id: usize, n: &Node) -> FileAttr {
            let (kind, perm) = match n.kind {
                NodeKind::Dir => (FileType::Directory, 0o555),
                NodeKind::File => (FileType::RegularFile, (n.mode & !0o222) | 0o400),
                NodeKind::Symlink => (FileType::Symlink, 0o777),
            };
            let t = UNIX_EPOCH + Duration::from_secs(n.mtime.max(0) as u64);
            FileAttr {
                ino: INodeNo(id as u64 + 1),
                size: n.size,
                blocks: n.size.div_ceil(512),
                atime: t,
                mtime: t,
                ctime: t,
                crtime: t,
                kind,
                perm: (perm & 0o7777) as u16,
                nlink: if n.kind == NodeKind::Dir { 2 } else { 1 },
                uid: self.uid,
                gid: self.gid,
                rdev: 0,
                blksize: 4096,
                flags: 0,
            }
        }
        fn id(ino: INodeNo) -> usize {
            (ino.0 - 1) as usize
        }
    }

    impl Filesystem for Fs {
        fn lookup(&self, _req: &Request, parent: INodeNo, name: &OsStr, reply: ReplyEntry) {
            let found = name.to_str().and_then(|n| self.vfs.lookup(Self::id(parent), n));
            match found.and_then(|id| self.vfs.node(id).map(|n| (id, n))) {
                Some((id, n)) => reply.entry(&TTL, &self.attr(id, n), Generation(0)),
                None => reply.error(Errno::ENOENT),
            }
        }

        fn getattr(&self, _req: &Request, ino: INodeNo, _fh: Option<FileHandle>, reply: ReplyAttr) {
            let id = Self::id(ino);
            match self.vfs.node(id) {
                Some(n) => reply.attr(&TTL, &self.attr(id, n)),
                None => reply.error(Errno::ENOENT),
            }
        }

        fn readlink(&self, _req: &Request, ino: INodeNo, reply: ReplyData) {
            match self.vfs.node(Self::id(ino)).and_then(|n| n.link.as_ref()) {
                Some(l) => reply.data(l.as_bytes()),
                None => reply.error(Errno::EINVAL),
            }
        }

        fn open(&self, _req: &Request, ino: INodeNo, flags: OpenFlags, reply: ReplyOpen) {
            match self.vfs.node(Self::id(ino)) {
                None => reply.error(Errno::ENOENT),
                Some(n) if n.kind == NodeKind::Dir => reply.error(Errno::EISDIR),
                Some(_) if flags.acc_mode() != OpenAccMode::O_RDONLY => reply.error(Errno::EROFS),
                Some(_) => reply.opened(FileHandle(0), fuser::FopenFlags::empty()),
            }
        }

        fn read(
            &self,
            _req: &Request,
            ino: INodeNo,
            _fh: FileHandle,
            offset: u64,
            size: u32,
            _flags: OpenFlags,
            _lock: Option<fuser::LockOwner>,
            reply: ReplyData,
        ) {
            match self.vfs.read(Self::id(ino), offset, size as usize) {
                Ok(b) => reply.data(&b),
                Err(e) => {
                    eprintln!("rqz mount: read failed: {e}");
                    reply.error(Errno::EIO)
                }
            }
        }

        fn readdir(&self, _req: &Request, ino: INodeNo, _fh: FileHandle, offset: u64, mut reply: ReplyDirectory) {
            let id = Self::id(ino);
            let Some(n) = self.vfs.node(id) else { return reply.error(Errno::ENOENT) };
            if n.kind != NodeKind::Dir {
                return reply.error(Errno::ENOTDIR);
            }
            let mut entries: Vec<(u64, FileType, String)> =
                vec![(ino.0, FileType::Directory, ".".into()), (n.parent as u64 + 1, FileType::Directory, "..".into())];
            for &c in &n.children {
                if let Some(cn) = self.vfs.node(c) {
                    let k = match cn.kind {
                        NodeKind::Dir => FileType::Directory,
                        NodeKind::File => FileType::RegularFile,
                        NodeKind::Symlink => FileType::Symlink,
                    };
                    entries.push((c as u64 + 1, k, cn.name.clone()));
                }
            }
            for (i, (ino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
                if reply.add(INodeNo(ino), i as u64 + 1, kind, name) {
                    break;
                }
            }
            reply.ok();
        }
    }

    let meta =
        std::fs::metadata(mountpoint).with_context(|| format!("mount point {} must exist", mountpoint.display()))?;
    let fs = Fs { vfs: Vfs::new(a, snapshot), uid: meta.uid(), gid: meta.gid() };
    let mut cfg = Config::default();
    cfg.mount_options = vec![MountOption::RO, MountOption::FSName("razerq".into()), MountOption::Subtype("rqz".into())];
    eprintln!(
        "  mounted read-only at {}  (unmount with: fusermount3 -u {})",
        mountpoint.display(),
        mountpoint.display()
    );
    fuser::mount(fs, mountpoint, &cfg).context("FUSE mount failed (is FUSE installed and /dev/fuse accessible?)")?;
    Ok(())
}
