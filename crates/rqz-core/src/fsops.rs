//! Filesystem-level operations built on the core: pack, extract, import, protect, repair.
//! Not available in the WASM build.

use crate::archive::*;
use crate::error::{Error, Result};
use crate::index::*;
use crate::progress::{Event, Progress};
use crate::storage::ReadAt;
use crate::volume::{volume_file_name, VolumeSet, VolumeWriter, VOL_MAGIC};
use crate::writer::*;
use cap_fs_ext::DirExt;
use cap_std::{
    ambient_authority,
    fs::{Dir, OpenOptions as DirOpenOptions},
};
use std::collections::HashSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::{NamedTempFile, TempDir};

// ---------------------------------------------------------------- sources (file or volume set)

enum Inner {
    File(File),
    Vols(VolumeSet),
}

/// Something an archive can be read from: a single file, or a set of volumes on disk.
pub struct Source {
    inner: Inner,
    paths: Vec<Option<PathBuf>>,
    dir: PathBuf,
    base: String,
}

fn split_volume_name(name: &str) -> (String, bool) {
    match name.rsplit_once('.') {
        Some((b, d)) if d.len() >= 3 && d.bytes().all(|c| c.is_ascii_digit()) => (b.to_string(), true),
        _ => (name.to_string(), false),
    }
}

fn volume_siblings(path: &Path) -> Vec<PathBuf> {
    let dir = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf();
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let (base, _) = split_volume_name(&name);
    let mut v: Vec<PathBuf> = fs::read_dir(&dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            let n = p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let (b, is_vol) = split_volume_name(&n);
            is_vol && b == base
        })
        .collect();
    v.sort();
    v
}

impl Source {
    /// Open a single archive file, or a volume set given any one volume (or the bare name).
    pub fn open(path: &Path) -> Result<Source> {
        let real = if path.exists() {
            path.to_path_buf()
        } else {
            volume_siblings(path)
                .into_iter()
                .next()
                .ok_or_else(|| Error::Other(format!("{}: no such archive", path.display())))?
        };
        let mut f = File::open(&real)?;
        let mut magic = [0u8; 8];
        let n = f.read(&mut magic)?;
        let dir = real.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf();
        let name = real.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if n == 8 && magic == VOL_MAGIC {
            let files = volume_siblings(&real);
            let mut parts: Vec<Box<dyn ReadAt>> = Vec::new();
            for p in &files {
                parts.push(Box::new(File::open(p)?));
            }
            let set = VolumeSet::from_parts(parts)?;
            let mut paths = vec![None; set.count() as usize];
            for (i, sup) in set.supplied.iter().enumerate() {
                paths[i] = sup.map(|k| files[k].clone());
            }
            let base = split_volume_name(&name).0;
            Ok(Source { inner: Inner::Vols(set), paths, dir, base })
        } else {
            Ok(Source { inner: Inner::File(File::open(&real)?), paths: vec![], dir, base: name })
        }
    }

    pub fn volume_set(&self) -> Option<&VolumeSet> {
        match &self.inner {
            Inner::Vols(v) => Some(v),
            Inner::File(_) => None,
        }
    }
    pub fn volume_paths(&self) -> &[Option<PathBuf>] {
        &self.paths
    }
    pub fn is_split(&self) -> bool {
        matches!(self.inner, Inner::Vols(_))
    }
    pub fn dir(&self) -> &Path {
        &self.dir
    }
    pub fn base_name(&self) -> &str {
        &self.base
    }
    /// The first volume (or the file itself), for follow-up opens.
    pub fn first_path(&self) -> PathBuf {
        match &self.inner {
            Inner::Vols(_) => self.dir.join(volume_file_name(&self.base, 0)),
            Inner::File(_) => self.dir.join(&self.base),
        }
    }
}

impl ReadAt for Source {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        match &self.inner {
            Inner::File(f) => f.read_exact_at(buf, offset),
            Inner::Vols(v) => v.read_exact_at(buf, offset),
        }
    }
    fn len(&self) -> std::io::Result<u64> {
        match &self.inner {
            Inner::File(f) => ReadAt::len(f),
            Inner::Vols(v) => v.len(),
        }
    }
    fn notes(&self) -> Vec<String> {
        match &self.inner {
            Inner::File(_) => vec![],
            Inner::Vols(v) => v.notes(),
        }
    }
    fn is_incomplete(&self) -> bool {
        match &self.inner {
            Inner::File(_) => false,
            Inner::Vols(v) => v.is_incomplete(),
        }
    }
}

// ---------------------------------------------------------------- collecting input

pub struct Entry {
    pub src: PathBuf,
    pub rel: String,
    pub kind: u8,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    pub link: Option<String>,
}

fn mode_of(m: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        m.mode() & 0o7777
    }
    #[cfg(not(unix))]
    {
        if m.is_dir() || m.permissions().readonly() == false {
            0o755
        } else {
            0o644
        }
    }
}

fn mtime_of(m: &fs::Metadata) -> i64 {
    m.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// Turn a relative path into the archive's canonical form: `/`-separated, no `.`/`..`.
fn rel_name(p: &Path) -> Option<String> {
    let mut parts = Vec::new();
    for c in p.components() {
        match c {
            Component::Normal(s) => parts.push(s.to_str()?.to_owned()),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

pub fn collect(inputs: &[PathBuf], exclude: Option<&Path>) -> Result<(Vec<Entry>, u64)> {
    let mut out = Vec::new();
    let mut total = 0u64;
    let mut names = HashSet::new();
    let excl = exclude.and_then(|e| fs::canonicalize(e).ok());
    for input in inputs {
        let base = input.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let md = fs::symlink_metadata(input)?;
        let walker: Vec<PathBuf> = if md.is_dir() {
            walkdir::WalkDir::new(input)
                .follow_links(false)
                .sort_by_file_name()
                .into_iter()
                .map(|e| e.map(|e| e.into_path()).map_err(std::io::Error::from))
                .collect::<std::io::Result<_>>()?
        } else {
            vec![input.clone()]
        };
        for p in walker {
            if let (Some(x), Ok(c)) = (&excl, fs::canonicalize(&p)) {
                if &c == x {
                    continue;
                }
            }
            let m = fs::symlink_metadata(&p)?;
            let rel = match rel_name(p.strip_prefix(&base).unwrap_or(&p)) {
                Some(r) => r,
                None if p == *input && m.is_dir() && p.file_name().is_none() => continue,
                None => return Err(Error::Other(format!("cannot represent input path {}", p.display()))),
            };
            let (kind, link) = if m.file_type().is_symlink() {
                (KIND_SYMLINK, Some(fs::read_link(&p)?.to_string_lossy().replace('\\', "/")))
            } else if m.is_dir() {
                (KIND_DIR, None)
            } else if m.is_file() {
                (KIND_FILE, None)
            } else {
                return Err(Error::Unsupported(format!("cannot archive special file {}", p.display())));
            };
            validate_member_path(&rel)?;
            if !names.insert(rel.clone()) {
                return Err(Error::Other(format!("duplicate archive path {rel:?}")));
            }
            let size = if kind == KIND_FILE { m.len() } else { 0 };
            total += size;
            out.push(Entry { src: p, rel, kind, size, mode: mode_of(&m), mtime: mtime_of(&m), link });
        }
    }
    Ok((out, total))
}

fn parent_dir(path: &Path) -> &Path {
    path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."))
}

fn lock_path(path: &Path) -> Result<PathBuf> {
    if fs::symlink_metadata(path)?.file_type().is_symlink() {
        return Err(Error::Other("update the archive by its actual path instead of a symlink".into()));
    }
    let actual = fs::canonicalize(path)?;
    let mut name = actual.file_name().unwrap_or_default().to_os_string();
    name.push(".lock");
    Ok(actual.with_file_name(name))
}

fn lock_archive(path: &Path) -> Result<File> {
    let path = lock_path(path)?;
    let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
    file.try_lock().map_err(|e| Error::Other(format!("cannot lock archive for update: {e}")))?;
    Ok(file)
}

fn ensure_new(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(Error::Other(format!("output already exists: {}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

fn stage_file(dest: &Path, source: Option<&Path>) -> Result<NamedTempFile> {
    let mut file = NamedTempFile::new_in(parent_dir(dest))?;
    if let Some(source) = source {
        let mut input = File::open(source)?;
        std::io::copy(&mut input, file.as_file_mut())?;
        file.as_file().set_permissions(input.metadata()?.permissions())?;
        file.as_file_mut().rewind()?;
    }
    Ok(file)
}

fn publish_file(file: NamedTempFile, dest: &Path, replace: bool) -> Result<()> {
    file.as_file().sync_all()?;
    let result = if replace { file.persist(dest) } else { file.persist_noclobber(dest) };
    result.map_err(|e| Error::Io(e.error))?;
    #[cfg(unix)]
    File::open(parent_dir(dest))?.sync_all()?;
    Ok(())
}

/// Publish verified volumes under new names. If publication stops partway, roll back the names
/// this operation published; any existing archive or unrelated file remains in place.
fn publish_volumes(stage: &Path, dest: &Path, base: &str) -> Result<()> {
    let mut sources = volume_siblings(&stage.join(volume_file_name(base, 0)));
    if sources.is_empty() {
        return Err(Error::Other("no staged volumes to publish".into()));
    }
    // Publish the conventional entry point last.
    sources.rotate_left(1);
    let mut published = Vec::new();
    for source in sources {
        let path = dest.join(source.file_name().unwrap());
        let result = tempfile::TempPath::try_from_path(source)
            .and_then(|temp| temp.persist_noclobber(&path).map_err(|e| e.error));
        if let Err(e) = result {
            for p in published {
                let _ = fs::remove_file(p);
            }
            return Err(e.into());
        }
        published.push(path);
    }
    #[cfg(unix)]
    File::open(dest)?.sync_all()?;
    Ok(())
}

/// A writer for either a single file or a split-volume set.
#[allow(clippy::large_enum_variant)]
pub enum AnyWriter<'p> {
    File(ArchiveWriter<'p, File>, NamedTempFile),
    Vol(ArchiveWriter<'p, VolumeWriter>, TempDir),
}

impl<'p> AnyWriter<'p> {
    pub fn create(out: &Path, mut opts: PackOptions, progress: &'p dyn Progress) -> Result<Self> {
        ensure_new(out)?;
        if opts.volume_size > 0 {
            let base =
                out.file_name().and_then(|n| n.to_str()).ok_or_else(|| Error::Other("invalid volume name".into()))?;
            if !volume_siblings(out).is_empty() {
                return Err(Error::Other(format!("split output already exists: {}", out.display())));
            }
            let stage = tempfile::tempdir_in(parent_dir(out))?;
            // One ECC set across the whole archive.
            opts.set_bytes = u64::MAX;
            let vw = VolumeWriter::new(stage.path(), base, opts.volume_size);
            Ok(AnyWriter::Vol(ArchiveWriter::create(vw, opts, progress)?, stage))
        } else {
            let stage = stage_file(out, None)?;
            Ok(AnyWriter::File(ArchiveWriter::create(stage.reopen()?, opts, progress)?, stage))
        }
    }

    pub fn add_file<R: Read>(&mut self, path: &str, mode: u32, mtime: i64, r: &mut R) -> Result<u64> {
        match self {
            AnyWriter::File(w, _) => w.add_file(path, mode, mtime, r),
            AnyWriter::Vol(w, _) => w.add_file(path, mode, mtime, r),
        }
    }
    pub fn add_dir(&mut self, path: &str, mode: u32, mtime: i64) -> Result<()> {
        match self {
            AnyWriter::File(w, _) => w.add_dir(path, mode, mtime),
            AnyWriter::Vol(w, _) => w.add_dir(path, mode, mtime),
        }
    }
    pub fn add_symlink(&mut self, path: &str, target: &str, mode: u32, mtime: i64) -> Result<()> {
        match self {
            AnyWriter::File(w, _) => w.add_symlink(path, target, mode, mtime),
            AnyWriter::Vol(w, _) => w.add_symlink(path, target, mode, mtime),
        }
    }

    fn finish(self, out: &Path, verify: bool, password: Option<&str>, progress: &dyn Progress) -> Result<Summary> {
        match self {
            AnyWriter::File(w, stage) => {
                let (file, summary) = w.finish()?;
                file.sync_all()?;
                drop(file);
                if verify {
                    verify_written(stage.path(), password, progress)?;
                }
                publish_file(stage, out, false)?;
                Ok(summary)
            }
            AnyWriter::Vol(w, stage) => {
                let (vw, mut summary) = w.finish()?;
                let (paths, _) = vw.finalize()?;
                summary.volumes = paths.len() as u32;
                summary.file_len =
                    paths.iter().map(|p| fs::metadata(p).map(|m| m.len())).sum::<std::io::Result<u64>>()?;
                if verify {
                    verify_written(&paths[0], password, progress)?;
                }
                let base = out.file_name().unwrap().to_str().unwrap();
                publish_volumes(stage.path(), parent_dir(out), base)?;
                Ok(summary)
            }
        }
    }
}

fn feed(w: &mut AnyWriter<'_>, entries: &[Entry]) -> Result<()> {
    for e in entries {
        match e.kind {
            KIND_DIR => w.add_dir(&e.rel, e.mode, e.mtime)?,
            KIND_SYMLINK => w.add_symlink(&e.rel, e.link.as_deref().unwrap_or(""), e.mode, e.mtime)?,
            _ => {
                let mut f = File::open(&e.src)?;
                w.add_file(&e.rel, e.mode, e.mtime, &mut f)?;
            }
        }
    }
    Ok(())
}

pub struct PackResult {
    pub summary: Summary,
    pub verified: bool,
}

fn verify_written(path: &Path, password: Option<&str>, progress: &dyn Progress) -> Result<()> {
    progress.emit(Event::Stage("Verifying written archive".into()));
    let a = Archive::open(Source::open(path)?, password)?;
    let asm = a.assess(progress);
    if !asm.is_healthy() {
        return Err(Error::Other(
            "verification after write failed: the archive on disk does not match what was written (bad disk or bad RAM?)"
                .into(),
        ));
    }
    Ok(())
}

pub fn pack_paths(
    inputs: &[PathBuf],
    out: &Path,
    mut opts: PackOptions,
    verify: bool,
    progress: &dyn Progress,
) -> Result<PackResult> {
    ensure_new(out)?;
    let (entries, total) = collect(inputs, None)?;
    if entries.is_empty() {
        return Err(Error::Other("nothing to pack".into()));
    }
    opts.total_hint = Some(total);
    let pw = opts.password.clone();
    progress.emit(Event::Stage("Packing".into()));
    let mut w = AnyWriter::create(out, opts, progress)?;
    feed(&mut w, &entries)?;
    let summary = w.finish(out, verify, pw.as_deref(), progress)?;
    Ok(PackResult { summary, verified: verify })
}

pub fn add_paths(
    archive: &Path,
    inputs: &[PathBuf],
    opts: PackOptions,
    verify: bool,
    progress: &dyn Progress,
) -> Result<PackResult> {
    let pw = opts.password.clone();
    if Source::open(archive)?.is_split() {
        return Err(Error::Unsupported("adding to a split archive is not supported yet".into()));
    }
    let _lock = lock_archive(archive)?;
    let a = Archive::open(Source::open(archive)?, pw.as_deref())?;
    let (mut entries, mut total) = collect(inputs, Some(archive))?;
    let lock_name = lock_path(archive)?;
    entries.retain(|entry| {
        if fs::canonicalize(&entry.src).ok().as_ref() == Some(&lock_name) {
            total -= entry.size;
            false
        } else {
            true
        }
    });
    let mut opts = opts;
    opts.total_hint = Some(total);
    let stage = stage_file(archive, Some(archive))?;
    let f = stage.reopen()?;
    progress.emit(Event::Stage("Adding".into()));
    let mut w = ArchiveWriter::append(f, &a, opts, progress)?;
    for e in &entries {
        match e.kind {
            KIND_DIR => w.add_dir(&e.rel, e.mode, e.mtime)?,
            KIND_SYMLINK => w.add_symlink(&e.rel, e.link.as_deref().unwrap_or(""), e.mode, e.mtime)?,
            _ => {
                let mut f = File::open(&e.src)?;
                w.add_file(&e.rel, e.mode, e.mtime, &mut f)?;
            }
        }
    }
    let (f, summary) = w.finish()?;
    f.sync_all()?;
    drop(f);
    if verify {
        verify_written(stage.path(), pw.as_deref(), progress)?;
    }
    // Windows cannot replace the destination while our reader still holds it open.
    drop(a);
    publish_file(stage, archive, true)?;
    Ok(PackResult { summary, verified: verify })
}

pub fn add_protection_file(
    path: &Path,
    extra: Protect,
    password: Option<&str>,
    progress: &dyn Progress,
) -> Result<u32> {
    if Source::open(path)?.is_split() {
        return Err(Error::Unsupported("add-protection is not supported on split archives yet".into()));
    }
    let _lock = lock_archive(path)?;
    let a = Archive::open(Source::open(path)?, password)?;
    if extra.ratio == 0.0 {
        return Ok(0);
    }
    let stage = stage_file(path, Some(path))?;
    let mut w = ArchiveWriter::maintain(stage.reopen()?, &a, progress)?;
    let added = w.add_protection(extra)?;
    let (f, _) = w.finish()?;
    f.sync_all()?;
    drop(f);
    verify_written(stage.path(), password, progress)?;
    drop(a);
    publish_file(stage, path, true)?;
    Ok(added)
}

// ---------------------------------------------------------------- sidecar (detached)

pub fn sidecar_path(target: &Path) -> PathBuf {
    let mut s = target.as_os_str().to_owned();
    s.push(".rqzp");
    PathBuf::from(s)
}

pub fn protect_file(
    target: &Path,
    out: &Path,
    opts: PackOptions,
    verify: bool,
    progress: &dyn Progress,
) -> Result<Summary> {
    let name = target
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| Error::Other("invalid protected file name".into()))?;
    validate_member_path(name)?;
    let t = File::open(target)?;
    ensure_new(out)?;
    let stage = stage_file(out, None)?;
    let f = stage.reopen()?;
    progress.emit(Event::Stage("Protecting".into()));
    let w = ArchiveWriter::create_detached(f, opts, t, name, progress)?;
    let (f, summary) = w.finish()?;
    f.sync_all()?;
    drop(f);
    if verify {
        let mut a = Archive::open(Source::open(stage.path())?, None)?;
        a.attach_target(Box::new(File::open(target)?));
        if !a.assess(progress).is_healthy() {
            return Err(Error::Other("sidecar verification failed".into()));
        }
    }
    publish_file(stage, out, false)?;
    Ok(summary)
}

/// Open a path as either a normal archive or a detached sidecar (locating its target).
pub fn open_any(
    path: &Path,
    password: Option<&str>,
    target: Option<&Path>,
) -> Result<(Archive<Source>, Option<PathBuf>)> {
    let mut a = Archive::open(Source::open(path)?, password)?;
    let mut tpath = None;
    if let Some(d) = a.index.detached.clone() {
        let t = if let Some(p) = target {
            p.to_path_buf()
        } else {
            validate_member_path(&d.target_name)?;
            if d.target_name.contains('/') {
                return Err(Error::Corrupt("sidecar target name must be a single component".into()));
            }
            parent_dir(path).join(&d.target_name)
        };
        a.attach_target(Box::new(
            File::open(&t).map_err(|e| Error::Other(format!("cannot open protected file {}: {e}", t.display())))?,
        ));
        tpath = Some(t);
    }
    Ok((a, tpath))
}

// ---------------------------------------------------------------- repair

#[derive(Default)]
pub struct RepairOptions {
    pub out: Option<PathBuf>,
    pub in_place: bool,
    pub donor: Option<PathBuf>,
    pub password: Option<String>,
    pub target: Option<PathBuf>,
}

pub struct RepairReport {
    pub before: Health,
    pub after: Health,
    pub plan: RepairPlan,
    pub written: Option<PathBuf>,
    /// The archive is a split-volume set; `written` is then its first volume.
    pub split: bool,
    pub archive_output: Option<PathBuf>,
    pub stored_bytes_only: bool,
    pub outputs: Vec<PathBuf>,
    pub verified: bool,
}

pub fn repaired_name(p: &Path) -> PathBuf {
    let stem = p.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let ext = p.extension().map(|e| format!(".{}", e.to_string_lossy())).unwrap_or_default();
    p.with_file_name(format!("{stem}.repaired{ext}"))
}

pub fn apply_patches_file(f: &mut File, patches: &[Patch]) -> Result<()> {
    for p in patches {
        f.seek(SeekFrom::Start(p.offset))?;
        f.write_all(&p.data)?;
    }
    f.sync_all()?;
    Ok(())
}

/// Build a complete split set in a private directory before publishing it.
fn stage_repair_volumes(set: &VolumeSet, src: &Source, patches: &[Patch], stage: &Path) -> Result<PathBuf> {
    let base = src.base_name();
    for (i, p) in src.volume_paths().iter().enumerate() {
        if let Some(p) = p {
            fs::copy(p, stage.join(volume_file_name(base, i as u32)))?;
        }
    }
    for rw in set.plan_volume_patches(patches) {
        let path = stage.join(volume_file_name(base, rw.index));
        let mut f = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        if let Some(h) = &rw.header {
            f.seek(SeekFrom::Start(0))?;
            f.write_all(h)?;
        }
        for p in &rw.patches {
            f.seek(SeekFrom::Start(p.offset))?;
            f.write_all(&p.data)?;
        }
        f.set_len(set.vh_len + rw.payload_len)?;
        f.sync_all()?;
    }
    for path in volume_siblings(&stage.join(volume_file_name(base, 0))) {
        File::open(path)?.sync_all()?;
    }
    Ok(stage.join(volume_file_name(base, 0)))
}

fn sidecar_for_target(
    source: &Path,
    target_output: &Path,
    archive_patches: &[Patch],
    progress: &dyn Progress,
) -> Result<(NamedTempFile, PathBuf)> {
    let output = sidecar_path(target_output);
    ensure_new(&output)?;
    let mut stage = stage_file(&output, Some(source))?;
    apply_patches_file(stage.as_file_mut(), archive_patches)?;
    let sidecar = Archive::open(Source::open(stage.path())?, None)?;
    let name = target_output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| Error::Other("invalid repaired target name".into()))?;
    let writer = ArchiveWriter::rebind_sidecar(stage.reopen()?, &sidecar, name, progress)?;
    let (file, _) = writer.finish()?;
    file.sync_all()?;
    Ok((stage, output))
}

fn repair_assessment(
    archive: &Path,
    target: Option<&Path>,
    password: Option<&str>,
    progress: &dyn Progress,
) -> Result<Health> {
    let (a, _) = open_any(archive, password, target)?;
    Ok(a.assess(progress).health)
}

impl RepairReport {
    pub fn exit_code(&self) -> i32 {
        if self.after != Health::Healthy || !self.plan.lost_blocks.is_empty() {
            2
        } else if self.outputs.is_empty() {
            0
        } else {
            1
        }
    }
}

pub fn repair_file(path: &Path, o: &RepairOptions, progress: &dyn Progress) -> Result<RepairReport> {
    if o.in_place && o.out.is_some() {
        return Err(Error::Other("choose either an output or in-place repair".into()));
    }
    let password = o.password.as_deref();
    let _lock = if o.in_place {
        let source = Source::open(path)?;
        if source.is_split() {
            return Err(Error::Unsupported("choose a new output folder to repair a split archive".into()));
        }
        Some(lock_archive(path)?)
    } else {
        None
    };
    let (a, target) = open_any(path, password, o.target.as_deref())?;
    if o.in_place && a.header.detached() {
        return Err(Error::Unsupported("choose a new output to repair a detached sidecar".into()));
    }
    let before = a.assess(progress);
    let donor = o.donor.as_ref().map(|p| Archive::open(Source::open(p)?, None)).transpose()?;
    let mut plan = a.plan_repair(&before, donor.as_ref().map(|d| d as &dyn Donor), progress);
    let split = a.source().is_split();
    let incomplete = a.source().is_incomplete();
    let mut report = RepairReport {
        before: before.health,
        after: before.health,
        plan: RepairPlan::default(),
        written: None,
        split,
        archive_output: None,
        stored_bytes_only: before.stored_bytes_only,
        outputs: Vec::new(),
        verified: false,
    };
    if let Some(set) = a.source().volume_set() {
        if (!plan.patches.is_empty() || incomplete) && a.has_valid_index() {
            let src = a.source();
            let dest = o.out.clone().unwrap_or_else(|| src.dir().join("repaired"));
            fs::create_dir_all(&dest)?;
            if !volume_siblings(&dest.join(volume_file_name(src.base_name(), 0))).is_empty() {
                return Err(Error::Other(format!("split output already exists in {}", dest.display())));
            }
            let stage = tempfile::tempdir_in(&dest)?;
            let first = stage_repair_volumes(set, src, &plan.patches, stage.path())?;
            report.after = repair_assessment(&first, None, password, progress)?;
            report.verified = report.after == Health::Healthy;
            publish_volumes(stage.path(), &dest, src.base_name())?;
            report.outputs = volume_siblings(&dest.join(first.file_name().unwrap()));
            report.written = Some(dest.join(first.file_name().unwrap()));
            report.archive_output = report.written.clone();
        }
    } else if !plan.is_empty() {
        let target_changes = !plan.target_patches.is_empty() || plan.target_len.is_some();
        // A repaired detached target gets a matching sidecar beside it.
        // Verify the staged pair before publishing either file.
        let mut target_stage = None;
        if target_changes {
            let source = target.as_ref().ok_or_else(|| Error::Other("no protected file to repair".into()))?;
            let output = o.out.clone().unwrap_or_else(|| repaired_name(source));
            ensure_new(&output)?;
            let mut file = stage_file(&output, Some(source))?;
            apply_patches_file(file.as_file_mut(), &plan.target_patches)?;
            if let Some(len) = plan.target_len {
                file.as_file().set_len(len)?;
            }
            target_stage = Some((file, output));
        }
        let archive_stage = if let Some((_, output)) = &target_stage {
            Some(sidecar_for_target(path, output, &plan.patches, progress)?)
        } else if !plan.patches.is_empty() {
            let dest =
                if o.in_place { path.to_path_buf() } else { o.out.clone().unwrap_or_else(|| repaired_name(path)) };
            if !o.in_place {
                ensure_new(&dest)?;
            }
            let mut file = stage_file(&dest, Some(path))?;
            apply_patches_file(file.as_file_mut(), &plan.patches)?;
            Some((file, dest))
        } else {
            None
        };
        report.after = repair_assessment(
            archive_stage.as_ref().map_or(path, |(file, _)| file.path()),
            target_stage.as_ref().map(|(file, _)| file.path()).or(target.as_deref()),
            password,
            progress,
        )
        .unwrap_or_else(|e| {
            plan.notes.push(format!("output verification failed: {e}"));
            Health::Damaged
        });
        report.verified = report.after == Health::Healthy;
        if o.in_place && !report.verified {
            return Err(Error::Other("repair did not verify; originals were preserved".into()));
        }
        // The donor may also point to the original archive.
        drop(donor);
        drop(a);
        if let Some((file, output)) = target_stage {
            publish_file(file, &output, false)?;
            report.outputs.push(output);
        }
        if let Some((file, dest)) = archive_stage {
            if let Err(e) = publish_file(file, &dest, o.in_place) {
                if !o.in_place {
                    for published in &report.outputs {
                        let _ = fs::remove_file(published);
                    }
                }
                return Err(e);
            }
            report.archive_output = Some(dest.clone());
            report.outputs.push(dest);
        }
        report.written = report.outputs.first().cloned();
    }
    if report.after != Health::Healthy && plan.notes.is_empty() {
        plan.notes.push("damage remains; extract what is available or try a second copy".into());
    }
    report.plan = plan;
    Ok(report)
}

// ---------------------------------------------------------------- extract

fn open_child_dir(parent: &Dir, name: &str) -> std::io::Result<Dir> {
    match parent.open_dir_nofollow(name) {
        Ok(dir) => Ok(dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            match parent.create_dir(name) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(e),
            }
            parent.open_dir_nofollow(name)
        }
        Err(e) => Err(e),
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn publish_restored(dir: &Dir, temp: &str, name: &str) -> std::io::Result<()> {
    use rustix::fs::{renameat_with, RenameFlags};
    use rustix::io::Errno;
    match renameat_with(dir, temp, dir, name, RenameFlags::NOREPLACE) {
        Ok(()) => Ok(()),
        Err(Errno::NOSYS | Errno::INVAL | Errno::OPNOTSUPP) => dir.hard_link(temp, dir, name),
        Err(e) => Err(e.into()),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn publish_restored(dir: &Dir, temp: &str, name: &str) -> std::io::Result<()> {
    // On Windows use MoveFile via std/cap-std only for replacement. A hard link is the
    // no-clobber publication operation on filesystems that support it.
    dir.hard_link(temp, dir, name)
}

fn restore_file<S: ReadAt>(
    archive: &Archive<S>,
    entry: &FileEntry,
    dir: &Dir,
    name: &str,
    cache: &mut BlockCache,
) -> Result<()> {
    let rand = crate::crypto::random_bytes::<16>();
    let temp = format!(".rqz-restore-{:032x}", u128::from_le_bytes(rand));
    let file = dir.open_with(&temp, DirOpenOptions::new().write(true).create_new(true))?.into_std();
    let result = (|| -> Result<()> {
        let mut out = std::io::BufWriter::new(file);
        archive.extract_to(entry, &mut out, cache)?;
        let file = out.into_inner().map_err(|e| Error::Io(e.into_error()))?;
        let _ = file.set_modified(UNIX_EPOCH + Duration::from_secs(entry.mtime.max(0) as u64));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(entry.mode & 0o777))?;
        }
        file.sync_all()?;
        drop(file);
        // Publish without following or replacing any existing destination entry.
        publish_restored(dir, &temp, name)?;
        Ok(())
    })();
    let cleanup = dir.remove_file(&temp);
    result?;
    match cleanup {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    Ok(())
}

#[derive(Default, Debug)]
pub struct ExtractReport {
    pub files: u64,
    pub bytes: u64,
    pub lost: Vec<String>,
    pub skipped: Vec<String>,
    pub healed_groups: usize,
    pub inventory_complete: bool,
}

pub fn extract_archive(
    a: &Archive<Source>,
    dest: &Path,
    filter: &[String],
    snapshot: Option<u32>,
    progress: &dyn Progress,
) -> Result<ExtractReport> {
    if a.locked {
        return Err(Error::PasswordRequired);
    }
    if a.header.detached() {
        return Err(Error::Unsupported("use repair with the protected file to restore a detached sidecar".into()));
    }
    fs::create_dir_all(dest)?;
    let root = Dir::open_ambient_dir(dest, ambient_authority())?;
    let healed_before = a.healed_groups();
    let mut rep = ExtractReport { inventory_complete: a.has_complete_inventory(), ..Default::default() };
    let mut cache = BlockCache::default();
    let wanted = |p: &str| {
        filter.is_empty() || filter.iter().any(|f| p == f || p.starts_with(&format!("{}/", f.trim_end_matches('/'))))
    };
    if let Some(id) = snapshot {
        if !a.index.snapshots.iter().any(|snapshot| snapshot.id == id) {
            return Err(Error::Other(format!("unknown snapshot {id}")));
        }
    }
    let visible = a.visible_files(snapshot);
    for selection in filter {
        let prefix = format!("{}/", selection.trim_end_matches('/'));
        if !visible.iter().any(|f| f.path == *selection || f.path.starts_with(&prefix)) {
            rep.skipped.push(format!("{selection} (not in the file inventory)"));
        }
    }
    let entries: Vec<&FileEntry> = visible.into_iter().filter(|f| wanted(&f.path)).collect();
    let total: u64 = entries.iter().map(|f| f.size).sum();
    progress.emit(Event::Stage("Extracting".into()));
    let mut done = 0u64;
    for f in entries {
        let result = (|| -> Result<()> {
            validate_member_path(&f.path)?;
            let mut components = f.path.split('/');
            let mut dir = root.try_clone()?;
            let mut name = components.next().unwrap_or_default();
            for next in components {
                dir = open_child_dir(&dir, name)?;
                name = next;
            }
            match f.kind {
                KIND_DIR => {
                    open_child_dir(&dir, name)?;
                }
                KIND_SYMLINK => {
                    #[cfg(unix)]
                    {
                        let target = f.link.as_deref().unwrap_or("");
                        let depth = f.path.bytes().filter(|&b| b == b'/').count();
                        let mut available = depth;
                        if target.is_empty()
                            || Path::new(target).components().any(|component| match component {
                                Component::Normal(_) => {
                                    available += 1;
                                    false
                                }
                                Component::CurDir => false,
                                Component::ParentDir if available > 0 => {
                                    available -= 1;
                                    false
                                }
                                _ => true,
                            })
                        {
                            return Err(Error::Other("symlink target escapes the extraction root".into()));
                        }
                        dir.symlink_contents(target, name)?;
                    }
                    #[cfg(not(unix))]
                    return Err(Error::Unsupported("symlinks are not extracted on this platform".into()));
                }
                _ => {
                    restore_file(a, f, &dir, name, &mut cache)?;
                    rep.files += 1;
                    rep.bytes += f.size;
                }
            }
            Ok(())
        })();
        match result {
            Ok(()) => {}
            Err(Error::BlockLost(_)) => rep.lost.push(f.path.clone()),
            Err(e) => rep.skipped.push(format!("{} ({e})", f.path)),
        }
        done += f.size;
        progress.emit(Event::Progress { done, total });
    }
    rep.healed_groups = a.healed_groups().saturating_sub(healed_before);
    Ok(rep)
}

// ---------------------------------------------------------------- import

fn dos_to_unix(y: i64, mo: i64, d: i64, h: i64, mi: i64, s: i64) -> i64 {
    // days since 1970-01-01 (civil-from-days inverse)
    let y = if mo <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let doy = (153 * (mo + if mo > 2 { -3 } else { 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    days * 86400 + h * 3600 + mi * 60 + s
}

pub fn import_zip(
    src: &Path,
    out: &Path,
    mut opts: PackOptions,
    verify: bool,
    progress: &dyn Progress,
) -> Result<PackResult> {
    let zerr = |e: zip::result::ZipError| Error::Other(format!("zip: {e}"));
    let mut z = zip::ZipArchive::new(File::open(src)?).map_err(zerr)?;
    let mut total = 0u64;
    for i in 0..z.len() {
        total += z.by_index(i).map_err(zerr)?.size();
    }
    opts.total_hint = Some(total);
    let pw = opts.password.clone();
    progress.emit(Event::Stage("Importing (transcoding)".into()));
    let mut w = AnyWriter::create(out, opts, progress)?;
    for i in 0..z.len() {
        let mut e = z.by_index(i).map_err(zerr)?;
        let Some(rel) = e.enclosed_name().and_then(|p| rel_name(&p)) else {
            return Err(Error::Other(format!("unsafe ZIP entry {}", e.name())));
        };
        let mtime = e
            .last_modified()
            .map(|t| {
                dos_to_unix(
                    t.year() as i64,
                    t.month() as i64,
                    t.day() as i64,
                    t.hour() as i64,
                    t.minute() as i64,
                    t.second() as i64,
                )
            })
            .unwrap_or(0);
        if e.is_dir() {
            w.add_dir(&rel, e.unix_mode().unwrap_or(0o755), mtime)?;
        } else if e.is_symlink() {
            let mut target = String::new();
            (&mut e).take(1 << 16).read_to_string(&mut target)?;
            if target.is_empty() || target.len() == 1 << 16 {
                return Err(Error::Other(format!("invalid ZIP symlink target for {rel}")));
            }
            w.add_symlink(&rel, &target, e.unix_mode().unwrap_or(0o777), mtime)?;
        } else {
            let mode = e.unix_mode().unwrap_or(0o644);
            w.add_file(&rel, mode, mtime, &mut e)?;
        }
    }
    let summary = w.finish(out, verify, pw.as_deref(), progress)?;
    Ok(PackResult { summary, verified: verify })
}

pub fn import_tar(
    src: &Path,
    out: &Path,
    mut opts: PackOptions,
    verify: bool,
    progress: &dyn Progress,
) -> Result<PackResult> {
    let name = src.to_string_lossy().to_ascii_lowercase();
    let gz = name.ends_with(".gz") || name.ends_with(".tgz");
    let len = fs::metadata(src)?.len();
    opts.total_hint = Some(if gz { len * 3 } else { len });
    let pw = opts.password.clone();
    let reader: Box<dyn Read> =
        if gz { Box::new(flate2::read::GzDecoder::new(File::open(src)?)) } else { Box::new(File::open(src)?) };
    let mut tar = tar::Archive::new(reader);
    progress.emit(Event::Stage("Importing (transcoding)".into()));
    let mut w = AnyWriter::create(out, opts, progress)?;
    for e in tar.entries()? {
        let mut e = e?;
        let path = e.path()?.into_owned();
        let Some(rel) = rel_name(&path) else {
            return Err(Error::Other(format!("unsafe tar entry {}", path.display())));
        };
        let mode = e.header().mode().unwrap_or(0o644);
        let mtime = e.header().mtime().unwrap_or(0) as i64;
        let t = e.header().entry_type();
        if t.is_dir() {
            w.add_dir(&rel, mode, mtime)?;
        } else if t.is_symlink() {
            let target = e.link_name()?.map(|l| l.to_string_lossy().into_owned()).unwrap_or_default();
            w.add_symlink(&rel, &target, mode, mtime)?;
        } else if t.is_file() {
            w.add_file(&rel, mode, mtime, &mut e)?;
        } else {
            return Err(Error::Unsupported(format!("cannot import tar entry {rel} of type {t:?}")));
        }
    }
    let summary = w.finish(out, verify, pw.as_deref(), progress)?;
    Ok(PackResult { summary, verified: verify })
}

// ---------------------------------------------------------------- dev helpers

/// Copy `src` to `dst` and corrupt `spans` random regions of `span_len` bytes (demos and tests).
pub fn damage_copy(src: &Path, dst: &Path, spans: u32, span_len: usize, seed: u64) -> Result<Vec<(u64, usize)>> {
    ensure_new(dst)?;
    let mut stage = stage_file(dst, Some(src))?;
    let f = stage.as_file_mut();
    let len = f.metadata()?.len();
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let mut hits = Vec::new();
    let lo = 8192u64.min(len / 2);
    for _ in 0..spans {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        let span = span_len.min((len - lo) as usize);
        let at = lo + s % (len - lo - span as u64).max(1);
        let mut buf = vec![0u8; span];
        f.seek(SeekFrom::Start(at))?;
        f.read_exact(&mut buf)?;
        for b in &mut buf {
            *b ^= 0x5A;
        }
        f.seek(SeekFrom::Start(at))?;
        f.write_all(&buf)?;
        hits.push((at, span));
    }
    publish_file(stage, dst, false)?;
    Ok(hits)
}

pub fn systime(t: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(t.max(0) as u64)
}
