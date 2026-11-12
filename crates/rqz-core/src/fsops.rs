//! Filesystem-level operations built on the core: pack, extract, import, protect, repair.
//! Not available in the WASM build.

use crate::archive::*;
use crate::error::{Error, Result};
use crate::index::*;
use crate::progress::{Event, Progress};
use crate::storage::ReadAt;
use crate::volume::{volume_file_name, VolumeSet, VolumeWriter, VOL_MAGIC};
use crate::writer::*;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            Component::CurDir => {}
            _ => return None,
        }
    }
    (!parts.is_empty()).then(|| parts.join("/"))
}

pub fn collect(inputs: &[PathBuf], exclude: Option<&Path>) -> Result<(Vec<Entry>, u64)> {
    let mut out = Vec::new();
    let mut total = 0u64;
    let excl = exclude.and_then(|e| fs::canonicalize(e).ok());
    for input in inputs {
        let base = input.parent().map(|p| p.to_path_buf()).unwrap_or_default();
        let md = fs::symlink_metadata(input)?;
        let walker: Vec<PathBuf> = if md.is_dir() {
            walkdir::WalkDir::new(input)
                .follow_links(false)
                .sort_by_file_name()
                .into_iter()
                .filter_map(|e| e.ok())
                .map(|e| e.into_path())
                .collect()
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
                None => continue,
            };
            let (kind, link) = if m.file_type().is_symlink() {
                (KIND_SYMLINK, Some(fs::read_link(&p)?.to_string_lossy().replace('\\', "/")))
            } else if m.is_dir() {
                (KIND_DIR, None)
            } else if m.is_file() {
                (KIND_FILE, None)
            } else {
                continue;
            };
            let size = if kind == KIND_FILE { m.len() } else { 0 };
            total += size;
            out.push(Entry { src: p, rel, kind, size, mode: mode_of(&m), mtime: mtime_of(&m), link });
        }
    }
    Ok((out, total))
}

/// A writer for either a single file or a split-volume set.
#[allow(clippy::large_enum_variant)]
pub enum AnyWriter<'p> {
    File(ArchiveWriter<'p, File>),
    Vol(ArchiveWriter<'p, VolumeWriter>),
}

impl<'p> AnyWriter<'p> {
    pub fn create(out: &Path, mut opts: PackOptions, progress: &'p dyn Progress) -> Result<Self> {
        if opts.volume_size > 0 {
            let dir = out.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new(".")).to_path_buf();
            let base = out.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            // One ECC set across the whole archive, so recovery data is striped over every volume.
            opts.set_bytes = u64::MAX;
            // Remove leftovers from an earlier run with the same name.
            for old in volume_siblings(&dir.join(volume_file_name(&base, 0))) {
                let _ = fs::remove_file(old);
            }
            let vw = VolumeWriter::new(&dir, &base, opts.volume_size);
            Ok(AnyWriter::Vol(ArchiveWriter::create(vw, opts, progress)?))
        } else {
            let f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(out)?;
            Ok(AnyWriter::File(ArchiveWriter::create(f, opts, progress)?))
        }
    }

    pub fn add_file<R: Read>(&mut self, path: &str, mode: u32, mtime: i64, r: &mut R) -> Result<u64> {
        match self {
            AnyWriter::File(w) => w.add_file(path, mode, mtime, r),
            AnyWriter::Vol(w) => w.add_file(path, mode, mtime, r),
        }
    }
    pub fn add_dir(&mut self, path: &str, mode: u32, mtime: i64) -> Result<()> {
        match self {
            AnyWriter::File(w) => w.add_dir(path, mode, mtime),
            AnyWriter::Vol(w) => w.add_dir(path, mode, mtime),
        }
    }
    pub fn add_symlink(&mut self, path: &str, target: &str, mode: u32, mtime: i64) -> Result<()> {
        match self {
            AnyWriter::File(w) => w.add_symlink(path, target, mode, mtime),
            AnyWriter::Vol(w) => w.add_symlink(path, target, mode, mtime),
        }
    }

    /// Finish; returns the summary and the path to open for verification (first volume or the file).
    pub fn finish(self, out: &Path) -> Result<(Summary, PathBuf)> {
        match self {
            AnyWriter::File(w) => {
                let (f, summary) = w.finish()?;
                f.sync_all()?;
                Ok((summary, out.to_path_buf()))
            }
            AnyWriter::Vol(w) => {
                let (vw, mut summary) = w.finish()?;
                let (paths, _) = vw.finalize()?;
                summary.volumes = paths.len() as u32;
                summary.file_len = paths.iter().filter_map(|p| fs::metadata(p).ok()).map(|m| m.len()).sum();
                Ok((summary, paths[0].clone()))
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
    let (entries, total) = collect(inputs, Some(out))?;
    opts.total_hint = Some(total);
    let pw = opts.password.clone();
    progress.emit(Event::Stage("Packing".into()));
    let mut w = AnyWriter::create(out, opts, progress)?;
    feed(&mut w, &entries)?;
    let (summary, first) = w.finish(out)?;
    if verify {
        verify_written(&first, pw.as_deref(), progress)?;
    }
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
    let src = Source::open(archive)?;
    if src.is_split() {
        return Err(Error::Unsupported("adding to a split archive is not supported yet".into()));
    }
    let a = Archive::open(src, pw.as_deref())?;
    let (entries, total) = collect(inputs, Some(archive))?;
    let mut opts = opts;
    opts.total_hint = Some(total);
    let f = OpenOptions::new().read(true).write(true).open(archive)?;
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
        verify_written(archive, pw.as_deref(), progress)?;
    }
    Ok(PackResult { summary, verified: verify })
}

pub fn add_protection_file(
    path: &Path,
    extra: Protect,
    password: Option<&str>,
    progress: &dyn Progress,
) -> Result<u32> {
    let src = Source::open(path)?;
    if src.is_split() {
        return Err(Error::Unsupported("add-protection is not supported on split archives yet".into()));
    }
    let a = Archive::open(src, password)?;
    let f = OpenOptions::new().read(true).write(true).open(path)?;
    let mut w = ArchiveWriter::append(f, &a, PackOptions::default(), progress)?;
    let added = w.add_protection(extra)?;
    let (f, _) = w.finish()?;
    f.sync_all()?;
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
    let name = target.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let t = File::open(target)?;
    let f = OpenOptions::new().read(true).write(true).create(true).truncate(true).open(out)?;
    progress.emit(Event::Stage("Protecting".into()));
    let w = ArchiveWriter::create_detached(f, opts, t, &name, progress)?;
    let (f, summary) = w.finish()?;
    f.sync_all()?;
    drop(f);
    if verify {
        let mut a = Archive::open(Source::open(out)?, None)?;
        a.attach_target(Box::new(File::open(target)?));
        if !a.assess(progress).is_healthy() {
            return Err(Error::Other("sidecar verification failed".into()));
        }
    }
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
        let t = target
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| path.parent().unwrap_or(Path::new(".")).join(&d.target_name));
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

/// Write a repaired copy of a split archive. Returns the first volume of the result.
fn repair_volumes(set: &VolumeSet, src: &Source, patches: &[Patch], o: &RepairOptions) -> Result<PathBuf> {
    let rewrites = set.plan_volume_patches(patches);
    let outdir =
        if o.in_place { src.dir().to_path_buf() } else { o.out.clone().unwrap_or_else(|| src.dir().join("repaired")) };
    fs::create_dir_all(&outdir)?;
    let base = src.base_name().to_string();
    if !o.in_place {
        for (i, p) in src.volume_paths().iter().enumerate() {
            if let Some(p) = p {
                fs::copy(p, outdir.join(volume_file_name(&base, i as u32)))?;
            }
        }
    }
    for rw in rewrites {
        let path = outdir.join(volume_file_name(&base, rw.index));
        let mut f = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)?;
        if rw.create {
            f.set_len(set.vh_len + rw.payload_len)?;
        }
        if let Some(h) = &rw.header {
            f.seek(SeekFrom::Start(0))?;
            f.write_all(h)?;
        }
        for p in &rw.patches {
            f.seek(SeekFrom::Start(p.offset))?;
            f.write_all(&p.data)?;
        }
        if f.metadata()?.len() < set.vh_len + rw.payload_len {
            f.set_len(set.vh_len + rw.payload_len)?;
        }
        f.sync_all()?;
    }
    Ok(outdir.join(volume_file_name(&base, 0)))
}

pub fn repair_file(path: &Path, o: &RepairOptions, progress: &dyn Progress) -> Result<RepairReport> {
    let (a, tpath) = open_any(path, o.password.as_deref(), o.target.as_deref())?;
    let asm = a.assess(progress);
    let donor = match &o.donor {
        Some(d) => Some(Archive::open(Source::open(d)?, o.password.as_deref())?),
        None => None,
    };
    let plan = a.plan_repair(&asm, donor.as_ref().map(|d| d as &dyn Donor), progress);
    let split = a.source().is_split();
    let incomplete = a.source().is_incomplete();
    if plan.is_empty() && !incomplete {
        return Ok(RepairReport { before: asm.health, after: asm.health, plan, written: None, split });
    }
    let mut written = None;
    if split {
        let set = a.source().volume_set().expect("split source has a volume set");
        written = Some(repair_volumes(set, a.source(), &plan.patches, o)?);
    } else if !plan.patches.is_empty() {
        let dest = if o.in_place { path.to_path_buf() } else { o.out.clone().unwrap_or_else(|| repaired_name(path)) };
        if !o.in_place {
            fs::copy(path, &dest)?;
        }
        let mut f = OpenOptions::new().read(true).write(true).open(&dest)?;
        apply_patches_file(&mut f, &plan.patches)?;
        written = Some(dest);
    }
    if !plan.target_patches.is_empty() {
        let t = tpath.clone().ok_or_else(|| Error::Other("no protected file to repair".into()))?;
        let dest = if o.in_place { t.clone() } else { repaired_name(&t) };
        if !o.in_place {
            fs::copy(&t, &dest)?;
        }
        let mut f = OpenOptions::new().read(true).write(true).open(&dest)?;
        apply_patches_file(&mut f, &plan.target_patches)?;
        written = Some(dest);
    }
    let after = match &written {
        Some(w) if tpath.is_none() => Archive::open(Source::open(w)?, o.password.as_deref())
            .map(|r| r.assess(progress).health)
            .unwrap_or(Health::Damaged),
        Some(w) => {
            let mut r = Archive::open(Source::open(path)?, o.password.as_deref())?;
            r.attach_target(Box::new(File::open(w)?));
            r.assess(progress).health
        }
        None => asm.health,
    };
    Ok(RepairReport { before: asm.health, after, plan, written, split })
}

// ---------------------------------------------------------------- extract

fn safe_join(dest: &Path, rel: &str) -> Option<PathBuf> {
    let mut p = dest.to_path_buf();
    for c in rel.split('/') {
        if c.is_empty()
            || c == "."
            || c == ".."
            || c.contains('\\')
            || c.contains('\0')
            || (cfg!(windows) && c.contains(':'))
        {
            return None;
        }
        p.push(c);
    }
    Some(p)
}

/// Refuse to write through a symlink that already exists inside the destination.
fn ancestors_are_plain(dest: &Path, full: &Path) -> bool {
    let Ok(rest) = full.strip_prefix(dest) else { return false };
    let mut cur = dest.to_path_buf();
    let comps: Vec<_> = rest.components().collect();
    for c in comps.iter().take(comps.len().saturating_sub(1)) {
        cur.push(c);
        if let Ok(m) = fs::symlink_metadata(&cur) {
            if m.file_type().is_symlink() {
                return false;
            }
        }
    }
    true
}

#[derive(Default, Debug)]
pub struct ExtractReport {
    pub files: u64,
    pub bytes: u64,
    pub lost: Vec<String>,
    pub skipped: Vec<String>,
    pub healed_groups: usize,
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
    fs::create_dir_all(dest)?;
    let mut rep = ExtractReport::default();
    let mut cache = BlockCache::default();
    let wanted = |p: &str| {
        filter.is_empty() || filter.iter().any(|f| p == f || p.starts_with(&format!("{}/", f.trim_end_matches('/'))))
    };
    let entries: Vec<&FileEntry> = a.visible_files(snapshot).into_iter().filter(|f| wanted(&f.path)).collect();
    let total: u64 = entries.iter().map(|f| f.size).sum();
    progress.emit(Event::Stage("Extracting".into()));
    let mut done = 0u64;
    for f in entries {
        let Some(full) = safe_join(dest, &f.path) else {
            rep.skipped.push(format!("{} (unsafe path)", f.path));
            continue;
        };
        if !ancestors_are_plain(dest, &full) {
            rep.skipped.push(format!("{} (would write through a symlink)", f.path));
            continue;
        }
        match f.kind {
            KIND_DIR => fs::create_dir_all(&full)?,
            KIND_SYMLINK => {
                if let Some(parent) = full.parent() {
                    fs::create_dir_all(parent)?;
                }
                #[cfg(unix)]
                {
                    let _ = fs::remove_file(&full);
                    std::os::unix::fs::symlink(f.link.clone().unwrap_or_default(), &full)?;
                }
                #[cfg(not(unix))]
                rep.skipped.push(format!("{} (symlinks are not extracted on this platform)", f.path));
            }
            _ => {
                if let Some(parent) = full.parent() {
                    fs::create_dir_all(parent)?;
                }
                let file = File::create(&full)?;
                let mut bw = std::io::BufWriter::new(file);
                match a.extract_to(f, &mut bw, &mut cache) {
                    Ok(()) => {
                        bw.flush()?;
                        let file = bw.into_inner().map_err(|e| Error::Io(e.into_error()))?;
                        let _ = file.set_modified(UNIX_EPOCH + Duration::from_secs(f.mtime.max(0) as u64));
                        drop(file);
                        #[cfg(unix)]
                        {
                            use std::os::unix::fs::PermissionsExt;
                            let _ = fs::set_permissions(&full, fs::Permissions::from_mode(f.mode & 0o7777));
                        }
                        rep.files += 1;
                        rep.bytes += f.size;
                    }
                    Err(Error::BlockLost(_)) => {
                        drop(bw);
                        let _ = fs::remove_file(&full);
                        rep.lost.push(f.path.clone());
                    }
                    Err(e) => return Err(e),
                }
            }
        }
        done += f.size;
        progress.emit(Event::Progress { done, total });
    }
    rep.healed_groups = a.healed_groups();
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
            progress.emit(Event::Note(format!("skipped unsafe entry {}", e.name())));
            continue;
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
        } else {
            let mode = e.unix_mode().unwrap_or(0o644);
            w.add_file(&rel, mode, mtime, &mut e)?;
        }
    }
    let (summary, first) = w.finish(out)?;
    if verify {
        verify_written(&first, pw.as_deref(), progress)?;
    }
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
            progress.emit(Event::Note(format!("skipped unsafe entry {}", path.display())));
            continue;
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
        }
    }
    let (summary, first) = w.finish(out)?;
    if verify {
        verify_written(&first, pw.as_deref(), progress)?;
    }
    Ok(PackResult { summary, verified: verify })
}

// ---------------------------------------------------------------- dev helpers

/// Copy `src` to `dst` and corrupt `spans` random regions of `span_len` bytes (demos and tests).
pub fn damage_copy(src: &Path, dst: &Path, spans: u32, span_len: usize, seed: u64) -> Result<Vec<(u64, usize)>> {
    fs::copy(src, dst)?;
    let len = fs::metadata(dst)?.len();
    let mut f = OpenOptions::new().read(true).write(true).open(dst)?;
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
    f.sync_all()?;
    Ok(hits)
}

pub fn systime(t: i64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(t.max(0) as u64)
}
