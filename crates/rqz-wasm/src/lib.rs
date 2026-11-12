//! razerq in the browser. Everything runs locally: the archive never leaves the page.
//!
//! Scope: open, list, check, repair (optionally with a second copy), extract single files,
//! and create small archives in memory. Not available here: mount, sidecar discovery,
//! scheduled scrub, extended attributes, multithreading. Archives must fit in browser memory.

use rqz_core::archive::{apply_patches_to_vec, Archive, Assessment, BlockState, Donor, Health};
use rqz_core::codec::Compression;
use rqz_core::index::KIND_FILE;
use rqz_core::progress::Quiet;
use rqz_core::storage::ReadAt;
use rqz_core::volume::{split_archive_bytes, VolumeSet};
use rqz_core::writer::{ArchiveWriter, PackOptions, Protect};
use serde_json::json;
use std::io::Cursor;
use std::sync::Arc;
use wasm_bindgen::prelude::*;

fn err<E: std::fmt::Display>(e: E) -> JsError {
    JsError::new(&e.to_string())
}

fn health_str(h: Health) -> &'static str {
    match h {
        Health::Healthy => "healthy",
        Health::Repairable => "repairable",
        Health::Damaged => "damaged",
    }
}

/// Either one archive image, or a set of volumes (some possibly missing).
enum Source {
    Bytes(Vec<u8>),
    Volumes(VolumeSet),
}

impl ReadAt for Source {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> std::io::Result<()> {
        match self {
            Source::Bytes(b) => b.read_exact_at(buf, offset),
            Source::Volumes(v) => v.read_exact_at(buf, offset),
        }
    }
    fn len(&self) -> std::io::Result<u64> {
        match self {
            Source::Bytes(b) => ReadAt::len(b),
            Source::Volumes(v) => v.len(),
        }
    }
    fn notes(&self) -> Vec<String> {
        match self {
            Source::Bytes(_) => vec![],
            Source::Volumes(v) => v.notes(),
        }
    }
    fn is_incomplete(&self) -> bool {
        match self {
            Source::Bytes(_) => false,
            Source::Volumes(v) => v.is_incomplete(),
        }
    }
}

#[wasm_bindgen]
pub struct Rqz {
    archive: Archive<Source>,
    parts: Vec<Arc<Vec<u8>>>,
    repaired_volumes: Option<Vec<Vec<u8>>>,
    password: Option<String>,
    assessment: Option<Assessment>,
    repaired: Option<Vec<u8>>,
}

#[wasm_bindgen]
impl Rqz {
    /// Open an archive from its bytes. A wrong password is an error; no password on an
    /// encrypted archive still opens it "locked" (health checks work, browsing does not).
    #[wasm_bindgen(constructor)]
    pub fn new(bytes: Vec<u8>, password: Option<String>) -> Result<Rqz, JsError> {
        let archive = Archive::open(Source::Bytes(bytes), password.as_deref()).map_err(err)?;
        Ok(Rqz { archive, parts: vec![], repaired_volumes: None, password, assessment: None, repaired: None })
    }

    /// Open a split archive from its volume files (an Array of Uint8Array, in any order).
    /// Missing volumes are fine: the archive opens "incomplete" and can be repaired.
    pub fn open_volumes(parts: js_sys::Array, password: Option<String>) -> Result<Rqz, JsError> {
        let parts: Vec<Arc<Vec<u8>>> = parts.iter().map(|p| Arc::new(js_sys::Uint8Array::new(&p).to_vec())).collect();
        let set = VolumeSet::from_parts(parts.iter().map(|p| Box::new(p.clone()) as Box<dyn ReadAt>).collect())
            .map_err(err)?;
        let archive = Archive::open(Source::Volumes(set), password.as_deref()).map_err(err)?;
        Ok(Rqz { archive, parts, repaired_volumes: None, password, assessment: None, repaired: None })
    }

    pub fn info(&self) -> String {
        let i = self.archive.info();
        json!({
            "version": format!("{}.{}", i.version.0, i.version.1), "writer": i.writer, "file_len": i.file_len,
            "files": i.files, "dirs": i.dirs, "raw_bytes": i.raw_bytes, "stored_bytes": i.stored_bytes,
            "recovery_bytes": i.recovery_bytes, "blocks": i.blocks, "sets": i.sets, "groups": i.groups,
            "symbol_size": i.symbol_size, "block_size": i.block_size, "encrypted": i.encrypted, "locked": i.locked,
            "detached": i.detached, "tiny_profile": i.tiny_profile, "snapshots": i.snapshots.len(),
            "opened_via": i.opened_via.describe(), "protection_ratio": i.protection_ratio,
            "weak_protection": i.weak_protection,
            "volumes": match self.archive.source() { Source::Volumes(v) => Some(v.count()), _ => None },
            "missing_volumes": match self.archive.source() { Source::Volumes(v) => v.missing().iter().map(|m| m + 1).collect::<Vec<_>>(), _ => vec![] },
        })
        .to_string()
    }

    pub fn files(&self) -> String {
        let v: Vec<_> = self
            .archive
            .visible_files(None)
            .into_iter()
            .filter(|f| f.kind == KIND_FILE)
            .map(|f| json!({"path": f.path, "size": f.size, "mtime": f.mtime}))
            .collect();
        serde_json::to_string(&v).unwrap()
    }

    /// Verify every block. `states` has one char per block: g(ood), a(mber: repairable), r(ed: lost).
    pub fn check(&mut self) -> String {
        let a = self.archive.assess(&Quiet);
        let states: String = a
            .block_states
            .iter()
            .map(|s| match s {
                BlockState::Good => 'g',
                BlockState::Repairable => 'a',
                BlockState::Lost => 'r',
            })
            .collect();
        let mut groups: Vec<_> = a.groups.iter().collect();
        groups.sort_by_key(|g| g.headroom());
        let gj: Vec<_> = groups
            .iter()
            .take(48)
            .map(|g| json!({"set": g.set, "group": g.group, "erased": g.erased, "repair_ok": g.repair_ok, "repair_total": g.repair_total}))
            .collect();
        let out = json!({
            "health": health_str(a.health), "blocks_total": a.blocks_total, "blocks_damaged": a.blocks_damaged,
            "headroom_ratio": a.min_headroom_ratio, "headroom_symbols": a.min_headroom_symbols,
            "structural": a.structural, "states": states, "groups": gj,
        });
        self.assessment = Some(a);
        out.to_string()
    }

    /// Plan and apply a repair in memory. Returns a JSON report; fetch the bytes with `repaired_bytes`.
    pub fn repair(&mut self, donor: Option<Vec<u8>>) -> Result<String, JsError> {
        if self.assessment.is_none() {
            self.check();
        }
        let asm = self.assessment.as_ref().unwrap();
        let donor_archive = match donor {
            Some(d) => Some(Archive::open(d, self.password.as_deref()).map_err(err)?),
            None => None,
        };
        let plan = self.archive.plan_repair(asm, donor_archive.as_ref().map(|d| d as &dyn Donor), &Quiet);
        let (mut bytes, mut vols_out) = (Vec::new(), None);
        match self.archive.source() {
            Source::Bytes(b) => {
                bytes = b.clone();
                apply_patches_to_vec(&mut bytes, &plan.patches);
            }
            Source::Volumes(set) => {
                let rewrites = set.plan_volume_patches(&plan.patches);
                let count = rewrites.iter().map(|r| r.index + 1).max().unwrap_or(0).max(set.count());
                let vh = set.vh_len as usize;
                let mut vols: Vec<Vec<u8>> = (0..count)
                    .map(|i| match set.supplied.get(i as usize).copied().flatten() {
                        Some(k) => (*self.parts[k]).clone(),
                        None => Vec::new(),
                    })
                    .collect();
                for rw in rewrites {
                    let v = &mut vols[rw.index as usize];
                    if rw.create {
                        *v = vec![0u8; vh + rw.payload_len as usize];
                    }
                    if let Some(h) = &rw.header {
                        v[..h.len()].copy_from_slice(h);
                    }
                    apply_patches_to_vec(v, &rw.patches);
                    if v.len() < vh + rw.payload_len as usize {
                        v.resize(vh + rw.payload_len as usize, 0);
                    }
                }
                vols_out = Some(vols);
            }
        }
        self.repaired_volumes = vols_out;
        self.repaired = Some(bytes);
        Ok(json!({
            "blocks_fixed": plan.blocks_fixed, "recovery_regenerated": plan.recovery_regenerated,
            "structural_fixed": plan.structural_fixed, "lost_blocks": plan.lost_blocks.len(), "lost_files": plan.lost_files,
        })
        .to_string())
    }

    pub fn repaired_bytes(&self) -> Option<Vec<u8>> {
        self.repaired.clone()
    }

    /// For split archives: the repaired volumes, in order (an Array of Uint8Array).
    pub fn repaired_volumes(&self) -> js_sys::Array {
        let out = js_sys::Array::new();
        for v in self.repaired_volumes.iter().flatten() {
            out.push(&js_sys::Uint8Array::from(&v[..]));
        }
        out
    }

    /// Extract one file. Damage within the recovery budget is repaired in memory.
    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, JsError> {
        let f = self
            .archive
            .visible_files(None)
            .into_iter()
            .find(|f| f.path == path)
            .ok_or_else(|| err("no such file in this archive"))?;
        self.archive.read_file(f).map_err(err)
    }
}

fn options(protect_percent: f64, compression: &str, password: Option<String>, total: u64) -> PackOptions {
    let mut o = PackOptions::default();
    o.compression = Compression::parse(compression).unwrap_or(Compression::Normal);
    o.protect =
        if protect_percent <= 0.0 { Protect::NONE } else { Protect { ratio: protect_percent / 100.0, min_repair: 4 } };
    o.password = password.filter(|p| !p.is_empty());
    o.total_hint = Some(total);
    o.now_unix = (js_sys::Date::now() / 1000.0) as i64;
    o
}

/// Create an archive in memory from named byte blobs (`blobs` is an Array of Uint8Array).
#[wasm_bindgen]
pub fn pack(
    names: Vec<String>,
    blobs: js_sys::Array,
    protect_percent: f64,
    compression: &str,
    password: Option<String>,
) -> Result<Vec<u8>, JsError> {
    let data: Vec<Vec<u8>> = blobs.iter().map(|b| js_sys::Uint8Array::new(&b).to_vec()).collect();
    if data.len() != names.len() {
        return Err(err("names and blobs differ in length"));
    }
    let total: u64 = data.iter().map(|d| d.len() as u64).sum();
    let o = options(protect_percent, compression, password, total);
    let mtime = o.now_unix;
    let mut w = ArchiveWriter::create(Cursor::new(Vec::new()), o, &Quiet).map_err(err)?;
    for (n, d) in names.iter().zip(&data) {
        w.add_bytes(n, 0o644, mtime, d).map_err(err)?;
    }
    Ok(w.finish().map_err(err)?.0.into_inner())
}

/// A ready-made archive for the "watch it heal" demo: small blocks so the map has plenty of squares.
#[wasm_bindgen]
pub fn demo_archive() -> Result<Vec<u8>, JsError> {
    let mut o = PackOptions::default();
    o.block_size = 16 * 1024;
    o.symbol_size = Some(512);
    o.target_k = 192;
    o.protect = Protect { ratio: 0.12, min_repair: 4 };
    o.deterministic = true;
    let mut w = ArchiveWriter::create(Cursor::new(Vec::new()), o, &Quiet).map_err(err)?;
    let words =
        ["ledger", "archive", "recovery", "symbol", "parity", "stripe", "block", "erasure", "fountain", "healing"];
    let mut s = 0x9E3779B97F4A7C15u64;
    for i in 0..14 {
        let mut text = String::new();
        let n = 6_000 + i * 4_500;
        for _ in 0..n {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            text.push_str(words[(s % words.len() as u64) as usize]);
            text.push(' ');
        }
        w.add_bytes(&format!("notes/entry-{i:02}.txt"), 0o644, 0, text.as_bytes()).map_err(err)?;
    }
    Ok(w.finish().map_err(err)?.0.into_inner())
}

/// A split demo: six volumes with enough recovery data to lose any one of them.
#[wasm_bindgen]
pub fn demo_volumes() -> Result<js_sys::Array, JsError> {
    let mut o = PackOptions::default();
    o.block_size = 16 * 1024;
    o.symbol_size = Some(512);
    o.target_k = 96;
    o.protect = Protect { ratio: 0.45, min_repair: 4 };
    o.deterministic = true;
    let mut w = ArchiveWriter::create(Cursor::new(Vec::new()), o, &Quiet).map_err(err)?;
    let words =
        ["ledger", "archive", "recovery", "symbol", "parity", "stripe", "block", "erasure", "fountain", "healing"];
    let mut s = 0x9E3779B97F4A7C15u64;
    for i in 0..14 {
        let mut text = String::new();
        for _ in 0..(6_000 + i * 4_500) {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            text.push_str(words[(s % words.len() as u64) as usize]);
            text.push(' ');
        }
        w.add_bytes(&format!("notes/entry-{i:02}.txt"), 0o644, 0, text.as_bytes()).map_err(err)?;
    }
    let image = w.finish().map_err(err)?.0.into_inner();
    let vols = split_archive_bytes(&image, (image.len() as u64 / 6).max(8 * 1024)).map_err(err)?;
    let out = js_sys::Array::new();
    for v in vols {
        out.push(&js_sys::Uint8Array::from(&v[..]));
    }
    Ok(out)
}

#[wasm_bindgen]
pub fn version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}
