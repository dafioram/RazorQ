//! Reading, checking and repairing archives.
//!
//! The open path degrades gracefully: footer -> mirror footer -> newest valid
//! index checkpoint (backward scan) -> full forward scan of self-describing
//! segments. Damage is always handled as erasures: checksums say *where* it is,
//! RaptorQ fills the gaps.

use crate::codec;
use crate::crypto::Crypto;
use crate::error::{Error, Result};
use crate::format::*;
use crate::index::*;
use crate::progress::{Event, Progress};
use crate::storage::{pmap, read_lossy, read_vec, ReadAt};
use rqz_ecc as ecc;
use std::collections::{HashMap, HashSet};
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenPath {
    Footer,
    MirrorFooter,
    ScanBackward,
    CatalogRecovery,
    FullScan,
}

impl OpenPath {
    pub fn describe(&self) -> &'static str {
        match self {
            OpenPath::Footer => "footer",
            OpenPath::MirrorFooter => "mirror footer (primary footer damaged)",
            OpenPath::ScanBackward => "index checkpoint found by backward scan (footers damaged)",
            OpenPath::CatalogRecovery => "index recovered from catalog symbols",
            OpenPath::FullScan => "index rebuilt by full scan (all index copies damaged)",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Health {
    Healthy,
    Repairable,
    Damaged,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BlockState {
    Good,
    Repairable,
    Lost,
}

#[derive(Clone, Debug)]
pub struct BlockHealth {
    pub idx: usize,
    pub header_ok: bool,
    pub hash_ok: bool,
    pub table_ok: bool,
    pub content_ok: bool,
    /// Symbol indices (within the block) that failed their checksum.
    pub bad_symbols: Vec<u32>,
}

impl BlockHealth {
    fn needs_work(&self) -> bool {
        !self.hash_ok || !self.header_ok || !self.table_ok || !self.content_ok
    }
}

#[derive(Clone, Debug)]
pub struct GroupHealth {
    pub set: u32,
    pub group: u32,
    pub k: u32,
    pub erased: u32,
    pub repair_total: u32,
    pub repair_ok: u32,
    pub bad_repairs: Vec<(u32, u64)>,
    pub blocks: Vec<BlockHealth>,
    decode_verified: bool,
}

impl GroupHealth {
    pub fn headroom(&self) -> i64 {
        self.repair_ok as i64 - self.erased as i64
    }
    pub fn state(&self) -> Health {
        let blocks_ok = self.blocks.iter().all(|b| !b.needs_work());
        if self.erased == 0 && self.bad_repairs.is_empty() && blocks_ok {
            Health::Healthy
        } else if self.decode_verified && self.blocks.iter().all(|b| b.content_ok) {
            Health::Repairable
        } else {
            Health::Damaged
        }
    }
}

#[derive(Clone, Debug)]
pub struct Assessment {
    pub groups: Vec<GroupHealth>,
    /// Blocks outside any protected set that have problems.
    pub loose: Vec<BlockHealth>,
    pub block_states: Vec<BlockState>,
    pub structural: Vec<String>,
    pub blocks_total: usize,
    pub inventory_complete: bool,
    pub stored_bytes_only: bool,
    pub blocks_damaged: usize,
    pub health: Health,
    /// Worst-case headroom: spare repair symbols in the tightest group, as a share of its size.
    pub min_headroom_ratio: Option<f64>,
    pub min_headroom_symbols: Option<i64>,
}

impl Assessment {
    pub fn is_healthy(&self) -> bool {
        self.health == Health::Healthy
    }
}

#[derive(Clone, Debug)]
pub struct Patch {
    pub offset: u64,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default)]
pub struct RepairPlan {
    /// Writes to the archive file (offsets at or past the end extend it).
    pub patches: Vec<Patch>,
    /// Writes to the protected file when repairing a detached sidecar.
    pub target_patches: Vec<Patch>,
    pub target_len: Option<u64>,
    pub blocks_fixed: u32,
    pub recovery_regenerated: u32,
    pub structural_fixed: u32,
    pub lost_blocks: Vec<usize>,
    pub lost_files: Vec<String>,
    pub notes: Vec<String>,
}

impl RepairPlan {
    pub fn is_empty(&self) -> bool {
        self.patches.is_empty() && self.target_patches.is_empty() && self.target_len.is_none()
    }
}

/// A second copy of the same archive that can donate intact blocks.
pub trait Donor: Sync {
    fn stored_block(&self, seq: u64, hash: &[u8; 16]) -> Option<Vec<u8>>;
}

#[derive(Clone, Copy, Debug)]
struct RecRef {
    esi: u32,
    offset: u64,
}

#[derive(Default)]
struct Structure {
    header_ok: [bool; 2],
    footer_ok: [bool; 2],
    index_ok: [bool; 2],
    catalog_ok: bool,
}

#[derive(Debug, Clone)]
pub struct Info {
    pub version: (u16, u16),
    pub writer: String,
    pub uuid: [u8; 16],
    pub file_len: u64,
    pub files: usize,
    pub dirs: usize,
    pub raw_bytes: u64,
    pub stored_bytes: u64,
    pub recovery_bytes: u64,
    pub blocks: usize,
    pub sets: usize,
    pub groups: u32,
    pub symbol_size: u16,
    pub block_size: usize,
    pub encrypted: bool,
    pub locked: bool,
    pub detached: bool,
    pub tiny_profile: bool,
    pub snapshots: Vec<Snapshot>,
    pub opened_via: OpenPath,
    /// Share of the stored data covered by recovery symbols.
    pub protection_ratio: f64,
    pub weak_protection: Option<String>,
}

pub struct Archive<S: ReadAt> {
    src: S,
    target: Option<Box<dyn ReadAt>>,
    pub header: Header,
    pub index: IndexData,
    crypto: Option<Crypto>,
    pub locked: bool,
    pub opened_via: OpenPath,
    pub notes: Vec<String>,
    total_len: u64,
    inventory_complete: bool,
    sealed_index: Option<u64>,
    recovered_catalog: Option<Vec<u8>>,
    structure: Structure,
    crc_offsets: Vec<u64>,
    recs: HashMap<(u32, u32), Vec<RecRef>>,
    healed_count: AtomicU64,
    heal: Mutex<HashMap<(u32, u32), Option<Arc<Vec<u8>>>>>,
    cache: Mutex<std::collections::VecDeque<(usize, Arc<Vec<u8>>)>>,
}

fn pad(mut v: Vec<u8>, ss: usize) -> Vec<u8> {
    let p = padded_len(v.len(), ss);
    v.resize(p, 0);
    v
}

fn find_sync(buf: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while i + 8 <= buf.len() {
        let p = buf[i..buf.len() - 7].iter().position(|&b| b == SYNC[0])?;
        i += p;
        if buf[i..i + 8] == SYNC {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn read_headers<S: ReadAt>(src: &S, total: u64, st: &mut Structure, notes: &mut Vec<String>) -> Result<Header> {
    let mut found: Option<Header> = None;
    // Header A at 0 tells us the header length; mirror B sits right after it.
    if let Ok(first) = read_vec(src, 0, 12.min(total as usize)) {
        if first.len() == 12 && first[0..8] == MAGIC {
            let hl = u32::from_le_bytes(first[8..12].try_into().unwrap()) as u64;
            if (128..=65536).contains(&hl) && hl <= total {
                if let Ok(b) = read_vec(src, 0, hl as usize) {
                    if let Ok(h) = Header::decode(&b) {
                        st.header_ok[0] = true;
                        found = Some(h);
                    }
                }
            }
        }
    }
    let candidates: Vec<u64> = match &found {
        Some(h) => vec![h.header_len as u64],
        None => vec![HEADER_LEN_TINY as u64, HEADER_LEN_NORMAL as u64],
    };
    for hl in candidates {
        if hl * 2 > total {
            continue;
        }
        if let Ok(b) = read_vec(src, hl, hl as usize) {
            if let Ok(h) = Header::decode(&b) {
                if h.header_len as u64 == hl {
                    st.header_ok[1] = true;
                    if found.as_ref().is_none_or(|old| h.generation > old.generation) {
                        notes.push("primary header damaged; used mirror".into());
                        found = Some(h);
                    }
                    break;
                }
            }
        }
    }
    if let Some(header) = &found {
        if st.header_ok == [true, true] {
            for (i, valid) in st.header_ok.iter_mut().enumerate() {
                *valid = read_vec(src, i as u64 * u64::from(header.header_len), header.header_len as usize)
                    .ok()
                    .and_then(|b| Header::decode(&b).ok())
                    .as_ref()
                    == Some(header);
            }
        }
    }
    if found.is_some() && !st.header_ok[1] {
        notes.push("mirror header damaged".into());
    }
    found.ok_or(Error::NotArchive)
}

impl<S: ReadAt> Archive<S> {
    pub fn open(src: S, password: Option<&str>) -> Result<Self> {
        let total = src.len()?;
        let mut notes = src.notes();
        let mut structure = Structure::default();
        let header = read_headers(&src, total, &mut structure, &mut notes)?;
        header.check_supported()?;

        let crypto = if header.encrypted() {
            match password {
                Some(pw) => {
                    let kdf = header.kdf.as_ref().ok_or_else(|| Error::Corrupt("missing KDF parameters".into()))?;
                    let c = Crypto::derive(pw, kdf, header.uuid)?;
                    if Some(c.key_check()) != header.key_check {
                        return Err(Error::WrongPassword);
                    }
                    Some(c)
                }
                None => None,
            }
        } else {
            None
        };
        let locked = header.encrypted() && crypto.is_none();

        let mut a = Archive {
            src,
            target: None,
            header,
            index: IndexData::default(),
            crypto,
            locked,
            opened_via: OpenPath::Footer,
            notes,
            total_len: total,
            inventory_complete: true,
            sealed_index: None,
            recovered_catalog: None,
            structure,
            crc_offsets: Vec::new(),
            recs: HashMap::new(),
            healed_count: AtomicU64::new(0),
            heal: Mutex::new(HashMap::new()),
            cache: Mutex::new(std::collections::VecDeque::new()),
        };
        a.locate_index()?;
        a.build_recs();
        if let Some(d) = &a.index.detached {
            let mut off = d.crc_offset;
            for b in &a.index.blocks {
                a.crc_offsets.push(off);
                off += (SEG_HEADER_LEN + table_len(b.stored_len as usize, a.header.symbol_size as usize)) as u64;
            }
        }
        Ok(a)
    }

    pub fn has_valid_index(&self) -> bool {
        self.inventory_complete
    }

    pub fn has_complete_inventory(&self) -> bool {
        self.inventory_complete && !self.locked
    }

    pub fn symbol_size(&self) -> usize {
        self.header.symbol_size as usize
    }
    pub fn crypto(&self) -> Option<&Crypto> {
        self.crypto.as_ref()
    }
    pub fn file_len(&self) -> u64 {
        self.total_len
    }
    pub fn source(&self) -> &S {
        &self.src
    }

    /// For detached (sidecar) archives: attach the file being protected.
    pub fn attach_target(&mut self, target: Box<dyn ReadAt>) {
        self.target = Some(target);
    }

    // ------------------------------------------------------------ open path

    fn matches_inventory(&self, index: &IndexData) -> bool {
        let Some((blocks, files)) = self.header.inventory else { return false };
        let (actual_blocks, actual_files) = index.inventory_hashes(self.crypto.as_ref());
        blocks == actual_blocks && (self.locked || files == actual_files)
    }

    fn load_index_at(&self, off: u64) -> Result<(IndexData, SegHeader)> {
        let hb = read_vec(&self.src, off, SEG_HEADER_LEN)?;
        let sh = SegHeader::decode(&hb).ok_or_else(|| Error::Corrupt("index segment header".into()))?;
        if !matches!(sh.kind, kind::INDEX | kind::INDEX_MIRROR) {
            return Err(Error::Corrupt("not an index segment".into()));
        }
        if sh.stored_len as usize > MAX_INDEX
            || off.checked_add(SEG_HEADER_LEN as u64 + u64::from(sh.stored_len)).is_none_or(|end| end > self.total_len)
        {
            return Err(Error::Corrupt("index segment overruns file".into()));
        }
        let payload = read_vec(&self.src, off + SEG_HEADER_LEN as u64, sh.stored_len as usize)?;
        if hash128(&payload) != sh.hash {
            return Err(Error::Corrupt("index payload hash mismatch".into()));
        }
        let index = IndexData::from_bytes(&payload, self.header.encrypted(), self.crypto.as_ref())?.0;
        index.validate(&self.header, self.total_len, false)?;
        Ok((index, sh))
    }

    fn locate_index(&mut self) -> Result<()> {
        let total = self.total_len;
        let committed = self.header.feat_required & REQ_CHECKPOINTS != 0;
        let mut found = None;
        let mut catalog_location = None;
        for (i, back) in [(0usize, 128u64), (1, 64)] {
            if total < back {
                continue;
            }
            let Ok(fb) = read_vec(&self.src, total - back, FOOTER_LEN) else { continue };
            let Some(f) = Footer::decode(&fb) else { continue };
            if f.uuid != self.header.uuid || f.index_len < SEG_HEADER_LEN as u32 {
                continue;
            }
            let mirror = if committed {
                f.index_offset.checked_sub(u64::from(f.index_len) + u64::from(f.index_gap))
            } else {
                None
            };
            let candidates = [(Some(f.index_offset), kind::INDEX), (mirror, kind::INDEX_MIRROR)];
            for (slot, (off, expected_kind)) in candidates.into_iter().enumerate() {
                let Some(off) = off else { continue };
                let Ok((idx, sh)) = self.load_index_at(off) else { continue };
                if sh.kind != expected_kind
                    || sh.hash != f.index_hash
                    || u64::from(sh.stored_len) + SEG_HEADER_LEN as u64 != u64::from(f.index_len)
                    || (committed
                        && (sh.owner != 1 || sh.seq != self.header.generation || !self.matches_inventory(&idx)))
                {
                    continue;
                }
                self.structure.index_ok[slot] = true;
                self.structure.footer_ok[i] = true;
                if found.is_none() {
                    catalog_location = mirror.map(|mirror| (mirror, sh.stored_len as usize, f.index_hash));
                    found = Some((idx, off, if i == 0 { OpenPath::Footer } else { OpenPath::MirrorFooter }));
                }
            }
        }
        if let Some((idx, off, via)) = found {
            self.sealed_index = Some(off);
            self.index = idx;
            self.opened_via = via;
            self.structure.catalog_ok = catalog_location.is_some_and(|(off, len, digest)| {
                crate::catalog::verify(&self.src, off, len, self.header.generation, digest)
            });
            if committed && !self.structure.catalog_ok {
                self.notes.push("protected index catalog is damaged".into());
            }
            if committed && self.structure.index_ok != [true, true] {
                self.notes.push("one final index copy is damaged; used its mirror".into());
            }
            if !self.structure.footer_ok[0] {
                self.notes.push("primary footer damaged".into());
            }
            if !self.structure.footer_ok[1] {
                self.notes.push("mirror footer damaged".into());
            }
            return Ok(());
        }
        if let Some((idx, off)) = self.scan_backward() {
            self.sealed_index = Some(off);
            self.index = idx;
            self.opened_via = OpenPath::ScanBackward;
            self.notes.push("footers damaged; used the committed index".into());
            return Ok(());
        }
        self.scan_rebuild()?;
        if self.recovered_catalog.is_some() {
            self.opened_via = OpenPath::CatalogRecovery;
            self.notes.push("final index recovered from its protected catalog".into());
            return Ok(());
        }
        self.opened_via = OpenPath::FullScan;
        self.notes.push("all usable index copies damaged; scanned surviving segments".into());
        self.inventory_complete = committed && !self.locked && self.matches_inventory(&self.index);
        if !self.inventory_complete {
            self.notes.push("complete file inventory or block layout could not be established; salvage only".into());
        }
        Ok(())
    }

    fn scan_backward(&self) -> Option<(IndexData, u64)> {
        const WIN: u64 = 4 << 20;
        let mut end = self.total_len;
        if self.header.feat_required & REQ_CHECKPOINTS == 0 {
            return None;
        }
        loop {
            let start = end.saturating_sub(WIN);
            let buf = read_lossy(&self.src, start, (end - start) as usize);
            let mut cands = Vec::new();
            let mut i = 0;
            while let Some(p) = find_sync(&buf, i) {
                if let Some(h) = SegHeader::decode(&buf[p..]) {
                    if matches!(h.kind, kind::INDEX | kind::INDEX_MIRROR)
                        && h.owner == 1
                        && h.seq == self.header.generation
                    {
                        cands.push(start + p as u64);
                    }
                }
                i = p + 1;
            }
            for &c in cands.iter().rev() {
                if let Ok((idx, _)) = self.load_index_at(c) {
                    if self.matches_inventory(&idx) {
                        return Some((idx, c));
                    }
                }
            }
            if start == 0 {
                return None;
            }
            end = start + SEG_HEADER_LEN as u64 - 1;
        }
    }

    fn scan_rebuild(&mut self) -> Result<()> {
        let total = self.total_len;
        let ss = self.symbol_size();
        let mut pos = 2 * self.header.header_len as u64;
        let mut datas: Vec<(u64, SegHeader)> = Vec::new();
        let mut recs: Vec<(u64, SegHeader)> = Vec::new();
        let mut metas: Vec<(u64, SegHeader)> = Vec::new();
        let mut indexes: Vec<u64> = Vec::new();
        let mut catalog = crate::catalog::Catalog::default();
        while pos + SEG_HEADER_LEN as u64 <= total {
            let hb = read_lossy(&self.src, pos, SEG_HEADER_LEN);
            match SegHeader::decode(&hb) {
                Some(h) => {
                    if h.kind == kind::DATA && h.stored_len as usize > self.header.block_size() + 40 {
                        pos += 1;
                        continue;
                    }
                    let len = h.total_len(ss);
                    let truncated = pos + len > total;
                    match h.kind {
                        kind::DATA
                            if h.raw_len != 0
                                && h.raw_len as usize <= self.header.block_size()
                                && h.stored_len != 0
                                && h.stored_len as usize <= self.header.block_size() + 40 =>
                        {
                            datas.push((pos, h))
                        }
                        kind::RECOVERY if !truncated => recs.push((pos, h)),
                        kind::META if !truncated && h.stored_len as usize <= MAX_INDEX => metas.push((pos, h)),
                        kind::INDEX | kind::INDEX_MIRROR if !truncated => indexes.push(pos),
                        kind::CATALOG
                            if !truncated
                                && h.seq == self.header.generation
                                && h.stored_len as usize == crate::catalog::PAYLOAD_LEN =>
                        {
                            if let Ok(payload) =
                                read_vec(&self.src, pos + SEG_HEADER_LEN as u64, crate::catalog::PAYLOAD_LEN)
                            {
                                catalog.push(&h, &payload);
                            }
                        }
                        _ => {}
                    }
                    pos = if truncated { total } else { pos + len };
                }
                None => {
                    let want = ((total - pos - 1) as usize).min(1 << 20);
                    let w = read_lossy(&self.src, pos + 1, want);
                    match find_sync(&w, 0) {
                        Some(p) => pos += 1 + p as u64,
                        None if w.len() < 8 => break,
                        None => pos += w.len() as u64 - 7,
                    }
                }
            }
        }
        if let Some(payload) = catalog.decode() {
            if let Ok((index, _)) = IndexData::from_bytes(&payload, self.header.encrypted(), self.crypto.as_ref()) {
                if self.matches_inventory(&index) && index.validate(&self.header, total, false).is_ok() {
                    self.index = index;
                    self.recovered_catalog = Some(payload);
                    return Ok(());
                }
            }
        }
        if self.header.detached() {
            return Err(Error::Corrupt("every usable index copy of this sidecar is damaged".into()));
        }
        datas.sort_by_key(|(_, h)| h.seq);
        datas.dedup_by_key(|(_, h)| h.seq);

        let mut idx = IndexData::default();
        let mut raw_offset = 0u64;
        let mut stripe_of: HashMap<u32, u32> = HashMap::new();
        for (_, h) in &recs {
            let e = stripe_of.entry(h.set_id as u32).or_insert(0);
            *e = (*e).max(h.stripe as u32);
        }
        let mut last_seq: Option<u64> = None;
        for (i, (off, h)) in datas.iter().enumerate() {
            if h.raw_offset().is_none() && h.seq != last_seq.map_or(0u64, |seq| seq.saturating_add(1)) {
                break; // Legacy headers have no absolute offset after a missing block.
            }
            last_seq = Some(h.seq);
            let set_id = h.set_id as u32;
            match idx.sets.last_mut() {
                Some(s) if s.id == set_id => s.block_count += 1,
                _ => idx.sets.push(SetInfo {
                    id: set_id,
                    first_block: i as u32,
                    block_count: 1,
                    stripe: stripe_of.get(&set_id).copied().unwrap_or(0),
                }),
            }
            idx.blocks.push(BlockEntry {
                seq: h.seq,
                offset: *off,
                stored_len: h.stored_len,
                raw_len: h.raw_len,
                raw_offset: h.raw_offset().unwrap_or(raw_offset),
                codec: h.codec,
                flags: h.flags,
                set_id,
                hash: h.hash,
            });
            raw_offset = h
                .raw_offset()
                .unwrap_or(raw_offset)
                .checked_add(u64::from(h.raw_len))
                .ok_or_else(|| Error::Corrupt("logical stream size overflow".into()))?;
        }
        for (off, h) in &recs {
            self.recs.entry((h.set_id as u32, h.owner)).or_default().push(RecRef { esi: h.seq as u32, offset: *off });
        }
        if !self.locked {
            let mut by_id: HashMap<u32, FileEntry> = HashMap::new();
            for (off, h) in &metas {
                let payload = read_lossy(&self.src, off + SEG_HEADER_LEN as u64, h.stored_len as usize);
                if hash128(&payload) != h.hash {
                    continue;
                }
                let c = if self.header.encrypted() { self.crypto.as_ref() } else { None };
                if let Ok(list) = files_from_bytes(&payload, c) {
                    for f in list {
                        by_id.insert(f.id, f);
                    }
                }
            }
            let mut files: Vec<FileEntry> = by_id.into_values().collect();
            files.sort_by_key(|f| f.id);
            idx.files = files;
        }
        idx.snapshots = vec![Snapshot { id: 1, created: self.header.created_unix as i64, name: "recovered".into() }];
        for &off in indexes.iter().rev() {
            if let Ok((i, _)) = self.load_index_at(off) {
                if !i.snapshots.is_empty() {
                    idx.snapshots = i.snapshots;
                    break;
                }
            }
        }
        // Files in snapshots newer than any known snapshot would be hidden; widen if needed.
        let max_snap = idx.files.iter().map(|f| f.snapshot).max().unwrap_or(1);
        if max_snap > 1_000_000 {
            return Err(Error::Corrupt("snapshot number exceeds format limit".into()));
        }
        while idx.snapshots.last().map(|s| s.id).unwrap_or(0) < max_snap {
            let id = idx.snapshots.last().map(|s| s.id).unwrap_or(0) + 1;
            idx.snapshots.push(Snapshot { id, created: 0, name: "recovered".into() });
        }
        // A gap makes the original stripe positions uncertain. Verify surviving data independently.
        if idx.blocks.iter().enumerate().any(|(i, b)| b.seq != i as u64) {
            for set in &mut idx.sets {
                set.stripe = 0;
            }
            self.recs.clear();
        }
        idx.validate(&self.header, self.total_len, true)?;
        self.index = idx;
        Ok(())
    }

    fn build_recs(&mut self) {
        let ss = self.symbol_size() as u64;
        for r in &self.index.regions {
            let groups = r.esi_start.len() as u64;
            for j in 0..r.per_group as u64 {
                for (gi, base) in r.esi_start.iter().enumerate() {
                    let off = r.offset + (j * groups + gi as u64) * (SEG_HEADER_LEN as u64 + ss);
                    self.recs
                        .entry((r.set_id, r.group_base + gi as u32))
                        .or_default()
                        .push(RecRef { esi: base + j as u32, offset: off });
                }
            }
        }
    }

    /// The index with recovery regions filled in even if it had to be rebuilt by scanning.
    pub fn full_index(&self) -> IndexData {
        let mut i = self.index.clone();
        if i.regions.is_empty() && !self.recs.is_empty() {
            i.regions = self.regions_from_recs();
        }
        i
    }

    /// Regions describing every known recovery symbol (used when the index must be rewritten).
    fn regions_from_recs(&self) -> Vec<Region> {
        let mut keys: Vec<_> = self.recs.keys().copied().collect();
        keys.sort();
        let mut out = Vec::new();
        for k in keys {
            for r in &self.recs[&k] {
                out.push(Region {
                    set_id: k.0,
                    group_base: k.1,
                    offset: r.offset,
                    per_group: 1,
                    esi_start: vec![r.esi],
                });
            }
        }
        out
    }

    // ------------------------------------------------------------ layout helpers

    fn set_of(&self, block_idx: usize) -> Option<&SetInfo> {
        let sets = &self.index.sets;
        let p = sets.partition_point(|s| (s.first_block as usize) <= block_idx);
        let s = sets.get(p.checked_sub(1)?)?;
        ((block_idx as u32) < s.first_block + s.block_count).then_some(s)
    }

    fn group_members(set: &SetInfo, g: u32) -> Vec<usize> {
        (g..set.block_count).step_by(set.stripe.max(1) as usize).map(|i| (set.first_block + i) as usize).collect()
    }

    fn nsyms(&self, b: &BlockEntry) -> usize {
        n_symbols(b.stored_len as usize, self.symbol_size())
    }

    fn block_src(&self) -> Option<&dyn ReadAt> {
        if self.header.detached() {
            self.target.as_deref()
        } else {
            Some(&self.src)
        }
    }

    fn stored_offset(&self, b: &BlockEntry) -> u64 {
        if self.header.detached() {
            b.offset
        } else if b.flags & flag::SYMCRC != 0 {
            b.offset + (SEG_HEADER_LEN + table_len(b.stored_len as usize, self.symbol_size())) as u64
        } else {
            b.offset + SEG_HEADER_LEN as u64
        }
    }

    fn read_stored(&self, b: &BlockEntry) -> Vec<u8> {
        match self.block_src() {
            Some(s) => read_lossy(s, self.stored_offset(b), b.stored_len as usize),
            None => vec![0u8; b.stored_len as usize],
        }
    }

    // ------------------------------------------------------------ checking

    pub fn check_block(&self, idx: usize) -> BlockHealth {
        let b = &self.index.blocks[idx];
        let ss = self.symbol_size();
        let n = self.nsyms(b);
        let detached = self.header.detached();
        let mut h =
            BlockHealth { idx, header_ok: true, hash_ok: false, table_ok: true, content_ok: true, bad_symbols: vec![] };
        if !detached {
            let hb = read_lossy(&self.src, b.offset, SEG_HEADER_LEN);
            h.header_ok = SegHeader::decode(&hb)
                .map(|s| {
                    s.kind == kind::DATA
                        && s.seq == b.seq
                        && s.stored_len == b.stored_len
                        && s.hash == b.hash
                        && s.codec == b.codec
                        && s.flags == b.flags
                        && s.raw_len == b.raw_len
                        && u32::from(s.set_id) == b.set_id
                        && s.raw_offset().is_none_or(|off| off == b.raw_offset)
                })
                .unwrap_or(false);
        }
        let mut stored = vec![0; b.stored_len as usize];
        let readable = self.block_src().is_some_and(|src| {
            let offset = self.stored_offset(b);
            if src.read_exact_at(&mut stored, offset).is_ok() {
                true
            } else {
                stored = read_lossy(src, offset, b.stored_len as usize);
                false
            }
        });
        h.hash_ok = readable && hash128(&stored) == b.hash;
        let mut table: Option<Vec<u8>> = None;
        let tl = 4 * n + 4;
        let valid = |t: &[u8]| crc(&t[..4 * n]) == u32::from_le_bytes(t[4 * n..].try_into().unwrap());
        if !detached && b.flags & flag::SYMCRC != 0 {
            let base = b.offset + SEG_HEADER_LEN as u64;
            let ta = read_lossy(&self.src, base, tl);
            let tb = read_lossy(&self.src, base + (tl + n * ss) as u64, tl);
            let (va, vb) = (valid(&ta), valid(&tb));
            h.table_ok = va && vb;
            table = if va {
                Some(ta)
            } else if vb {
                Some(tb)
            } else {
                None
            };
        } else if detached && !self.crc_offsets.is_empty() {
            let off = self.crc_offsets[idx];
            let raw = read_lossy(&self.src, off, SEG_HEADER_LEN + tl);
            if let Some(sh) = SegHeader::decode(&raw) {
                if sh.kind == kind::CRCTAB
                    && sh.stored_len as usize == tl
                    && sh.hash == hash128(&raw[SEG_HEADER_LEN..])
                    && valid(&raw[SEG_HEADER_LEN..])
                {
                    table = Some(raw[SEG_HEADER_LEN..].to_vec());
                }
            }
        }
        if h.hash_ok {
            h.content_ok = self.locked || detached || self.decode_block(b, &stored).is_ok();
            return h;
        }
        let mut bad = Vec::new();
        if let Some(t) = &table {
            let stored_len = stored.len();
            let padded = pad(stored, ss);
            for (i, chunk) in padded.chunks(ss).enumerate() {
                let want = u32::from_le_bytes(t[i * 4..i * 4 + 4].try_into().unwrap());
                let available = if readable {
                    true
                } else {
                    let off = i * ss;
                    let len = ss.min(stored_len.saturating_sub(off));
                    self.block_src().is_some_and(|src| {
                        let mut probe = vec![0; len];
                        src.read_exact_at(&mut probe, self.stored_offset(b) + off as u64).is_ok()
                    })
                };
                if !available || crc(chunk) != want {
                    bad.push(i as u32);
                }
            }
        }
        if bad.is_empty() {
            // No usable localisation: treat the whole block as erased.
            bad = (0..n as u32).collect();
        }
        h.bad_symbols = bad;
        h
    }

    fn read_valid_repairs(&self, set: u32, group: u32, keep_data: bool) -> (Vec<(u32, Vec<u8>)>, Vec<(u32, u64)>) {
        let ss = self.symbol_size();
        let (mut good, mut bad) = (Vec::new(), Vec::new());
        for r in self.recs.get(&(set, group)).map(|v| v.as_slice()).unwrap_or(&[]) {
            let raw = read_lossy(&self.src, r.offset, SEG_HEADER_LEN + ss);
            let ok = SegHeader::decode(&raw)
                .map(|h| {
                    h.kind == kind::RECOVERY
                        && h.owner == group
                        && h.set_id as u32 == set & 0xFFFF
                        && h.seq == r.esi as u64
                        && h.hash == hash128(&raw[SEG_HEADER_LEN..])
                })
                .unwrap_or(false);
            if ok {
                good.push((r.esi, if keep_data { raw[SEG_HEADER_LEN..].to_vec() } else { Vec::new() }));
            } else {
                bad.push((r.esi, r.offset));
            }
        }
        (good, bad)
    }

    fn inspect_group(&self, set: &SetInfo, g: u32) -> GroupHealth {
        let members = Self::group_members(set, g);
        let mut blocks = Vec::with_capacity(members.len());
        let (mut k, mut erased) = (0u32, 0u32);
        for &m in &members {
            let bh = self.check_block(m);
            k += self.nsyms(&self.index.blocks[m]) as u32;
            erased += bh.bad_symbols.len() as u32;
            blocks.push(bh);
        }
        let (good, bad) = self.read_valid_repairs(set.id, g, false);
        GroupHealth {
            set: set.id,
            group: g,
            k,
            erased,
            repair_total: (good.len() + bad.len()) as u32,
            repair_ok: good.len() as u32,
            bad_repairs: bad,
            blocks,
            decode_verified: erased == 0,
        }
    }

    pub fn assess_group(&self, set: &SetInfo, g: u32) -> GroupHealth {
        let mut group = self.inspect_group(set, g);
        if group.erased != 0 && group.erased <= group.repair_ok {
            group.decode_verified = self.solve_group(&group, &HashMap::new()).is_some_and(|decoded| {
                let mut at = 0;
                group.blocks.iter().all(|bh| {
                    let b = &self.index.blocks[bh.idx];
                    let end = at + b.stored_len as usize;
                    let valid = if bh.hash_ok {
                        bh.content_ok
                    } else {
                        let stored = &decoded[at..end];
                        hash128(stored) == b.hash
                            && (self.locked || self.header.detached() || self.decode_block(b, stored).is_ok())
                    };
                    at += self.nsyms(b) * self.symbol_size();
                    valid
                })
            });
        }
        group
    }

    pub fn assess(&self, progress: &dyn Progress) -> Assessment {
        progress.emit(Event::Stage("Verifying".into()));
        let total_blocks = self.index.blocks.len() as u64;
        let done = AtomicU64::new(0);
        let tick = |n: u64| {
            let d = done.fetch_add(n, Ordering::Relaxed) + n;
            progress.emit(Event::Progress { done: d, total: total_blocks });
        };

        let mut tasks: Vec<(usize, Option<u32>)> = Vec::new(); // (set index, Some(group) | None = loose)
        for (si, s) in self.index.sets.iter().enumerate() {
            if s.stripe == 0 {
                tasks.push((si, None));
            } else {
                for g in 0..s.stripe {
                    tasks.push((si, Some(g)));
                }
            }
        }
        enum Res {
            Group(Box<GroupHealth>),
            Loose(Vec<BlockHealth>),
        }
        let results = pmap(&tasks, |&(si, g)| {
            let s = &self.index.sets[si];
            match g {
                Some(g) => {
                    let gh = self.assess_group(s, g);
                    tick(gh.blocks.len() as u64);
                    Res::Group(Box::new(gh))
                }
                None => {
                    let v: Vec<BlockHealth> =
                        (s.first_block..s.first_block + s.block_count).map(|i| self.check_block(i as usize)).collect();
                    tick(v.len() as u64);
                    Res::Loose(v)
                }
            }
        });

        let mut groups = Vec::new();
        let mut loose = Vec::new();
        for r in results {
            match r {
                Res::Group(g) => groups.push(*g),
                Res::Loose(v) => loose.extend(v.into_iter().filter(|b| b.needs_work())),
            }
        }
        let mut states = vec![BlockState::Good; self.index.blocks.len()];
        let mut health = Health::Healthy;
        let mut blocks_damaged = 0;
        let (mut min_ratio, mut min_sym): (Option<f64>, Option<i64>) = (None, None);
        for gh in &groups {
            let st = gh.state();
            health = health.max(st);
            for bh in &gh.blocks {
                if !bh.hash_ok || !bh.content_ok {
                    blocks_damaged += 1;
                    states[bh.idx] = if st == Health::Damaged { BlockState::Lost } else { BlockState::Repairable };
                } else if bh.needs_work() {
                    states[bh.idx] = BlockState::Repairable;
                }
            }
            if gh.k > 0 {
                let r = gh.headroom() as f64 / gh.k as f64;
                if min_ratio.map(|m| r < m).unwrap_or(true) {
                    min_ratio = Some(r);
                }
                if min_sym.map(|m| gh.headroom() < m).unwrap_or(true) {
                    min_sym = Some(gh.headroom());
                }
            }
        }
        if self.index.sets.iter().any(|set| set.stripe == 0) && !groups.is_empty() {
            min_ratio = Some(min_ratio.unwrap_or(0.0).min(0.0));
            min_sym = Some(min_sym.unwrap_or(0).min(0));
        }
        for bh in &loose {
            if !bh.hash_ok || !bh.content_ok {
                blocks_damaged += 1;
                states[bh.idx] = BlockState::Lost;
                health = health.max(Health::Damaged);
            } else {
                states[bh.idx] = BlockState::Repairable;
                health = health.max(Health::Repairable);
            }
        }
        let mut structural = self.notes.clone();
        if self.locked {
            structural.push("locked: verification covers stored bytes; unlock to verify files".into());
        }
        if let Some(detached) = &self.index.detached {
            match self.target.as_ref().and_then(|target| target.len().ok()) {
                None => {
                    structural.push("attach the protected file to verify this sidecar".into());
                    health = Health::Damaged;
                }
                Some(len) if len != detached.target_len => {
                    structural.push(format!("protected file length differs from {} bytes", detached.target_len));
                    health = health.max(Health::Repairable);
                }
                _ => {}
            }
        }
        if !self.inventory_complete {
            health = Health::Damaged;
        }
        if self.src.is_incomplete() {
            health = health.max(Health::Repairable);
        }
        if self.opened_via != OpenPath::Footer
            || self.structure.footer_ok != [true, true]
            || self.structure.header_ok != [true, true]
            || (self.header.feat_required & REQ_CHECKPOINTS != 0
                && (self.structure.index_ok != [true, true] || !self.structure.catalog_ok))
        {
            if structural.is_empty() {
                structural.push(format!("opened via {}", self.opened_via.describe()));
            }
            health = health.max(Health::Repairable);
        }
        Assessment {
            groups,
            loose,
            block_states: states,
            structural,
            blocks_total: self.index.blocks.len(),
            inventory_complete: self.inventory_complete && !self.locked,
            stored_bytes_only: self.locked,
            blocks_damaged,
            health,
            min_headroom_ratio: min_ratio,
            min_headroom_symbols: min_sym,
        }
    }

    // ------------------------------------------------------------ repairing

    /// Reconstruct every source symbol of a group. `overrides` supplies known-good stored bytes
    /// for blocks (e.g. from a second copy).
    fn solve_group(&self, gh: &GroupHealth, overrides: &HashMap<usize, Vec<u8>>) -> Option<Vec<u8>> {
        let ss = self.symbol_size();
        let k = gh.k as usize;
        let mut buf = vec![0u8; k * ss];
        let mut present_idx: Vec<u32> = Vec::new();
        let mut at = 0usize;
        for bh in &gh.blocks {
            let b = &self.index.blocks[bh.idx];
            let n = self.nsyms(b);
            let (data, bad): (Vec<u8>, HashSet<u32>) = match overrides.get(&bh.idx) {
                Some(o) => (pad(o.clone(), ss), HashSet::new()),
                None => (pad(self.read_stored(b), ss), bh.bad_symbols.iter().copied().collect()),
            };
            buf[at * ss..(at + n) * ss].copy_from_slice(&data[..n * ss]);
            for i in 0..n as u32 {
                if !bad.contains(&i) {
                    present_idx.push((at as u32) + i);
                }
            }
            at += n;
        }
        let (repairs, _) = self.read_valid_repairs(gh.set, gh.group, true);
        let present: Vec<(u32, &[u8])> =
            present_idx.iter().map(|&i| (i, &buf[i as usize * ss..(i as usize + 1) * ss])).collect();
        let reps: Vec<(u32, &[u8])> = repairs.iter().map(|(e, d)| (*e, d.as_slice())).collect();
        ecc::decode(k, self.header.symbol_size, &present, &reps)
    }

    fn block_segment_patch(&self, b: &BlockEntry, stored: &[u8]) -> Patch {
        if self.header.detached() {
            return Patch { offset: b.offset, data: stored.to_vec() };
        }
        let ss = self.symbol_size();
        let hdr = SegHeader {
            kind: kind::DATA,
            codec: b.codec,
            flags: b.flags,
            stored_len: b.stored_len,
            raw_len: b.raw_len,
            owner: if b.flags & flag::RAW_OFFSET != 0 { b.raw_offset as u32 } else { 0 },
            seq: b.seq,
            hash: b.hash,
            set_id: b.set_id as u16,
            stripe: if b.flags & flag::RAW_OFFSET != 0 { (b.raw_offset >> 32) as u16 } else { 0 },
        };
        let padded = pad(stored.to_vec(), ss);
        let mut data = hdr.encode().to_vec();
        if b.flags & flag::SYMCRC != 0 {
            let table = symbol_crc_table(&padded, ss);
            data.extend_from_slice(&table);
            data.extend_from_slice(&padded);
            data.extend_from_slice(&table);
        } else {
            data.extend_from_slice(&padded);
        }
        Patch { offset: b.offset, data }
    }

    fn push_block_patch(&self, plan: &mut RepairPlan, b: &BlockEntry, stored: &[u8]) {
        let p = self.block_segment_patch(b, stored);
        if self.header.detached() {
            plan.target_patches.push(p);
        } else {
            plan.patches.push(p);
        }
        plan.blocks_fixed += 1;
    }

    pub fn plan_repair(&self, a: &Assessment, donor: Option<&dyn Donor>, progress: &dyn Progress) -> RepairPlan {
        progress.emit(Event::Stage("Repairing".into()));
        let ss = self.symbol_size();
        let mut plan = RepairPlan::default();
        let mut lost: Vec<usize> = Vec::new();

        let donor_for = |idx: usize| -> Option<Vec<u8>> {
            let b = &self.index.blocks[idx];
            donor?.stored_block(b.seq, &b.hash)
        };

        struct GroupOut {
            patches: Vec<(usize, Vec<u8>)>, // (block idx, stored bytes)
            rec_patches: Vec<Patch>,
            regenerated: u32,
            lost: Vec<usize>,
        }
        let todo: Vec<&GroupHealth> = a.groups.iter().filter(|g| g.state() != Health::Healthy).collect();
        let outs = pmap(&todo, |gh| {
            let mut out = GroupOut { patches: vec![], rec_patches: vec![], regenerated: 0, lost: vec![] };
            let mut overrides: HashMap<usize, Vec<u8>> = HashMap::new();
            for bh in gh.blocks.iter().filter(|b| !b.hash_ok) {
                if let Some(s) = donor_for(bh.idx) {
                    overrides.insert(bh.idx, s);
                }
            }
            let mut work = (*gh).clone();
            work.erased -= work
                .blocks
                .iter()
                .filter(|b| overrides.contains_key(&b.idx))
                .map(|b| b.bad_symbols.len() as u32)
                .sum::<u32>();
            match self.solve_group(&work, &overrides) {
                Some(all) => {
                    let mut at = 0usize;
                    for bh in &gh.blocks {
                        let b = &self.index.blocks[bh.idx];
                        let n = self.nsyms(b);
                        if !bh.content_ok {
                            out.lost.push(bh.idx);
                        } else if bh.needs_work() {
                            let stored = all[at * ss..at * ss + b.stored_len as usize].to_vec();
                            if hash128(&stored) == b.hash
                                && (self.locked || self.header.detached() || self.decode_block(b, &stored).is_ok())
                            {
                                out.patches.push((bh.idx, stored));
                            } else {
                                out.lost.push(bh.idx);
                            }
                        }
                        at += n;
                    }
                    if !gh.bad_repairs.is_empty() {
                        let esis: Vec<u32> = gh.bad_repairs.iter().map(|r| r.0).collect();
                        let regen = ecc::regenerate_repair(&all, self.header.symbol_size, &esis);
                        for r in regen {
                            if let Some(&(_, off)) = gh.bad_repairs.iter().find(|x| x.0 == r.esi) {
                                let hdr = SegHeader {
                                    kind: kind::RECOVERY,
                                    codec: 0,
                                    flags: 0,
                                    stored_len: ss as u32,
                                    raw_len: ss as u32,
                                    owner: gh.group,
                                    seq: r.esi as u64,
                                    hash: hash128(&r.data),
                                    set_id: gh.set as u16,
                                    stripe: self
                                        .index
                                        .sets
                                        .iter()
                                        .find(|s| s.id == gh.set)
                                        .map(|s| s.stripe as u16)
                                        .unwrap_or(0),
                                };
                                let mut data = hdr.encode().to_vec();
                                data.extend_from_slice(&r.data);
                                out.rec_patches.push(Patch { offset: off, data });
                                out.regenerated += 1;
                            }
                        }
                    }
                }
                None => {
                    for bh in gh.blocks.iter().filter(|b| !b.hash_ok) {
                        match overrides.get(&bh.idx) {
                            Some(s) => out.patches.push((bh.idx, s.clone())),
                            None => out.lost.push(bh.idx),
                        }
                    }
                }
            }
            out
        });
        for o in outs {
            for (idx, stored) in o.patches {
                let b = self.index.blocks[idx].clone();
                self.push_block_patch(&mut plan, &b, &stored);
            }
            plan.patches.extend(o.rec_patches);
            plan.recovery_regenerated += o.regenerated;
            lost.extend(o.lost);
        }

        for bh in &a.loose {
            let b = &self.index.blocks[bh.idx];
            if !bh.content_ok {
                lost.push(bh.idx);
            } else if bh.hash_ok {
                let stored = self.read_stored(b);
                self.push_block_patch(&mut plan, b, &stored);
            } else if let Some(s) = donor_for(bh.idx) {
                self.push_block_patch(&mut plan, b, &s);
            } else {
                lost.push(bh.idx);
            }
        }

        self.plan_structure(&mut plan);
        if lost.is_empty() {
            if let (Some(detached), Some(target)) = (&self.index.detached, &self.target) {
                if target.len().is_ok_and(|len| len != detached.target_len) {
                    plan.target_len = Some(detached.target_len);
                }
            }
        }
        lost.sort_unstable();
        lost.dedup();
        plan.lost_files = self.files_touching(&lost).into_iter().map(|f| f.path.clone()).collect();
        plan.lost_blocks = lost;
        plan
    }

    fn plan_structure(&self, plan: &mut RepairPlan) {
        let hl = self.header.header_len as u64;
        let enc = self.header.encode();
        if !self.structure.header_ok[0] {
            plan.patches.push(Patch { offset: 0, data: enc.clone() });
            plan.structural_fixed += 1;
        }
        if !self.structure.header_ok[1] {
            plan.patches.push(Patch { offset: hl, data: enc });
            plan.structural_fixed += 1;
        }
        if !self.inventory_complete {
            plan.notes.push(
                if self.locked {
                    "unlock the archive to verify and rebuild the file inventory"
                } else {
                    "complete inventory is unavailable; extract the surviving files"
                }
                .into(),
            );
            return;
        }
        let final_index_damaged = self.header.feat_required & REQ_CHECKPOINTS != 0
            && (self.structure.index_ok != [true, true] || !self.structure.catalog_ok);
        if matches!(self.opened_via, OpenPath::Footer | OpenPath::MirrorFooter) && !final_index_damaged {
            let t = self.total_len;
            let (good, bad) = if self.structure.footer_ok[0] { (t - 128, t - 64) } else { (t - 64, t - 128) };
            if self.structure.footer_ok.iter().any(|ok| !ok) {
                if let Ok(f) = read_vec(&self.src, good, FOOTER_LEN) {
                    plan.patches.push(Patch { offset: bad, data: f });
                    plan.structural_fixed += 1;
                }
            }
        } else {
            let idx = self.full_index();
            let existing = self.recovered_catalog.clone().or_else(|| {
                self.sealed_index.and_then(|off| {
                    let (_, h) = self.load_index_at(off).ok()?;
                    read_vec(&self.src, off + SEG_HEADER_LEN as u64, h.stored_len as usize).ok()
                })
            });
            let payload = match existing {
                Some(payload) => payload,
                None if !self.locked => idx.to_bytes(self.crypto.as_ref()),
                None => {
                    plan.notes.push("index damaged: repair with the password to rebuild it".into());
                    return;
                }
            };
            let mut hdr = SegHeader {
                kind: kind::INDEX_MIRROR,
                codec: codec::LZ4,
                flags: 0,
                stored_len: payload.len() as u32,
                raw_len: 0,
                owner: 1,
                seq: self.header.generation,
                hash: hash128(&payload),
                set_id: 0,
                stripe: 0,
            };
            let off = self.total_len;
            let mut data = Vec::new();
            if let Err(e) = crate::catalog::encode(&payload, self.header.generation, |header, symbol| {
                data.extend_from_slice(&header.encode());
                data.extend_from_slice(symbol);
                Ok(())
            }) {
                plan.notes.push(format!("could not rebuild protected catalog: {e}"));
                return;
            }
            data.extend_from_slice(&hdr.encode());
            data.extend_from_slice(&payload);
            let primary = off + data.len() as u64;
            hdr.kind = kind::INDEX;
            data.extend_from_slice(&hdr.encode());
            data.extend_from_slice(&payload);
            let footer = Footer {
                index_offset: primary,
                index_len: SEG_HEADER_LEN as u32 + hdr.stored_len,
                index_hash: hdr.hash,
                uuid: self.header.uuid,
                total_segments: idx.blocks.len() as u32,
                index_gap: 0,
            }
            .encode();
            data.extend_from_slice(&footer);
            data.extend_from_slice(&footer);
            plan.patches.push(Patch { offset: off, data });
            plan.structural_fixed += 1;
        }
    }

    pub fn files_touching(&self, blocks: &[usize]) -> Vec<&FileEntry> {
        if blocks.is_empty() {
            return vec![];
        }
        let ranges: Vec<(u64, u64)> = blocks
            .iter()
            .map(|&i| {
                let b = &self.index.blocks[i];
                (b.raw_offset, b.raw_offset + b.raw_len as u64)
            })
            .collect();
        self.index
            .files
            .iter()
            .filter(|f| f.kind == KIND_FILE && f.size > 0)
            .filter(|f| ranges.iter().any(|&(s, e)| f.stream_offset < e && f.stream_offset + f.size > s))
            .collect()
    }

    // ------------------------------------------------------------ reading data

    fn heal_stored(&self, idx: usize) -> Option<Vec<u8>> {
        let set = self.set_of(idx)?;
        if set.stripe == 0 {
            return None;
        }
        let (g, _) = ecc::stripe(idx as u32 - set.first_block, set.stripe);
        let solved = {
            let mut m = self.heal.lock().unwrap();
            if let Some(decoded) = m.get(&(set.id, g)) {
                decoded.clone()
            } else {
                let gh = self.inspect_group(set, g);
                let decoded = self.solve_group(&gh, &HashMap::new()).map(Arc::new);
                m.clear();
                m.insert((set.id, g), decoded.clone());
                if decoded.is_some() {
                    self.healed_count.fetch_add(1, Ordering::Relaxed);
                }
                decoded
            }
        }?;
        let ss = self.symbol_size();
        let mut at = 0usize;
        for m in Self::group_members(set, g) {
            let b = &self.index.blocks[m];
            if m == idx {
                let s = solved[at * ss..at * ss + b.stored_len as usize].to_vec();
                return (hash128(&s) == b.hash).then_some(s);
            }
            at += self.nsyms(b);
        }
        None
    }

    /// Number of ECC groups that had to be reconstructed in memory so far.
    pub fn healed_groups(&self) -> usize {
        self.healed_count.load(Ordering::Relaxed) as usize
    }

    /// Decoded (decrypted + decompressed) bytes of a block, repairing in memory if needed.
    pub fn load_block(&self, idx: usize) -> Result<Arc<Vec<u8>>> {
        if let Some((_, d)) = self.cache.lock().unwrap().iter().find(|(i, _)| *i == idx) {
            return Ok(d.clone());
        }
        let b = &self.index.blocks[idx];
        let mut stored = vec![0; b.stored_len as usize];
        let readable =
            self.block_src().is_some_and(|src| src.read_exact_at(&mut stored, self.stored_offset(b)).is_ok());
        if !readable || hash128(&stored) != b.hash {
            stored = self.heal_stored(idx).ok_or(Error::BlockLost(b.seq))?;
        }
        let data = Arc::new(self.decode_block(b, &stored).map_err(|e| match e {
            Error::PasswordRequired => e,
            _ => Error::BlockLost(b.seq),
        })?);
        let mut c = self.cache.lock().unwrap();
        if c.len() >= 16 {
            c.pop_front();
        }
        c.push_back((idx, data.clone()));
        Ok(data)
    }

    fn decode_block(&self, b: &BlockEntry, stored: &[u8]) -> Result<Vec<u8>> {
        let decoded;
        let compressed = if b.flags & flag::ENCRYPTED != 0 {
            let c = self.crypto.as_ref().ok_or(Error::PasswordRequired)?;
            decoded = if b.flags & flag::RANDOM_NONCE != 0 {
                c.decrypt_random_block(b.seq, stored)?
            } else {
                c.decrypt_block(b.seq, stored)?
            };
            &decoded
        } else {
            stored
        };
        codec::decompress(b.codec, compressed, b.raw_len as usize)
    }

    fn first_block_at(&self, raw_offset: u64) -> usize {
        self.index.blocks.partition_point(|b| b.raw_offset + b.raw_len as u64 <= raw_offset)
    }

    pub fn extract_to(&self, f: &FileEntry, out: &mut dyn Write, cache: &mut BlockCache) -> Result<()> {
        if self.locked {
            return Err(Error::PasswordRequired);
        }
        let (mut pos, end) = (f.stream_offset, f.stream_offset + f.size);
        let mut bi = self.first_block_at(pos);
        while pos < end {
            let b = self.index.blocks.get(bi).ok_or(Error::BlockLost(bi as u64))?;
            let data = match &cache.entry {
                Some((i, d)) if *i == bi => d.clone(),
                _ => {
                    let d = self.load_block(bi)?;
                    cache.entry = Some((bi, d.clone()));
                    d
                }
            };
            if pos < b.raw_offset {
                return Err(Error::BlockLost(b.seq.saturating_sub(1)));
            }
            let from = (pos - b.raw_offset) as usize;
            let to = ((end - b.raw_offset) as usize).min(data.as_slice().len());
            out.write_all(&data[from..to])?;
            pos = b.raw_offset + to as u64;
            bi += 1;
        }
        Ok(())
    }

    /// Read `len` bytes of a file starting at `offset` (used by mount and serve).
    pub fn read_range(&self, f: &FileEntry, offset: u64, len: usize) -> Result<Vec<u8>> {
        if self.locked {
            return Err(Error::PasswordRequired);
        }
        if offset >= f.size {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(len as u64).min(f.size);
        let (mut pos, mut out) = (f.stream_offset + offset, Vec::with_capacity((end - offset) as usize));
        let stop = f.stream_offset + end;
        let mut bi = self.first_block_at(pos);
        while pos < stop {
            let b = self.index.blocks.get(bi).ok_or(Error::BlockLost(bi as u64))?;
            let data = self.load_block(bi)?;
            if pos < b.raw_offset {
                return Err(Error::BlockLost(b.seq.saturating_sub(1)));
            }
            let from = (pos - b.raw_offset) as usize;
            let to = ((stop - b.raw_offset) as usize).min(data.as_slice().len());
            out.extend_from_slice(&data[from..to]);
            pos = b.raw_offset + to as u64;
            bi += 1;
        }
        Ok(out)
    }

    pub fn read_file(&self, f: &FileEntry) -> Result<Vec<u8>> {
        let mut v = Vec::new();
        self.extract_to(f, &mut v, &mut BlockCache::default())?;
        Ok(v)
    }

    /// Entries visible as of `snapshot` (latest version of each path).
    pub fn visible_files(&self, snapshot: Option<u32>) -> Vec<&FileEntry> {
        let limit = snapshot.unwrap_or(u32::MAX);
        let mut latest: HashMap<&str, &FileEntry> = HashMap::new();
        for f in self.index.files.iter().filter(|f| f.snapshot <= limit) {
            latest.insert(f.path.as_str(), f);
        }
        let mut v: Vec<&FileEntry> = latest.into_values().collect();
        v.sort_by(|a, b| a.path.cmp(&b.path));
        v
    }

    /// `sha256sum`-compatible manifest, so anyone can verify extracted files without razerq.
    pub fn visit_manifest(&self, snapshot: Option<u32>, mut visit: impl FnMut(&str, &str) -> Result<()>) -> Result<()> {
        use sha2::{Digest, Sha256};
        struct HashW(Sha256);
        impl Write for HashW {
            fn write(&mut self, b: &[u8]) -> io::Result<usize> {
                self.0.update(b);
                Ok(b.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        if let Some(id) = snapshot {
            if !self.index.snapshots.iter().any(|s| s.id == id) {
                return Err(Error::Other(format!("unknown snapshot {id}")));
            }
        }
        let mut cache = BlockCache::default();
        for f in self.visible_files(snapshot).into_iter().filter(|f| f.kind == KIND_FILE) {
            let mut h = HashW(Sha256::new());
            self.extract_to(f, &mut h, &mut cache)?;
            let hex: String = h.0.finalize().iter().map(|b| format!("{b:02x}")).collect();
            visit(&f.path, &hex)?;
        }
        Ok(())
    }

    pub fn manifest(&self, snapshot: Option<u32>, out: &mut dyn Write) -> Result<()> {
        self.visit_manifest(snapshot, |path, hex| {
            if path.contains(['\n', '\r', '\\']) {
                let escaped = path.replace('\\', "\\\\").replace('\n', "\\n").replace('\r', "\\r");
                writeln!(out, "\\{hex}  {escaped}")?;
            } else {
                writeln!(out, "{hex}  {path}")?;
            }
            Ok(())
        })
    }

    pub fn info(&self) -> Info {
        let ss = self.symbol_size() as u64;
        let stored: u64 = self.index.blocks.iter().map(|b| b.stored_len as u64).sum();
        let rec_syms: u64 = self.recs.values().map(|v| v.len() as u64).sum();
        let groups: u32 = self.index.sets.iter().map(|s| s.stripe).sum();
        let raw: u64 = self.index.blocks.iter().map(|b| b.raw_len as u64).sum();
        let tiny = self.header.feat_optional & OPT_TINY_PROFILE != 0;
        let weak = if rec_syms == 0 {
            Some("no recovery data: damage can be detected but not repaired".to_string())
        } else if self.index.sets.iter().any(|s| s.stripe == 1 && s.block_count <= 2) && stored < (1 << 20) {
            let per = rec_syms.min(rec_syms / groups.max(1) as u64);
            Some(format!("small archive: {per} repair symbols in its recovery group; keep a second copy elsewhere"))
        } else {
            None
        };
        Info {
            version: (self.header.ver_major, self.header.ver_minor),
            writer: self.header.writer.clone(),
            uuid: self.header.uuid,
            file_len: self.total_len,
            files: self.index.files.iter().filter(|f| f.kind == KIND_FILE).count(),
            dirs: self.index.files.iter().filter(|f| f.kind == KIND_DIR).count(),
            raw_bytes: raw,
            stored_bytes: stored,
            recovery_bytes: rec_syms * ss,
            blocks: self.index.blocks.len(),
            sets: self.index.sets.len(),
            groups,
            symbol_size: self.header.symbol_size,
            block_size: self.header.block_size(),
            encrypted: self.header.encrypted(),
            locked: self.locked,
            detached: self.header.detached(),
            tiny_profile: tiny,
            snapshots: self.index.snapshots.clone(),
            opened_via: self.opened_via,
            protection_ratio: if stored > 0 { (rec_syms * ss) as f64 / stored as f64 } else { 0.0 },
            weak_protection: weak,
        }
    }
}

#[derive(Default)]
pub struct BlockCache {
    entry: Option<(usize, Arc<Vec<u8>>)>,
}

impl<S: ReadAt> Donor for Archive<S> {
    fn stored_block(&self, seq: u64, hash: &[u8; 16]) -> Option<Vec<u8>> {
        let p = self.index.blocks.partition_point(|b| b.seq < seq);
        let b = self.index.blocks.get(p)?;
        if b.seq != seq || &b.hash != hash {
            return None;
        }
        let s = self.read_stored(b);
        (hash128(&s) == *hash).then_some(s)
    }
}

/// Apply patches to an in-memory archive image (used by the WASM build and tests).
pub fn apply_patches_to_vec(data: &mut Vec<u8>, patches: &[Patch]) {
    for p in patches {
        let end = p.offset as usize + p.data.len();
        if data.len() < end {
            data.resize(end, 0);
        }
        data[p.offset as usize..end].copy_from_slice(&p.data);
    }
}
