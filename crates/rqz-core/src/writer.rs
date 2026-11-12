//! Creating and appending to archives.
//!
//! Files are concatenated into one logical stream that is cut into independent
//! blocks (so damage is contained and random access is cheap). Blocks are grouped
//! into ECC *sets*; each set is striped over several groups and protected by
//! RaptorQ repair symbols written round-robin after the set's data.

use crate::archive::Archive;
use crate::codec::{self, Compression};
use crate::crypto::{random_bytes, Crypto};
use crate::error::{Error, Result};
use crate::format::*;
use crate::index::*;
use crate::progress::{Event, Progress};
use crate::storage::{parallelism, pmap, read_vec, ReadAt};
use rqz_ecc as ecc;
use std::io::{Read, Seek, SeekFrom, Write};

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Protect {
    /// Repair symbols as a share of source symbols (0.10 = 10%).
    pub ratio: f64,
    /// Floor per group, so small archives still get a usable safety margin.
    pub min_repair: u32,
}

impl Protect {
    pub const NONE: Protect = Protect { ratio: 0.0, min_repair: 0 };
    pub const LOW: Protect = Protect { ratio: 0.02, min_repair: 2 };
    pub const NORMAL: Protect = Protect { ratio: 0.10, min_repair: 4 };
    pub const PARANOID: Protect = Protect { ratio: 0.30, min_repair: 8 };

    pub fn parse(s: &str) -> Option<Protect> {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "0" | "none" | "off" => Some(Protect::NONE),
            "low" => Some(Protect::LOW),
            "normal" => Some(Protect::NORMAL),
            "paranoid" | "max" => Some(Protect::PARANOID),
            _ => {
                let v: f64 = s.strip_suffix('%')?.parse().ok()?;
                (0.0..=300.0).contains(&v).then(|| Protect { ratio: v / 100.0, min_repair: 4 })
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct PackOptions {
    pub compression: Compression,
    pub protect: Protect,
    pub block_size: u32,
    /// `None` = automatic (4 KiB, or 1 KiB for the tiny profile).
    pub symbol_size: Option<u16>,
    pub target_k: u32,
    pub set_bytes: u64,
    pub password: Option<String>,
    pub deterministic: bool,
    pub snapshot_name: Option<String>,
    /// Total input size if known; archives under 1 MiB use the tiny profile.
    pub total_hint: Option<u64>,
    pub now_unix: i64,
    /// Split into volumes of about this many bytes (0 = single file). Set by the volume writer's caller.
    pub volume_size: u64,
    /// Recovery data is sized so that this many whole volumes can be lost.
    pub survive_volumes: u32,
}

pub fn default_now() -> i64 {
    #[cfg(not(target_arch = "wasm32"))]
    {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
    }
    #[cfg(target_arch = "wasm32")]
    {
        0
    }
}

impl Default for PackOptions {
    fn default() -> Self {
        PackOptions {
            compression: Compression::Normal,
            protect: Protect::NORMAL,
            block_size: 2 << 20,
            symbol_size: None,
            target_k: 12_000,
            set_bytes: 1 << 30,
            password: None,
            deterministic: false,
            snapshot_name: None,
            total_hint: None,
            now_unix: default_now(),
            volume_size: 0,
            survive_volumes: 0,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct Summary {
    pub files: u64,
    pub dirs: u64,
    pub raw_bytes: u64,
    pub stored_bytes: u64,
    pub recovery_bytes: u64,
    pub file_len: u64,
    pub blocks: u64,
    pub groups: u32,
    pub tiny_profile: bool,
    pub warnings: Vec<String>,
    pub volumes: u32,
}

/// Where an archive is written. Plain files need nothing special; a split-volume writer uses
/// the hooks to learn the header (copied into every volume) and where to cut a volume short.
pub trait ArchiveSink: Read + Write + Seek {
    /// Called with the encoded archive header before anything is written.
    fn note_header(&mut self, _header: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    /// The recovery region starts here: end the current volume at `pos` so that the tail
    /// volumes hold only recovery data and the final index (losing one never loses data blocks).
    fn cut_here(&mut self, _pos: u64) -> std::io::Result<()> {
        Ok(())
    }
}
impl ArchiveSink for std::fs::File {}
impl ArchiveSink for std::io::Cursor<Vec<u8>> {}

pub struct ArchiveWriter<'p, W: ArchiveSink> {
    w: W,
    header: Header,
    opts: PackOptions,
    crypto: Option<Crypto>,
    ss: usize,
    bs: usize,
    index: IndexData,
    pos: u64,
    cur: Vec<u8>,
    cur_skip: usize,
    stream_pos: u64,
    next_seq: u64,
    next_file_id: u32,
    snapshot: u32,
    set_id: u32,
    set_first_block: usize,
    set_stored: u64,
    meta_pending: Vec<FileEntry>,
    segments: u32,
    recovery_bytes: u64,
    stored_bytes: u64,
    files: u64,
    dirs: u64,
    raw_bytes: u64,
    target: Option<Box<dyn ReadAt>>,
    warnings: Vec<String>,
    progress: &'p dyn Progress,
}

impl<'p, W: ArchiveSink> ArchiveWriter<'p, W> {
    fn blank(w: W, header: Header, opts: PackOptions, crypto: Option<Crypto>, progress: &'p dyn Progress) -> Self {
        let ss = header.symbol_size as usize;
        let bs = header.block_size();
        ArchiveWriter {
            w,
            header,
            opts,
            crypto,
            ss,
            bs,
            index: IndexData::default(),
            pos: 0,
            cur: Vec::new(),
            cur_skip: 0,
            stream_pos: 0,
            next_seq: 0,
            next_file_id: 0,
            snapshot: 1,
            set_id: 0,
            set_first_block: 0,
            set_stored: 0,
            meta_pending: Vec::new(),
            segments: 0,
            recovery_bytes: 0,
            stored_bytes: 0,
            files: 0,
            dirs: 0,
            raw_bytes: 0,
            target: None,
            warnings: Vec::new(),
            progress,
        }
    }

    pub fn create(mut w: W, opts: PackOptions, progress: &'p dyn Progress) -> Result<Self> {
        let tiny = opts.total_hint.map(|t| t < (1 << 20)).unwrap_or(false);
        let ss = opts.symbol_size.unwrap_or(if tiny { 1024 } else { 4096 });
        if ss < 64 || ss % 8 != 0 {
            return Err(Error::Other("symbol size must be a multiple of 8 and at least 64".into()));
        }
        if !opts.block_size.is_power_of_two() || !(4096..=(64 << 20)).contains(&opts.block_size) {
            return Err(Error::Other("block size must be a power of two between 4 KiB and 64 MiB".into()));
        }
        if opts.deterministic && opts.password.is_some() {
            return Err(Error::Other("deterministic output cannot be combined with encryption".into()));
        }
        let mut h = Header::new(if tiny { HEADER_LEN_TINY } else { HEADER_LEN_NORMAL });
        h.uuid = if opts.deterministic { [0; 16] } else { random_bytes::<16>() };
        h.created_unix = if opts.deterministic { 0 } else { opts.now_unix.max(0) as u64 };
        h.block_log2 = opts.block_size.trailing_zeros() as u8;
        h.symbol_size = ss;
        h.target_k = opts.target_k.clamp(64, ecc::MAX_K);
        if tiny {
            h.feat_optional |= OPT_TINY_PROFILE;
        }
        let mut crypto = None;
        if let Some(pw) = &opts.password {
            let kdf = Crypto::new_kdf();
            let c = Crypto::derive(pw, &kdf, h.uuid)?;
            h.feat_required |= REQ_ENCRYPTED;
            h.key_check = Some(c.key_check());
            h.kdf = Some(kdf);
            crypto = Some(c);
        }
        let hb = h.encode();
        w.note_header(&hb)?;
        w.seek(SeekFrom::Start(0))?;
        w.write_all(&hb)?;
        w.write_all(&hb)?;
        let mut me = Self::blank(w, h, opts, crypto, progress);
        me.pos = 2 * me.header.header_len as u64;
        me.index.snapshots.push(Snapshot {
            id: 1,
            created: if me.opts.deterministic { 0 } else { me.opts.now_unix },
            name: me.opts.snapshot_name.clone().unwrap_or_else(|| "initial".into()),
        });
        Ok(me)
    }

    /// Continue an existing archive: new data goes after the old tail, with a new
    /// snapshot, a fresh index and new footers. Older footers stay valid points in time.
    pub fn append<S: ReadAt>(
        w: W,
        archive: &Archive<S>,
        opts: PackOptions,
        progress: &'p dyn Progress,
    ) -> Result<Self> {
        if archive.locked {
            return Err(Error::PasswordRequired);
        }
        if archive.header.detached() {
            return Err(Error::Unsupported("cannot append to a detached sidecar".into()));
        }
        let mut me = Self::blank(w, archive.header.clone(), opts, archive.crypto().cloned(), progress);
        me.index = archive.full_index();
        me.pos = archive.file_len();
        if let Some(b) = me.index.blocks.last() {
            me.next_seq = b.seq + 1;
            me.stream_pos = b.raw_offset + b.raw_len as u64;
        }
        me.set_id = me.index.sets.iter().map(|s| s.id + 1).max().unwrap_or(0);
        me.set_first_block = me.index.blocks.len();
        me.next_file_id = me.index.files.iter().map(|f| f.id + 1).max().unwrap_or(0);
        me.snapshot = me.index.snapshots.iter().map(|s| s.id + 1).max().unwrap_or(1);
        me.segments = me.index.blocks.len() as u32;
        me.index.snapshots.push(Snapshot {
            id: me.snapshot,
            created: me.opts.now_unix,
            name: me.opts.snapshot_name.clone().unwrap_or_else(|| format!("snapshot {}", me.snapshot)),
        });
        Ok(me)
    }

    /// Start a detached sidecar that protects an existing file without touching it.
    pub fn create_detached<T: ReadAt + 'static>(
        w: W,
        mut opts: PackOptions,
        target: T,
        target_name: &str,
        progress: &'p dyn Progress,
    ) -> Result<Self> {
        let len = target.len()?;
        opts.total_hint = Some(len.max(1 << 20));
        opts.block_size = opts.block_size.min(1 << 20);
        opts.password = None;
        let mut me = Self::create(w, opts, progress)?;
        me.header.feat_required |= REQ_DETACHED;
        me.header.feat_optional &= !OPT_TINY_PROFILE;
        let hb = me.header.encode();
        me.w.seek(SeekFrom::Start(0))?;
        me.w.write_all(&hb)?;
        me.w.write_all(&hb)?;
        me.index.snapshots.clear();
        me.index.detached =
            Some(Detached { target_name: target_name.to_string(), target_len: len, crc_offset: me.pos });
        me.target = Some(Box::new(target));
        let (bs, ss) = (me.bs as u64, me.ss);
        // Phase 1: hash every block and write its symbol-CRC segment (contiguous, in block order).
        let mut off = 0u64;
        while off < len {
            let n = bs.min(len - off) as usize;
            let mut data = read_vec(me.target.as_deref().unwrap(), off, n)?;
            let hash = hash128(&data);
            data.resize(padded_len(n, ss), 0);
            let table = symbol_crc_table(&data, ss);
            let hdr = SegHeader {
                kind: kind::CRCTAB,
                codec: codec::STORE,
                flags: 0,
                stored_len: table.len() as u32,
                raw_len: 0,
                owner: me.next_seq as u32,
                seq: me.next_seq,
                hash: hash128(&table),
                set_id: 0,
                stripe: 0,
            };
            me.write_segment(&hdr, &table)?;
            if me.set_stored >= me.opts.set_bytes {
                me.set_id += 1;
                me.set_stored = 0;
            }
            me.index.blocks.push(BlockEntry {
                seq: me.next_seq,
                offset: off,
                stored_len: n as u32,
                raw_len: n as u32,
                raw_offset: off,
                codec: codec::STORE,
                flags: 0,
                set_id: me.set_id,
                hash,
            });
            me.next_seq += 1;
            me.set_stored += n as u64;
            me.raw_bytes += n as u64;
            off += n as u64;
            me.progress.emit(Event::Progress { done: off, total: len });
        }
        // Phase 2: protect each set.
        me.set_id = 0;
        me.set_first_block = 0;
        me.set_stored = 0;
        while me.set_first_block < me.index.blocks.len() {
            let (first, sid) = (me.set_first_block, me.set_id);
            let end = me.index.blocks[first..]
                .iter()
                .position(|b| b.set_id != sid)
                .map(|p| first + p)
                .unwrap_or(me.index.blocks.len());
            me.close_set_range(end, false)?;
        }
        Ok(me)
    }

    // ------------------------------------------------------------ adding data

    fn new_entry(
        &mut self,
        path: &str,
        kind: u8,
        size: u64,
        mode: u32,
        mtime: i64,
        link: Option<String>,
    ) -> Result<()> {
        let e = FileEntry {
            id: self.next_file_id,
            path: path.to_string(),
            kind,
            size,
            mode,
            mtime,
            stream_offset: self.stream_pos - size,
            link,
            snapshot: self.snapshot,
        };
        self.next_file_id += 1;
        self.index.files.push(e.clone());
        self.meta_pending.push(e);
        if self.meta_pending.len() >= 512 {
            self.flush_meta()?;
        }
        Ok(())
    }

    /// Add a file whose bytes come from `r`. Returns the number of bytes stored.
    pub fn add_file<R: Read>(&mut self, path: &str, mode: u32, mtime: i64, r: &mut R) -> Result<u64> {
        let skip = codec::looks_incompressible(path);
        let mut tmp = vec![0u8; 1 << 20];
        let mut total = 0u64;
        loop {
            let n = r.read(&mut tmp)?;
            if n == 0 {
                break;
            }
            self.push_bytes(&tmp[..n], skip)?;
            total += n as u64;
        }
        self.files += 1;
        self.new_entry(path, KIND_FILE, total, mode, mtime, None)?;
        Ok(total)
    }

    pub fn add_bytes(&mut self, path: &str, mode: u32, mtime: i64, data: &[u8]) -> Result<u64> {
        let mut r = data;
        self.add_file(path, mode, mtime, &mut r)
    }

    pub fn add_dir(&mut self, path: &str, mode: u32, mtime: i64) -> Result<()> {
        self.dirs += 1;
        self.new_entry(path, KIND_DIR, 0, mode, mtime, None)
    }

    pub fn add_symlink(&mut self, path: &str, target: &str, mode: u32, mtime: i64) -> Result<()> {
        self.new_entry(path, KIND_SYMLINK, 0, mode, mtime, Some(target.to_string()))
    }

    fn push_bytes(&mut self, mut data: &[u8], skip: bool) -> Result<()> {
        while !data.is_empty() {
            let take = (self.bs - self.cur.len()).min(data.len());
            self.cur.extend_from_slice(&data[..take]);
            if skip {
                self.cur_skip += take;
            }
            self.stream_pos += take as u64;
            self.raw_bytes += take as u64;
            data = &data[take..];
            if self.cur.len() == self.bs {
                self.flush_block()?;
            }
        }
        Ok(())
    }

    // ------------------------------------------------------------ segments

    fn write_segment(&mut self, hdr: &SegHeader, payload: &[u8]) -> Result<u64> {
        let off = self.pos;
        self.w.seek(SeekFrom::Start(off))?;
        self.w.write_all(&hdr.encode())?;
        self.w.write_all(payload)?;
        self.pos += (SEG_HEADER_LEN + payload.len()) as u64;
        self.segments += 1;
        Ok(off)
    }

    fn flush_block(&mut self) -> Result<()> {
        if self.cur.is_empty() {
            return Ok(());
        }
        let raw = std::mem::take(&mut self.cur);
        let all_skip = self.cur_skip == raw.len();
        self.cur_skip = 0;
        let (codec_id, mut stored) =
            if all_skip { (codec::STORE, raw.clone()) } else { codec::compress(self.opts.compression, &raw) };
        let seq = self.next_seq;
        let mut flags = flag::SYMCRC;
        if let Some(c) = &self.crypto {
            stored = c.encrypt_block(seq, &stored);
            flags |= flag::ENCRYPTED;
        }
        let hash = hash128(&stored);
        let stored_len = stored.len() as u32;
        let mut padded = stored;
        padded.resize(padded_len(stored_len as usize, self.ss), 0);
        let table = symbol_crc_table(&padded, self.ss);
        let mut payload = Vec::with_capacity(padded.len() + 2 * table.len());
        payload.extend_from_slice(&table);
        payload.extend_from_slice(&padded);
        payload.extend_from_slice(&table);
        let hdr = SegHeader {
            kind: kind::DATA,
            codec: codec_id,
            flags,
            stored_len,
            raw_len: raw.len() as u32,
            owner: 0,
            seq,
            hash,
            set_id: self.set_id as u16,
            stripe: 0,
        };
        let off = self.write_segment(&hdr, &payload)?;
        self.index.blocks.push(BlockEntry {
            seq,
            offset: off,
            stored_len,
            raw_len: raw.len() as u32,
            raw_offset: self.stream_pos - raw.len() as u64,
            codec: codec_id,
            flags,
            set_id: self.set_id,
            hash,
        });
        self.stored_bytes += stored_len as u64;
        self.next_seq += 1;
        self.set_stored += payload.len() as u64;
        self.progress.emit(Event::Progress {
            done: self.stream_pos,
            total: self.opts.total_hint.unwrap_or(0).max(self.stream_pos),
        });
        if self.set_stored >= self.opts.set_bytes {
            self.close_set(true)?;
        }
        Ok(())
    }

    fn flush_meta(&mut self) -> Result<()> {
        if self.meta_pending.is_empty() {
            return Ok(());
        }
        let list = std::mem::take(&mut self.meta_pending);
        let payload = files_to_bytes(&list, self.crypto.as_ref());
        let hdr = SegHeader {
            kind: kind::META,
            codec: codec::STORE,
            flags: if self.crypto.is_some() { flag::ENCRYPTED } else { 0 },
            stored_len: payload.len() as u32,
            raw_len: payload.len() as u32,
            owner: 0,
            seq: 0,
            hash: hash128(&payload),
            set_id: 0,
            stripe: 0,
        };
        self.write_segment(&hdr, &payload)?;
        Ok(())
    }

    fn write_index_segment(&mut self) -> Result<(u64, SegHeader)> {
        let payload = self.index.to_bytes(self.crypto.as_ref());
        let hdr = SegHeader {
            kind: kind::INDEX,
            codec: codec::LZ4,
            flags: 0,
            stored_len: payload.len() as u32,
            raw_len: 0,
            owner: 0,
            seq: 0,
            hash: hash128(&payload),
            set_id: 0,
            stripe: 0,
        };
        let off = self.write_segment(&hdr, &payload)?;
        Ok((off, hdr))
    }

    // ------------------------------------------------------------ ECC

    fn read_block_symbols(&mut self, idx: usize) -> Result<Vec<u8>> {
        let (off, len) = {
            let b = &self.index.blocks[idx];
            (b.offset, b.stored_len as usize)
        };
        let data_off = off + (SEG_HEADER_LEN + table_len(len, self.ss)) as u64;
        let mut v = vec![0u8; padded_len(len, self.ss)];
        match &self.target {
            Some(t) => t.read_exact_at(&mut v[..len], off)?,
            None => {
                self.w.seek(SeekFrom::Start(data_off))?;
                self.w.read_exact(&mut v[..len])?;
            }
        }
        Ok(v)
    }

    /// Generate and write one region of repair symbols for `set`, starting at repair index `start`.
    fn write_set_recovery(&mut self, set: &SetInfo, start: u32, protect: Protect) -> Result<Option<Region>> {
        let g_count = set.stripe as usize;
        let members: Vec<Vec<usize>> = (0..set.stripe)
            .map(|g| (g..set.block_count).step_by(g_count).map(|i| (set.first_block + i) as usize).collect())
            .collect();
        let ss = self.ss;
        let kmax = members
            .iter()
            .map(|m| m.iter().map(|&i| n_symbols(self.index.blocks[i].stored_len as usize, ss) as u32).sum::<u32>())
            .max()
            .unwrap_or(0);
        let mut ratio = protect.ratio;
        if self.opts.volume_size > 0 && self.opts.survive_volumes > 0 && start == 0 {
            // Sized so that `survive_volumes` whole volumes can vanish. Erasures are quantised by
            // block (a lost volume also clips a block at each end), so work in blocks, per group.
            let all: Vec<usize> = members.iter().flatten().copied().collect();
            let syms = |i: usize| n_symbols(self.index.blocks[i].stored_len as usize, ss) as u64;
            let total_bytes: u64 = all.iter().map(|&i| syms(i) * ss as u64).sum();
            let avg = (total_bytes / all.len().max(1) as u64).max(1);
            let max_syms = all.iter().map(|&i| syms(i)).max().unwrap_or(1);
            let lost_blocks = (self.opts.volume_size / avg + 2) * self.opts.survive_volumes as u64;
            let need = lost_blocks.div_ceil(g_count as u64) * max_syms + 2;
            let floor = need as f64 / kmax.max(1) as f64 * 1.05;
            if total_bytes <= self.opts.volume_size {
                self.warnings.push("the whole archive fits in one volume, so there is no volume to lose".into());
            }
            if floor > 1.0 && total_bytes > self.opts.volume_size {
                self.warnings.push(format!(
                    "recovery data will be about {:.0}% of the archive because one volume is {:.0}% of it; smaller volumes need much less",
                    floor.min(3.0) * 100.0,
                    100.0 * self.opts.volume_size as f64 / total_bytes as f64
                ));
            }
            if floor > ratio {
                ratio = floor.min(3.0);
                if floor > 3.0 {
                    self.warnings.push(format!(
                        "surviving {} lost volume(s) would need more than 300% recovery data; capped at 300%. Use smaller volumes or fewer survived volumes",
                        self.opts.survive_volumes
                    ));
                }
            }
        }
        let r = ecc::repair_count(kmax, ratio, protect.min_repair);
        if r == 0 || kmax == 0 {
            return Ok(None);
        }
        let seg_len = (SEG_HEADER_LEN + ss) as u64;
        self.w.cut_here(self.pos)?;
        let region_start = self.pos;
        let mut esi_start = vec![0u32; g_count];
        let batch = (parallelism() * 2).max(2);
        let order: Vec<usize> = (0..g_count).collect();
        for chunk in order.chunks(batch) {
            let mut inputs: Vec<(usize, Vec<u8>)> = Vec::new();
            for &g in chunk {
                let mut buf = Vec::new();
                for &m in &members[g] {
                    buf.extend(self.read_block_symbols(m)?);
                }
                inputs.push((g, buf));
            }
            let outs = pmap(&inputs, |(_, buf)| ecc::encode_repair(buf, ss as u16, start, r));
            for ((g, _), reps) in inputs.iter().zip(outs) {
                esi_start[*g] = reps[0].esi;
                for (j, rep) in reps.iter().enumerate() {
                    let hdr = SegHeader {
                        kind: kind::RECOVERY,
                        codec: codec::STORE,
                        flags: 0,
                        stored_len: ss as u32,
                        raw_len: ss as u32,
                        owner: *g as u32,
                        seq: rep.esi as u64,
                        hash: hash128(&rep.data),
                        set_id: set.id as u16,
                        stripe: g_count as u16,
                    };
                    let off = region_start + (j as u64 * g_count as u64 + *g as u64) * seg_len;
                    self.w.seek(SeekFrom::Start(off))?;
                    self.w.write_all(&hdr.encode())?;
                    self.w.write_all(&rep.data)?;
                }
            }
        }
        let total = r as u64 * g_count as u64;
        self.pos = region_start + total * seg_len;
        self.segments += total as u32;
        self.recovery_bytes += total * ss as u64;
        Ok(Some(Region { set_id: set.id, group_base: 0, offset: region_start, per_group: r, esi_start }))
    }

    fn close_set(&mut self, checkpoint: bool) -> Result<()> {
        let end = self.index.blocks.len();
        self.close_set_range(end, checkpoint)
    }

    fn close_set_range(&mut self, end: usize, checkpoint: bool) -> Result<()> {
        let first = self.set_first_block;
        let n = end - first;
        if n == 0 {
            return Ok(());
        }
        if self.set_id > u16::MAX as u32 {
            return Err(Error::Other("too many ECC sets".into()));
        }
        self.progress.emit(Event::Stage("Writing recovery data".into()));
        let protect = self.opts.protect;
        let mut set = SetInfo { id: self.set_id, first_block: first as u32, block_count: n as u32, stripe: 0 };
        if protect.ratio > 0.0 || (self.opts.volume_size > 0 && self.opts.survive_volumes > 0) {
            let ss = self.ss;
            let total_syms: u64 =
                self.index.blocks[first..end].iter().map(|b| n_symbols(b.stored_len as usize, ss) as u64).sum();
            set.stripe = ecc::group_count(total_syms, self.header.target_k).min(n as u32);
            if let Some(region) = self.write_set_recovery(&set, 0, protect)? {
                self.index.regions.push(region);
            } else {
                set.stripe = 0;
            }
        }
        self.index.sets.push(set);
        self.set_id += 1;
        self.set_first_block = end;
        self.set_stored = 0;
        if checkpoint {
            self.flush_meta()?;
            self.write_index_segment()?;
        }
        Ok(())
    }

    /// Top up redundancy of every protected set by `protect` (rateless codes make this cheap).
    pub fn add_protection(&mut self, protect: Protect) -> Result<u32> {
        self.progress.emit(Event::Stage("Adding recovery data".into()));
        let sets: Vec<SetInfo> = self.index.sets.iter().filter(|s| s.stripe > 0).cloned().collect();
        let mut added = 0;
        for set in sets {
            let have: u32 = self.index.regions.iter().filter(|r| r.set_id == set.id).map(|r| r.per_group).sum();
            if let Some(region) = self.write_set_recovery(&set, have, protect)? {
                added += region.per_group * set.stripe;
                self.index.regions.push(region);
            }
        }
        Ok(added)
    }

    pub fn finish(mut self) -> Result<(W, Summary)> {
        self.flush_block()?;
        // File names go in *before* the recovery region, so a truncated or tail-less archive
        // still knows what its blocks are.
        self.flush_meta()?;
        self.close_set(false)?;
        let (off, hdr) = self.write_index_segment()?;
        let footer = Footer {
            index_offset: off,
            index_len: (SEG_HEADER_LEN as u32) + hdr.stored_len,
            index_hash: hdr.hash,
            uuid: self.header.uuid,
            total_segments: self.segments,
        }
        .encode();
        self.w.seek(SeekFrom::Start(self.pos))?;
        self.w.write_all(&footer)?;
        self.w.write_all(&footer)?;
        self.pos += 2 * FOOTER_LEN as u64;
        self.w.flush()?;
        let summary = Summary {
            files: self.files,
            dirs: self.dirs,
            raw_bytes: self.raw_bytes,
            stored_bytes: self.stored_bytes,
            recovery_bytes: self.recovery_bytes,
            file_len: self.pos,
            blocks: self.index.blocks.len() as u64,
            groups: self.index.sets.iter().map(|s| s.stripe).sum(),
            tiny_profile: self.header.feat_optional & OPT_TINY_PROFILE != 0,
            warnings: self.warnings.clone(),
            volumes: 1,
        };
        Ok((self.w, summary))
    }
}
