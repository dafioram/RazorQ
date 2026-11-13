//! The index: file table, block table, ECC sets and recovery regions.
//!
//! Serialised as tagged, length-prefixed sections so that new sections can be
//! added later: readers skip unknown tags unless the tag's critical bit is set.
//! The file table is sealed separately when the archive is encrypted, so check
//! and repair can still use everything else without the password.

use crate::crypto::Crypto;
use crate::error::{Error, Result};
use crate::format::{flag, n_symbols, Header, SegHeader, SEG_HEADER_LEN};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_SYMLINK: u8 = 2;

pub fn validate_member_path(path: &str) -> Result<()> {
    if path.split('/').any(|c| {
        c.is_empty()
            || c == "."
            || c == ".."
            || c.contains(['\\', '\0'])
            || (cfg!(windows)
                && (c.contains([':', '<', '>', '"', '|', '?', '*'])
                    || c.ends_with([' ', '.'])
                    || matches!(
                        c.split('.').next().unwrap_or("").to_ascii_uppercase().as_str(),
                        "CON"
                            | "PRN"
                            | "AUX"
                            | "NUL"
                            | "COM1"
                            | "COM2"
                            | "COM3"
                            | "COM4"
                            | "COM5"
                            | "COM6"
                            | "COM7"
                            | "COM8"
                            | "COM9"
                            | "LPT1"
                            | "LPT2"
                            | "LPT3"
                            | "LPT4"
                            | "LPT5"
                            | "LPT6"
                            | "LPT7"
                            | "LPT8"
                            | "LPT9"
                    )))
    }) {
        return Err(Error::Other(format!("unsafe archive path {path:?}")));
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct FileEntry {
    pub id: u32,
    pub path: String,
    pub kind: u8,
    pub size: u64,
    pub mode: u32,
    pub mtime: i64,
    /// Offset of this file's first byte in the logical stream that all files share.
    pub stream_offset: u64,
    pub link: Option<String>,
    pub snapshot: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct BlockEntry {
    pub seq: u64,
    /// Offset of the segment header (archive) or of the data (detached target).
    pub offset: u64,
    pub stored_len: u32,
    pub raw_len: u32,
    pub raw_offset: u64,
    pub codec: u8,
    pub flags: u16,
    pub set_id: u32,
    pub hash: [u8; 16],
}

/// An ECC set: a run of consecutive blocks protected together, striped over `stripe` groups.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct SetInfo {
    pub id: u32,
    pub first_block: u32,
    pub block_count: u32,
    /// Number of groups (0 = unprotected).
    pub stripe: u32,
}

/// Recovery segments of one set, written round-robin: for j in 0..per_group, for each group g.
/// Segment (g, j) lives at `offset + (j * groups + g) * (56 + symbol_size)`.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Region {
    pub set_id: u32,
    pub group_base: u32,
    pub offset: u64,
    pub per_group: u32,
    /// ESI of repair symbol j = 0 for each group (consecutive afterwards).
    pub esi_start: Vec<u32>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub id: u32,
    pub created: i64,
    pub name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct Detached {
    pub target_name: String,
    pub target_len: u64,
    /// Where the per-block symbol CRC segments start (they are contiguous, in block order).
    pub crc_offset: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct IndexData {
    pub files: Vec<FileEntry>,
    pub blocks: Vec<BlockEntry>,
    pub sets: Vec<SetInfo>,
    pub regions: Vec<Region>,
    pub snapshots: Vec<Snapshot>,
    pub detached: Option<Detached>,
}

const T_FILES: u16 = 1;
const T_BLOCKS: u16 = 2;
const T_SETS: u16 = 3;
const T_REGIONS: u16 = 4;
const T_SNAPSHOTS: u16 = 5;
const T_DETACHED: u16 = 6;
const CRITICAL: u16 = 0x8000;
pub(crate) const MAX_INDEX: usize = 64 << 20;

fn enc<T: Serialize>(v: &T) -> Vec<u8> {
    bincode::serialize(v).expect("index serialisation cannot fail")
}
fn dec<T: for<'a> Deserialize<'a>>(b: &[u8]) -> Result<T> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(b.len() as u64)
        .reject_trailing_bytes()
        .deserialize(b)
        .map_err(|e| Error::Corrupt(format!("index section: {e}")))
}

impl IndexData {
    pub(crate) fn inventory_hashes(&self, crypto: Option<&Crypto>) -> ([u8; 16], [u8; 16]) {
        let files = enc(&self.files);
        let file_hash = match crypto {
            Some(c) => c.inventory_hash(&files),
            None => crate::format::hash128(&files),
        };
        (crate::format::hash128(&enc(&self.blocks)), file_hash)
    }

    pub(crate) fn validate(&self, header: &Header, total: u64, salvage: bool) -> Result<()> {
        let invalid = |field: &str| Error::Corrupt(format!("invalid {field} in archive index"));
        let ss = usize::from(header.symbol_size);
        if header.detached() != self.detached.is_some() {
            return Err(invalid("detached target"));
        }
        let mut stream_end = 0u64;
        let mut physical_end = if header.detached() { 0 } else { 2 * u64::from(header.header_len) };
        let mut last_seq = None;
        for b in &self.blocks {
            let segment = SegHeader {
                kind: crate::format::kind::DATA,
                codec: b.codec,
                flags: b.flags,
                stored_len: b.stored_len,
                raw_len: b.raw_len,
                owner: 0,
                seq: b.seq,
                hash: b.hash,
                set_id: b.set_id as u16,
                stripe: 0,
            };
            let len = if header.detached() { u64::from(b.stored_len) } else { segment.total_len(ss) };
            let limit = self.detached.as_ref().map_or(total, |d| d.target_len);
            let max_stored = header.block_size() + crate::crypto::TAG_LEN + crate::crypto::NONCE_LEN;
            if b.raw_len == 0
                || b.raw_len as usize > header.block_size()
                || b.stored_len == 0
                || b.stored_len as usize > max_stored
                || b.flags & flag::RANDOM_NONCE != 0 && b.flags & flag::ENCRYPTED == 0
                || b.codec > crate::codec::LZ4
                || b.set_id > u16::MAX as u32
                || b.raw_offset < stream_end
                || (!salvage && b.raw_offset != stream_end)
                || b.offset < physical_end
                || (!salvage && b.offset.checked_add(len).is_none_or(|end| end > limit))
                || last_seq.is_some_and(|seq| b.seq <= seq)
            {
                return Err(invalid("block range"));
            }
            stream_end = b.raw_offset.checked_add(u64::from(b.raw_len)).ok_or_else(|| invalid("stream size"))?;
            physical_end = b.offset.checked_add(len).ok_or_else(|| invalid("physical size"))?;
            last_seq = Some(b.seq);
        }
        let mut sets = HashMap::new();
        let mut next_block = 0usize;
        for set in &self.sets {
            let first = set.first_block as usize;
            let end = first.checked_add(set.block_count as usize).ok_or_else(|| invalid("set range"))?;
            if first != next_block
                || end > self.blocks.len()
                || set.block_count == 0
                || set.stripe > set.block_count
                || set.stripe > u16::MAX as u32
                || sets.insert(set.id, set.stripe).is_some()
            {
                return Err(invalid("set layout"));
            }
            let mut symbols = vec![0usize; set.stripe as usize];
            for (i, b) in self.blocks[first..end].iter().enumerate() {
                if b.set_id != set.id {
                    return Err(invalid("block set"));
                }
                if !symbols.is_empty() {
                    let group = i % symbols.len();
                    symbols[group] += n_symbols(b.stored_len as usize, ss);
                    if symbols[group] > rqz_ecc::MAX_K as usize {
                        return Err(invalid("ECC group size"));
                    }
                }
            }
            next_block = end;
        }
        if next_block != self.blocks.len() {
            return Err(invalid("block coverage"));
        }
        let mut extents = Vec::new();
        for r in &self.regions {
            let stripe = sets.get(&r.set_id).copied().ok_or_else(|| invalid("recovery set"))?;
            let groups = r.esi_start.len() as u64;
            let size = groups
                .checked_mul(u64::from(r.per_group))
                .and_then(|n| n.checked_mul(SEG_HEADER_LEN as u64 + ss as u64));
            let end = size.and_then(|n| r.offset.checked_add(n)).ok_or_else(|| invalid("recovery extent"))?;
            if groups == 0
                || r.per_group == 0
                || u64::from(r.group_base) + groups > u64::from(stripe)
                || r.offset < 2 * u64::from(header.header_len)
                || end > total
                || r.esi_start.iter().any(|&start| start.checked_add(r.per_group).is_none_or(|end| end > 1 << 24))
            {
                return Err(invalid("recovery region"));
            }
            extents.push((r.offset, end));
        }
        extents.sort_unstable();
        if extents.windows(2).any(|w| w[0].1 > w[1].0) {
            return Err(invalid("overlapping recovery regions"));
        }
        let mut ids = HashSet::new();
        let snapshots: HashSet<_> = self.snapshots.iter().map(|s| s.id).collect();
        for f in &self.files {
            if f.kind > KIND_SYMLINK
                || !ids.insert(f.id)
                || (!salvage && !snapshots.contains(&f.snapshot))
                || f.snapshot == 0
                || f.snapshot > 1_000_000
                || f.stream_offset.checked_add(f.size).is_none_or(|end| !salvage && end > stream_end)
                || (f.kind != KIND_FILE && f.size != 0)
            {
                return Err(invalid("file extent"));
            }
        }
        if let Some(d) = &self.detached {
            let end = self.blocks.iter().try_fold(d.crc_offset, |off, b| {
                off.checked_add((SEG_HEADER_LEN + crate::format::table_len(b.stored_len as usize, ss)) as u64)
            });
            if d.target_name.is_empty() || end.is_none_or(|end| end > total) || d.target_len != stream_end {
                return Err(invalid("detached target layout"));
            }
        }
        Ok(())
    }

    pub fn to_bytes(&self, crypto: Option<&Crypto>) -> Vec<u8> {
        let mut tlv = Vec::new();
        let mut put = |tag: u16, v: Vec<u8>| {
            tlv.extend_from_slice(&tag.to_le_bytes());
            tlv.extend_from_slice(&(v.len() as u32).to_le_bytes());
            tlv.extend_from_slice(&v);
        };
        let files = enc(&self.files);
        put(
            T_FILES,
            match crypto {
                Some(c) => c.seal(&files),
                None => files,
            },
        );
        put(T_BLOCKS, enc(&self.blocks));
        put(T_SETS, enc(&self.sets));
        put(T_REGIONS, enc(&self.regions));
        put(T_SNAPSHOTS, enc(&self.snapshots));
        if let Some(d) = &self.detached {
            put(T_DETACHED, enc(d));
        }
        lz4_flex::block::compress_prepend_size(&tlv)
    }

    /// Returns the index and whether the file table is still locked (encrypted, no key).
    pub fn from_bytes(bytes: &[u8], encrypted: bool, crypto: Option<&Crypto>) -> Result<(IndexData, bool)> {
        if bytes.len() < 4 {
            return Err(Error::Corrupt("index too short".into()));
        }
        let claimed = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
        if claimed > MAX_INDEX {
            return Err(Error::Corrupt("index size implausible".into()));
        }
        let tlv = lz4_flex::block::decompress_size_prepended(bytes)
            .map_err(|e| Error::Corrupt(format!("index decompress: {e}")))?;
        let mut idx = IndexData::default();
        let mut locked = false;
        let mut at = 0usize;
        while at + 6 <= tlv.len() {
            let tag = u16::from_le_bytes(tlv[at..at + 2].try_into().unwrap());
            let len = u32::from_le_bytes(tlv[at + 2..at + 6].try_into().unwrap()) as usize;
            let end = at + 6 + len;
            if end > tlv.len() {
                return Err(Error::Corrupt("index section overruns".into()));
            }
            let v = &tlv[at + 6..end];
            match tag & !CRITICAL {
                T_FILES => match (encrypted, crypto) {
                    (false, _) => idx.files = dec(v)?,
                    (true, Some(c)) => idx.files = dec(&c.open(v)?)?,
                    (true, None) => locked = true,
                },
                T_BLOCKS => idx.blocks = dec(v)?,
                T_SETS => idx.sets = dec(v)?,
                T_REGIONS => idx.regions = dec(v)?,
                T_SNAPSHOTS => idx.snapshots = dec(v)?,
                T_DETACHED => idx.detached = Some(dec(v)?),
                _ if tag & CRITICAL != 0 => {
                    return Err(Error::Unsupported(format!("unknown critical index section {tag:#x}")))
                }
                _ => {}
            }
            at = end;
        }
        Ok((idx, locked))
    }
}

pub fn files_to_bytes(files: &[FileEntry], crypto: Option<&Crypto>) -> Vec<u8> {
    let b = enc(&files.to_vec());
    match crypto {
        Some(c) => c.seal(&b),
        None => b,
    }
}

pub fn files_from_bytes(b: &[u8], crypto: Option<&Crypto>) -> Result<Vec<FileEntry>> {
    match crypto {
        Some(c) => dec(&c.open(b)?),
        None => dec(b),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_roundtrip_and_skips_unknown() {
        let mut i = IndexData::default();
        i.files.push(FileEntry {
            id: 0,
            path: "a/b.txt".into(),
            kind: 0,
            size: 5,
            mode: 0o644,
            mtime: 1,
            stream_offset: 0,
            link: None,
            snapshot: 1,
        });
        i.snapshots.push(Snapshot { id: 1, created: 0, name: "first".into() });
        let raw = i.to_bytes(None);
        let (back, locked) = IndexData::from_bytes(&raw, false, None).unwrap();
        assert!(!locked);
        assert_eq!(back, i);
        // append an unknown, non-critical section
        let mut tlv = lz4_flex::block::decompress_size_prepended(&raw).unwrap();
        tlv.extend_from_slice(&0x0123u16.to_le_bytes());
        tlv.extend_from_slice(&3u32.to_le_bytes());
        tlv.extend_from_slice(b"xyz");
        let raw2 = lz4_flex::block::compress_prepend_size(&tlv);
        assert_eq!(IndexData::from_bytes(&raw2, false, None).unwrap().0, i);
    }
}
