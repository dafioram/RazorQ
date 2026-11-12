//! The index: file table, block table, ECC sets and recovery regions.
//!
//! Serialised as tagged, length-prefixed sections so that new sections can be
//! added later: readers skip unknown tags unless the tag's critical bit is set.
//! The file table is sealed separately when the archive is encrypted, so check
//! and repair can still use everything else without the password.

use crate::crypto::Crypto;
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};

pub const KIND_FILE: u8 = 0;
pub const KIND_DIR: u8 = 1;
pub const KIND_SYMLINK: u8 = 2;

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
const MAX_INDEX: usize = 1 << 30;

fn enc<T: Serialize>(v: &T) -> Vec<u8> {
    bincode::serialize(v).expect("index serialisation cannot fail")
}
fn dec<T: for<'a> Deserialize<'a>>(b: &[u8]) -> Result<T> {
    bincode::deserialize(b).map_err(|e| Error::Corrupt(format!("index section: {e}")))
}

impl IndexData {
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
