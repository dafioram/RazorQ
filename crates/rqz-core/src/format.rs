//! Byte-level structures. See `docs/FORMAT.md` for the prose version.
//! All integers are little-endian; CRC32C guards structure, BLAKE3 guards payloads.

use crate::error::{Error, Result};

pub const MAGIC: [u8; 8] = [0x89, b'R', b'Q', b'Z', 0x0D, 0x0A, 0x1A, 0x0A];
pub const FOOTER_MAGIC: [u8; 8] = [0x89, b'R', b'Q', b'F', 0x0D, 0x0A, 0x1A, 0x0A];
pub const SYNC: [u8; 8] = [0xD3, b'R', b'Q', b'S', 0xA5, 0x5A, 0xC3, 0x3C];

pub const FORMAT_MAJOR: u16 = 0;
pub const FORMAT_MINOR: u16 = 1;

pub const HEADER_LEN_NORMAL: u32 = 4096;
pub const HEADER_LEN_TINY: u32 = 512;
pub const SEG_HEADER_LEN: usize = 56;
pub const FOOTER_LEN: usize = 64;

/// Feature flags (ext4 style). Unknown *required* bit: refuse to open.
/// Unknown *read-only* bit: extract/check only. Unknown *optional* bit: ignore.
pub const REQ_ENCRYPTED: u64 = 1 << 0;
pub const REQ_DETACHED: u64 = 1 << 1;
pub const KNOWN_REQUIRED: u64 = REQ_ENCRYPTED | REQ_DETACHED;
pub const KNOWN_READONLY: u64 = 0;
pub const OPT_TINY_PROFILE: u64 = 1 << 0;

pub mod kind {
    pub const DATA: u8 = 0;
    pub const RECOVERY: u8 = 1;
    pub const INDEX: u8 = 2;
    pub const DICT: u8 = 3; // reserved
    pub const CRCTAB: u8 = 4; // detached sidecars: per-symbol CRCs of one protected block
    pub const META: u8 = 5;
}
pub mod flag {
    pub const ENCRYPTED: u16 = 1;
    pub const DEDUP: u16 = 2; // reserved
    pub const SYMCRC: u16 = 4;
}

pub fn hash128(data: &[u8]) -> [u8; 16] {
    let h = blake3::hash(data);
    let mut o = [0u8; 16];
    o.copy_from_slice(&h.as_bytes()[..16]);
    o
}

pub fn crc(data: &[u8]) -> u32 {
    crc32c::crc32c(data)
}

fn u16_at(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes(b[o..o + 2].try_into().unwrap())
}
fn u32_at(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes(b[o..o + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(b[o..o + 8].try_into().unwrap())
}

// ---------------------------------------------------------------- header

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub salt: [u8; 16],
    pub m_kib: u32,
    pub t_cost: u32,
    pub lanes: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub header_len: u32,
    pub ver_major: u16,
    pub ver_minor: u16,
    pub min_reader: u16,
    pub feat_required: u64,
    pub feat_readonly: u64,
    pub feat_optional: u64,
    pub uuid: [u8; 16],
    pub created_unix: u64,
    pub block_log2: u8,
    pub symbol_size: u16,
    pub target_k: u32,
    pub writer: String,
    pub kdf: Option<Kdf>,
    pub key_check: Option<[u8; 16]>,
}

const TLV_WRITER: u16 = 1;
const TLV_KDF: u16 = 2;
const TLV_KEYCHECK: u16 = 3;
const HDR_FIXED: usize = 76;

impl Header {
    pub fn new(header_len: u32) -> Header {
        Header {
            header_len,
            ver_major: FORMAT_MAJOR,
            ver_minor: FORMAT_MINOR,
            min_reader: FORMAT_MINOR,
            feat_required: 0,
            feat_readonly: 0,
            feat_optional: 0,
            uuid: [0; 16],
            created_unix: 0,
            block_log2: 21,
            symbol_size: 4096,
            target_k: 12_000,
            writer: format!("rqz-core {}", env!("CARGO_PKG_VERSION")),
            kdf: None,
            key_check: None,
        }
    }

    pub fn encrypted(&self) -> bool {
        self.feat_required & REQ_ENCRYPTED != 0
    }
    pub fn detached(&self) -> bool {
        self.feat_required & REQ_DETACHED != 0
    }
    pub fn block_size(&self) -> usize {
        1usize << self.block_log2
    }

    pub fn encode(&self) -> Vec<u8> {
        let len = self.header_len as usize;
        let mut b = vec![0u8; len];
        b[0..8].copy_from_slice(&MAGIC);
        b[8..12].copy_from_slice(&self.header_len.to_le_bytes());
        b[12..14].copy_from_slice(&self.ver_major.to_le_bytes());
        b[14..16].copy_from_slice(&self.ver_minor.to_le_bytes());
        b[16..18].copy_from_slice(&self.min_reader.to_le_bytes());
        b[20..28].copy_from_slice(&self.feat_required.to_le_bytes());
        b[28..36].copy_from_slice(&self.feat_readonly.to_le_bytes());
        b[36..44].copy_from_slice(&self.feat_optional.to_le_bytes());
        b[44..60].copy_from_slice(&self.uuid);
        b[60..68].copy_from_slice(&self.created_unix.to_le_bytes());
        b[68] = self.block_log2;
        b[70..72].copy_from_slice(&self.symbol_size.to_le_bytes());
        b[72..76].copy_from_slice(&self.target_k.to_le_bytes());
        let mut at = HDR_FIXED;
        let mut put = |tag: u16, val: &[u8]| {
            assert!(at + 4 + val.len() + 6 <= len, "header TLV does not fit");
            b[at..at + 2].copy_from_slice(&tag.to_le_bytes());
            b[at + 2..at + 4].copy_from_slice(&(val.len() as u16).to_le_bytes());
            b[at + 4..at + 4 + val.len()].copy_from_slice(val);
            at += 4 + val.len();
        };
        put(TLV_WRITER, self.writer.as_bytes());
        if let Some(k) = &self.kdf {
            let mut v = Vec::with_capacity(28);
            v.extend_from_slice(&k.salt);
            v.extend_from_slice(&k.m_kib.to_le_bytes());
            v.extend_from_slice(&k.t_cost.to_le_bytes());
            v.extend_from_slice(&k.lanes.to_le_bytes());
            put(TLV_KDF, &v);
        }
        if let Some(c) = &self.key_check {
            put(TLV_KEYCHECK, c);
        }
        let c = crc(&b[..len - 4]);
        b[len - 4..].copy_from_slice(&c.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Result<Header> {
        if b.len() < HDR_FIXED + 8 || b[0..8] != MAGIC {
            return Err(Error::NotArchive);
        }
        let len = b.len();
        if u32_at(b, 8) as usize != len {
            return Err(Error::Corrupt("header length mismatch".into()));
        }
        if crc(&b[..len - 4]) != u32_at(b, len - 4) {
            return Err(Error::Corrupt("header checksum mismatch".into()));
        }
        let mut h = Header::new(len as u32);
        h.ver_major = u16_at(b, 12);
        h.ver_minor = u16_at(b, 14);
        h.min_reader = u16_at(b, 16);
        h.feat_required = u64_at(b, 20);
        h.feat_readonly = u64_at(b, 28);
        h.feat_optional = u64_at(b, 36);
        h.uuid.copy_from_slice(&b[44..60]);
        h.created_unix = u64_at(b, 60);
        h.block_log2 = b[68];
        h.symbol_size = u16_at(b, 70);
        h.target_k = u32_at(b, 72);
        h.writer.clear();
        let mut at = HDR_FIXED;
        while at + 4 <= len - 4 {
            let tag = u16_at(b, at);
            let l = u16_at(b, at + 2) as usize;
            if tag == 0 || at + 4 + l > len - 4 {
                break;
            }
            let v = &b[at + 4..at + 4 + l];
            match tag {
                TLV_WRITER => h.writer = String::from_utf8_lossy(v).into_owned(),
                TLV_KDF if l == 28 => {
                    let mut salt = [0u8; 16];
                    salt.copy_from_slice(&v[..16]);
                    h.kdf = Some(Kdf { salt, m_kib: u32_at(v, 16), t_cost: u32_at(v, 20), lanes: u32_at(v, 24) });
                }
                TLV_KEYCHECK if l == 16 => {
                    let mut c = [0u8; 16];
                    c.copy_from_slice(v);
                    h.key_check = Some(c);
                }
                _ => {}
            }
            at += 4 + l;
        }
        Ok(h)
    }

    /// Refuse headers this build cannot safely interpret.
    pub fn check_supported(&self) -> Result<()> {
        if self.ver_major > FORMAT_MAJOR || self.min_reader > FORMAT_MINOR {
            return Err(Error::Unsupported(format!(
                "archive format {}.{} needs a newer razerq (this build reads {}.{})",
                self.ver_major, self.ver_minor, FORMAT_MAJOR, FORMAT_MINOR
            )));
        }
        let unknown = self.feat_required & !KNOWN_REQUIRED;
        if unknown != 0 {
            return Err(Error::Unsupported(format!("unknown required feature bits {unknown:#x}")));
        }
        if !(12..=26).contains(&self.block_log2) {
            return Err(Error::Corrupt("block size out of range".into()));
        }
        if self.symbol_size < 8 || self.symbol_size % 8 != 0 {
            return Err(Error::Corrupt("symbol size must be a multiple of 8".into()));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- segments

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SegHeader {
    pub kind: u8,
    pub codec: u8,
    pub flags: u16,
    pub stored_len: u32,
    pub raw_len: u32,
    pub owner: u32,
    pub seq: u64,
    pub hash: [u8; 16],
    pub set_id: u16,
    pub stripe: u16,
}

impl SegHeader {
    pub fn encode(&self) -> [u8; SEG_HEADER_LEN] {
        let mut b = [0u8; SEG_HEADER_LEN];
        b[0..8].copy_from_slice(&SYNC);
        b[8] = self.kind;
        b[9] = self.codec;
        b[10..12].copy_from_slice(&self.flags.to_le_bytes());
        b[12..16].copy_from_slice(&self.stored_len.to_le_bytes());
        b[16..20].copy_from_slice(&self.raw_len.to_le_bytes());
        b[20..24].copy_from_slice(&self.owner.to_le_bytes());
        b[24..32].copy_from_slice(&self.seq.to_le_bytes());
        b[32..48].copy_from_slice(&self.hash);
        b[48..50].copy_from_slice(&self.set_id.to_le_bytes());
        b[50..52].copy_from_slice(&self.stripe.to_le_bytes());
        let c = crc(&b[..52]);
        b[52..56].copy_from_slice(&c.to_le_bytes());
        b
    }

    pub fn decode(b: &[u8]) -> Option<SegHeader> {
        if b.len() < SEG_HEADER_LEN || b[0..8] != SYNC || crc(&b[..52]) != u32_at(b, 52) {
            return None;
        }
        let mut hash = [0u8; 16];
        hash.copy_from_slice(&b[32..48]);
        Some(SegHeader {
            kind: b[8],
            codec: b[9],
            flags: u16_at(b, 10),
            stored_len: u32_at(b, 12),
            raw_len: u32_at(b, 16),
            owner: u32_at(b, 20),
            seq: u64_at(b, 24),
            hash,
            set_id: u16_at(b, 48),
            stripe: u16_at(b, 50),
        })
    }

    pub fn has_symcrc(&self) -> bool {
        self.flags & flag::SYMCRC != 0
    }

    /// Total bytes of this segment on disk, header included.
    pub fn total_len(&self, symbol_size: usize) -> u64 {
        SEG_HEADER_LEN as u64
            + match self.kind {
                kind::DATA if self.has_symcrc() => data_payload_len(self.stored_len as usize, symbol_size) as u64,
                kind::DATA => padded_len(self.stored_len as usize, symbol_size) as u64,
                kind::RECOVERY => symbol_size as u64,
                _ => self.stored_len as u64,
            }
    }
}

pub fn n_symbols(stored_len: usize, ss: usize) -> usize {
    stored_len.div_ceil(ss).max(1)
}
pub fn padded_len(stored_len: usize, ss: usize) -> usize {
    n_symbols(stored_len, ss) * ss
}
/// One CRC32C per symbol plus a CRC32C of that table.
pub fn table_len(stored_len: usize, ss: usize) -> usize {
    4 * n_symbols(stored_len, ss) + 4
}
/// Data payload: `[table][padded data][table]`. The table is stored twice, on both sides
/// of the data, so one stretch of damage cannot take out both the data and its map.
pub fn data_payload_len(stored_len: usize, ss: usize) -> usize {
    padded_len(stored_len, ss) + 2 * table_len(stored_len, ss)
}

/// Build the trailing CRC table for a padded data payload.
pub fn symbol_crc_table(padded: &[u8], ss: usize) -> Vec<u8> {
    let n = padded.len() / ss;
    let mut t = Vec::with_capacity(4 * n + 4);
    for chunk in padded.chunks(ss) {
        t.extend_from_slice(&crc(chunk).to_le_bytes());
    }
    let c = crc(&t);
    t.extend_from_slice(&c.to_le_bytes());
    t
}

// ---------------------------------------------------------------- footer

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Footer {
    pub index_offset: u64,
    pub index_len: u32,
    pub index_hash: [u8; 16],
    pub uuid: [u8; 16],
    pub total_segments: u32,
}

impl Footer {
    pub fn encode(&self) -> [u8; FOOTER_LEN] {
        let mut b = [0u8; FOOTER_LEN];
        b[0..8].copy_from_slice(&FOOTER_MAGIC);
        b[8..16].copy_from_slice(&self.index_offset.to_le_bytes());
        b[16..20].copy_from_slice(&self.index_len.to_le_bytes());
        b[20..36].copy_from_slice(&self.index_hash);
        b[36..52].copy_from_slice(&self.uuid);
        b[52..56].copy_from_slice(&self.total_segments.to_le_bytes());
        let c = crc(&b[..60]);
        b[60..64].copy_from_slice(&c.to_le_bytes());
        b
    }
    pub fn decode(b: &[u8]) -> Option<Footer> {
        if b.len() < FOOTER_LEN || b[0..8] != FOOTER_MAGIC || crc(&b[..60]) != u32_at(b, 60) {
            return None;
        }
        let mut index_hash = [0u8; 16];
        index_hash.copy_from_slice(&b[20..36]);
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[36..52]);
        Some(Footer {
            index_offset: u64_at(b, 8),
            index_len: u32_at(b, 16),
            index_hash,
            uuid,
            total_segments: u32_at(b, 52),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrip() {
        for len in [HEADER_LEN_NORMAL, HEADER_LEN_TINY] {
            let mut h = Header::new(len);
            h.uuid = [7; 16];
            h.kdf = Some(Kdf { salt: [1; 16], m_kib: 64, t_cost: 3, lanes: 1 });
            h.key_check = Some([9; 16]);
            let d = Header::decode(&h.encode()).unwrap();
            assert_eq!(d, h);
        }
    }

    #[test]
    fn header_detects_flip() {
        let mut b = Header::new(HEADER_LEN_TINY).encode();
        b[100] ^= 1;
        assert!(Header::decode(&b).is_err());
    }

    #[test]
    fn segment_and_footer_roundtrip() {
        let s = SegHeader {
            kind: 0,
            codec: 1,
            flags: 4,
            stored_len: 99,
            raw_len: 200,
            owner: 3,
            seq: 42,
            hash: [5; 16],
            set_id: 2,
            stripe: 7,
        };
        assert_eq!(SegHeader::decode(&s.encode()).unwrap(), s);
        let f = Footer { index_offset: 123, index_len: 45, index_hash: [1; 16], uuid: [2; 16], total_segments: 9 };
        assert_eq!(Footer::decode(&f.encode()).unwrap(), f);
    }
}
