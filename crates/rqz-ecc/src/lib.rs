//! Erasure coding for razerq.
//!
//! This crate knows nothing about files or archives. It deals in *groups*:
//! a run of `k` source symbols of `symbol_size` bytes each, plus any number of
//! repair symbols. Damage is always treated as erasures (the caller knows which
//! symbols are bad from checksums), so decoding only has to fill known gaps.

use raptorq::{EncodingPacket, ObjectTransmissionInformation, PayloadId, SourceBlockDecoder, SourceBlockEncoder};

/// RaptorQ supports at most 56,403 source symbols per source block.
pub const MAX_K: u32 = 56_403;
const ALIGN: u8 = 8;

/// A repair symbol: its encoding symbol id (as produced by RaptorQ) and bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Repair {
    pub esi: u32,
    pub data: Vec<u8>,
}

fn config(k: usize, symbol_size: u16) -> ObjectTransmissionInformation {
    assert!(symbol_size as usize % ALIGN as usize == 0, "symbol size must be a multiple of 8");
    assert!(k >= 1 && k as u32 <= MAX_K, "group size out of range");
    ObjectTransmissionInformation::new((k * symbol_size as usize) as u64, symbol_size, 1, 1, ALIGN)
}

/// Number of groups needed to keep each at roughly `target_k` symbols.
pub fn group_count(total_symbols: u64, target_k: u32) -> u32 {
    let t = target_k.clamp(1, MAX_K) as u64;
    total_symbols.div_ceil(t).max(1) as u32
}

/// Striping: block `i` of an ECC set goes to group `i % g`, at position `i / g`.
/// Neighbouring blocks land in different groups, so a dead stretch of disk costs
/// every group a little instead of killing a few groups outright.
pub fn stripe(block_in_set: u32, groups: u32) -> (u32, u32) {
    (block_in_set % groups, block_in_set / groups)
}

/// Repair symbols to generate for a group of `k` symbols at `ratio` (0.10 = 10%).
pub fn repair_count(k: u32, ratio: f64, min_repair: u32) -> u32 {
    if ratio <= 0.0 {
        return 0;
    }
    (((k as f64) * ratio).ceil() as u32).max(min_repair)
}

fn pad_to_symbols(data: &[u8], symbol_size: usize) -> std::borrow::Cow<'_, [u8]> {
    if data.len() % symbol_size == 0 {
        std::borrow::Cow::Borrowed(data)
    } else {
        let mut v = data.to_vec();
        v.resize(data.len().div_ceil(symbol_size) * symbol_size, 0);
        std::borrow::Cow::Owned(v)
    }
}

/// Generate `count` repair symbols starting at repair index `start`.
/// `source` is the concatenation of all `k` source symbols.
pub fn encode_repair(source: &[u8], symbol_size: u16, start: u32, count: u32) -> Vec<Repair> {
    let ss = symbol_size as usize;
    let src = pad_to_symbols(source, ss);
    let k = src.len() / ss;
    let enc = SourceBlockEncoder::new(0, &config(k, symbol_size), &src);
    enc.repair_packets(start, count)
        .into_iter()
        .map(|p| Repair { esi: p.payload_id().encoding_symbol_id(), data: p.data().to_vec() })
        .collect()
}

/// Regenerate specific repair symbols (identified by ESI), e.g. to heal damaged
/// recovery data after the group's sources have been restored.
pub fn regenerate_repair(source: &[u8], symbol_size: u16, esis: &[u32]) -> Vec<Repair> {
    if esis.is_empty() {
        return vec![];
    }
    let ss = symbol_size as usize;
    let src = pad_to_symbols(source, ss);
    let k = src.len() / ss;
    let enc = SourceBlockEncoder::new(0, &config(k, symbol_size), &src);
    let base = enc.repair_packets(0, 1)[0].payload_id().encoding_symbol_id();
    let lo = esis.iter().copied().min().unwrap().saturating_sub(base);
    let hi = esis.iter().copied().max().unwrap().saturating_sub(base);
    enc.repair_packets(lo, hi - lo + 1)
        .into_iter()
        .map(|p| Repair { esi: p.payload_id().encoding_symbol_id(), data: p.data().to_vec() })
        .filter(|r| esis.contains(&r.esi))
        .collect()
}

/// Recover all `k` source symbols (returned concatenated, `k * symbol_size` bytes).
///
/// * `present` – the source symbols that are intact, as `(index, bytes)`.
/// * `repairs` – intact repair symbols, as `(esi, bytes)`.
///
/// Returns `None` if there is not enough surviving information.
pub fn decode(k: usize, symbol_size: u16, present: &[(u32, &[u8])], repairs: &[(u32, &[u8])]) -> Option<Vec<u8>> {
    let ss = symbol_size as usize;
    if present.len() == k {
        let mut out = vec![0u8; k * ss];
        for (i, d) in present {
            out[*i as usize * ss..(*i as usize + 1) * ss].copy_from_slice(d);
        }
        return Some(out);
    }
    if present.len() + repairs.len() < k {
        return None;
    }
    let cfg = config(k, symbol_size);
    let mut dec = SourceBlockDecoder::new(0, &cfg, (k * ss) as u64);
    let packets =
        present.iter().chain(repairs.iter()).map(|(id, d)| EncodingPacket::new(PayloadId::new(0, *id), d.to_vec()));
    dec.decode(packets)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(k: usize, ss: usize) -> Vec<u8> {
        (0..k * ss).map(|i| (i.wrapping_mul(2654435761) >> 7) as u8).collect()
    }

    #[test]
    fn roundtrip_with_erasures() {
        let (k, ss) = (100usize, 64u16);
        let src = sample(k, ss as usize);
        let rep = encode_repair(&src, ss, 0, 12);
        let missing = [3usize, 4, 50, 51, 52, 99];
        let present: Vec<(u32, &[u8])> = (0..k)
            .filter(|i| !missing.contains(i))
            .map(|i| (i as u32, &src[i * ss as usize..(i + 1) * ss as usize]))
            .collect();
        let reps: Vec<(u32, &[u8])> = rep.iter().map(|r| (r.esi, r.data.as_slice())).collect();
        assert_eq!(decode(k, ss, &present, &reps).expect("decodes"), src);
    }

    #[test]
    fn too_many_erasures_fails() {
        let (k, ss) = (40usize, 32u16);
        let src = sample(k, ss as usize);
        let rep = encode_repair(&src, ss, 0, 2);
        let present: Vec<(u32, &[u8])> =
            (0..30).map(|i| (i as u32, &src[i * ss as usize..(i + 1) * ss as usize])).collect();
        let reps: Vec<(u32, &[u8])> = rep.iter().map(|r| (r.esi, r.data.as_slice())).collect();
        assert!(decode(k, ss, &present, &reps).is_none());
    }

    #[test]
    fn regenerate_matches_original() {
        let (k, ss) = (20usize, 32u16);
        let src = sample(k, ss as usize);
        let rep = encode_repair(&src, ss, 0, 8);
        let want = [rep[2].esi, rep[5].esi];
        let got = regenerate_repair(&src, ss, &want);
        assert_eq!(got.len(), 2);
        for g in got {
            assert_eq!(g, *rep.iter().find(|r| r.esi == g.esi).unwrap());
        }
    }

    #[test]
    fn striping_spreads_neighbours() {
        let groups: Vec<u32> = (0..16).map(|i| stripe(i, 8).0).collect();
        assert_eq!(&groups[..8], &[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(group_count(100_000, 15_000), 7);
    }

    #[test]
    fn tiny_group() {
        let ss = 16u16;
        let src = sample(3, ss as usize);
        let rep = encode_repair(&src, ss, 0, 4);
        let present: Vec<(u32, &[u8])> = vec![(0, &src[0..16])];
        let reps: Vec<(u32, &[u8])> = rep.iter().map(|r| (r.esi, r.data.as_slice())).collect();
        assert_eq!(decode(3, ss, &present, &reps).unwrap(), src);
    }
}
