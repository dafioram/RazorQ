//! Independently checksummed RaptorQ symbols for the final compressed index.
use crate::format::{hash128, kind, SegHeader, SEG_HEADER_LEN};
use crate::index::MAX_INDEX;
use crate::storage::{read_vec, ReadAt};
use crate::Error;
use rqz_ecc as ecc;
use std::collections::BTreeMap;

const SYMBOL: usize = 4096;
const GROUP: usize = 64;
pub(crate) const PAYLOAD_LEN: usize = SYMBOL + 16;

pub(crate) fn encode(
    bytes: &[u8],
    generation: u64,
    mut write: impl FnMut(&SegHeader, &[u8]) -> crate::Result<()>,
) -> crate::Result<()> {
    if bytes.is_empty() || bytes.len() > MAX_INDEX {
        return Err(Error::Other("compressed index exceeds catalog limits".into()));
    }
    let digest = hash128(bytes);
    let mut payload = vec![0; PAYLOAD_LEN];
    payload[..16].copy_from_slice(&digest);
    for (group, data) in bytes.chunks(GROUP * SYMBOL).enumerate() {
        let mut padded = data.to_vec();
        padded.resize(data.len().div_ceil(SYMBOL) * SYMBOL, 0);
        let k = padded.len() / SYMBOL;
        let repairs = ecc::encode_repair(&padded, SYMBOL as u16, 0, ecc::repair_count(k as u32, 0.25, 4));
        let mut emit = |esi, symbol: &[u8], repair| {
            payload[16..].copy_from_slice(symbol);
            let h = SegHeader {
                kind: kind::CATALOG,
                codec: 0,
                flags: u16::from(repair),
                stored_len: PAYLOAD_LEN as u32,
                raw_len: bytes.len() as u32,
                owner: esi,
                seq: generation,
                hash: hash128(&payload),
                set_id: group as u16,
                stripe: k as u16,
            };
            write(&h, &payload)
        };
        for (i, symbol) in padded.as_chunks::<SYMBOL>().0.iter().enumerate() {
            emit(i as u32, symbol, false)?;
        }
        for repair in repairs {
            emit(repair.esi, &repair.data, true)?;
        }
    }
    Ok(())
}

/// A committed catalog sits immediately before the full index mirror.
pub(crate) fn verify<S: ReadAt>(src: &S, mirror: u64, len: usize, generation: u64, digest: [u8; 16]) -> bool {
    let symbols = len.div_ceil(SYMBOL);
    let groups = (0..symbols)
        .step_by(GROUP)
        .map(|i| {
            let k = (symbols - i).min(GROUP);
            (k, ecc::repair_count(k as u32, 0.25, 4) as usize)
        })
        .collect::<Vec<_>>();
    let segment = SEG_HEADER_LEN + PAYLOAD_LEN;
    let size: usize = groups.iter().map(|(k, r)| (k + r) * segment).sum();
    let Some(mut offset) = mirror.checked_sub(size as u64) else { return false };
    for (group, (k, repairs)) in groups.into_iter().enumerate() {
        let mut seen = std::collections::HashSet::new();
        for i in 0..k + repairs {
            let Ok(bytes) = read_vec(src, offset, segment) else { return false };
            let Some(h) = SegHeader::decode(&bytes) else { return false };
            let payload = &bytes[SEG_HEADER_LEN..];
            if h.kind != kind::CATALOG
                || h.seq != generation
                || h.set_id as usize != group
                || h.stripe as usize != k
                || h.stored_len as usize != PAYLOAD_LEN
                || h.raw_len as usize != len
                || payload[..16] != digest
                || hash128(payload) != h.hash
                || !seen.insert(h.owner)
                || (i < k && (h.flags != 0 || h.owner as usize != i))
                || (i >= k && (h.flags != 1 || !(k as u32..=128).contains(&h.owner)))
            {
                return false;
            }
            offset += segment as u64;
        }
    }
    true
}

#[derive(Default)]
pub(crate) struct Catalog {
    identity: Option<(usize, [u8; 16])>,
    groups: BTreeMap<u16, BTreeMap<(bool, u32), Vec<u8>>>,
}

impl Catalog {
    pub(crate) fn push(&mut self, header: &SegHeader, payload: &[u8]) {
        if payload.len() != PAYLOAD_LEN || hash128(payload) != header.hash {
            return;
        }
        let len = header.raw_len as usize;
        let offset = usize::from(header.set_id) * GROUP * SYMBOL;
        if len > MAX_INDEX || offset >= len {
            return;
        }
        let k = (len - offset).min(GROUP * SYMBOL).div_ceil(SYMBOL);
        let repair = match header.flags {
            0 if (header.owner as usize) < k => false,
            1 if (k as u32..=128).contains(&header.owner) => true,
            _ => return,
        };
        if header.stripe as usize != k {
            return;
        }
        let identity = (len, payload[..16].try_into().unwrap());
        if *self.identity.get_or_insert(identity) != identity {
            return;
        }
        let group = self.groups.entry(header.set_id).or_default();
        if !repair || group.keys().filter(|(repair, _)| *repair).count() < ecc::repair_count(k as u32, 0.25, 4) as usize
        {
            group.entry((repair, header.owner)).or_insert_with(|| payload[16..].to_vec());
        }
    }

    pub(crate) fn decode(self) -> Option<Vec<u8>> {
        let (len, digest) = self.identity?;
        let mut out = Vec::with_capacity(len);
        for group in 0..len.div_ceil(GROUP * SYMBOL) {
            let k = (len - out.len()).min(GROUP * SYMBOL).div_ceil(SYMBOL);
            let (present, repair): (Vec<_>, Vec<_>) =
                self.groups.get(&(group as u16))?.iter().partition(|((repair, _), _)| !repair);
            let present: Vec<_> = present.into_iter().map(|((_, id), data)| (*id, data.as_slice())).collect();
            let repair: Vec<_> = repair.into_iter().map(|((_, id), data)| (*id, data.as_slice())).collect();
            out.extend(ecc::decode(k, SYMBOL as u16, &present, &repair)?);
        }
        out.truncate(len);
        (hash128(&out) == digest).then_some(out)
    }
}
