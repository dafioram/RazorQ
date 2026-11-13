//! Split volumes.
//!
//! A split archive is the ordinary single-file archive, cut into volumes. Reading goes through
//! [`VolumeSet`], which presents the volumes as one address space, so open, check, repair and
//! extract work unchanged. A missing or damaged volume is just a stretch of erasures that the
//! erasure code fills in, because recovery data is striped across the whole archive.
//!
//! Each volume starts with a small header (volume number, layout, and a copy of the archive
//! header), so losing the first volume does not lose the archive header either.
//!
//! Layout rules, chosen so any lost volume's size can be derived from its neighbours:
//! every volume holds `std_len` payload bytes except one *short* volume where the data region
//! ends and the recovery region begins, and the last volume. That keeps the tail volumes free of
//! data blocks: losing them costs only recovery data, which can be regenerated.

use crate::archive::Patch;
use crate::error::{Error, Result};
use crate::format::{crc, Header};
use crate::storage::{read_vec, ReadAt};
use std::collections::BTreeMap;
use std::io;

pub const VOL_MAGIC: [u8; 8] = [0x89, b'R', b'Q', b'V', 0x0D, 0x0A, 0x1A, 0x0A];
pub const VOL_FIXED: usize = 80;
pub const NO_CUT: u32 = u32::MAX;
const MAX_VOLUMES: u32 = 100_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VolHeader {
    pub uuid: [u8; 16],
    pub index: u32,
    pub count: u32,
    pub std_len: u64,
    pub cut_index: u32,
    pub cut_len: u64,
    pub payload_len: u64,
    pub total_len: u64,
    /// Copy of the archive header (self-checking).
    pub arch_header: Vec<u8>,
}

impl VolHeader {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = vec![0u8; VOL_FIXED];
        b[0..8].copy_from_slice(&VOL_MAGIC);
        b[8..24].copy_from_slice(&self.uuid);
        b[24..28].copy_from_slice(&self.index.to_le_bytes());
        b[28..32].copy_from_slice(&self.count.to_le_bytes());
        b[32..40].copy_from_slice(&self.std_len.to_le_bytes());
        b[40..44].copy_from_slice(&self.cut_index.to_le_bytes());
        b[48..56].copy_from_slice(&self.cut_len.to_le_bytes());
        b[56..64].copy_from_slice(&self.payload_len.to_le_bytes());
        b[64..68].copy_from_slice(&(self.arch_header.len() as u32).to_le_bytes());
        let total = self.total_len.to_le_bytes();
        b[44..48].copy_from_slice(&total[..4]);
        b[68..72].copy_from_slice(&total[4..]);
        let c = crc(&b[..72]);
        b[72..76].copy_from_slice(&c.to_le_bytes());
        b.extend_from_slice(&self.arch_header);
        b
    }

    /// Decode the fixed part; returns the header with an empty `arch_header` and the copy length.
    pub fn decode_fixed(b: &[u8]) -> Option<(VolHeader, usize)> {
        if b.len() < VOL_FIXED
            || b[0..8] != VOL_MAGIC
            || crc(&b[..72]) != u32::from_le_bytes(b[72..76].try_into().ok()?)
        {
            return None;
        }
        let u32_at = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        let u64_at = |o: usize| u64::from_le_bytes(b[o..o + 8].try_into().unwrap());
        let copy_len = u32_at(64) as usize;
        if copy_len > 65536 {
            return None;
        }
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&b[8..24]);
        Some((
            VolHeader {
                uuid,
                index: u32_at(24),
                count: u32_at(28),
                std_len: u64_at(32),
                cut_index: u32_at(40),
                cut_len: u64_at(48),
                payload_len: u64_at(56),
                total_len: u64::from(u32_at(44)) | (u64::from(u32_at(68)) << 32),
                arch_header: Vec::new(),
            },
            copy_len,
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub std_len: u64,
    pub cut_index: u32,
    pub cut_len: u64,
    pub count: u32,
}

impl Layout {
    /// Payload capacity of volume `i`.
    pub fn cap(&self, i: u32) -> u64 {
        if i == self.cut_index {
            self.cut_len
        } else {
            self.std_len
        }
    }
    /// Logical offset where volume `i` starts.
    pub fn start(&self, i: u32) -> u64 {
        if self.cut_index == NO_CUT || i <= self.cut_index {
            i as u64 * self.std_len
        } else {
            self.cut_index as u64 * self.std_len + self.cut_len + (i - self.cut_index - 1) as u64 * self.std_len
        }
    }
    /// Which volume a logical offset falls in, and the offset inside that volume's payload.
    pub fn locate(&self, off: u64) -> (u32, u64) {
        if self.cut_index == NO_CUT {
            return ((off / self.std_len) as u32, off % self.std_len);
        }
        let boundary = self.cut_index as u64 * self.std_len + self.cut_len;
        if off < boundary {
            ((off / self.std_len) as u32, off % self.std_len)
        } else {
            let rel = off - boundary;
            (self.cut_index + 1 + (rel / self.std_len) as u32, rel % self.std_len)
        }
    }
}

/// What to do to one volume file to repair a set.
#[derive(Clone, Debug)]
pub struct VolumeRewrite {
    pub index: u32,
    /// The volume is missing and must be created.
    pub create: bool,
    /// New volume header, when it must be (re)written.
    pub header: Option<Vec<u8>>,
    pub payload_len: u64,
    /// Patches at *file* offsets within this volume.
    pub patches: Vec<Patch>,
}

pub struct VolumeSet {
    parts: Vec<Option<Box<dyn ReadAt>>>,
    pub layout: Layout,
    pub vh_len: u64,
    payload: Vec<u64>,
    arch_header: Vec<u8>,
    pub uuid: [u8; 16],
    /// For each volume, which input part supplied it.
    pub supplied: Vec<Option<usize>>,
    notes: Vec<String>,
    total_len: u64,
    short: bool,
}

impl VolumeSet {
    /// Build a set from volume files in any order. Files without a readable volume header are
    /// ignored (and reported); volumes that are absent show up as missing.
    pub fn from_parts(parts: Vec<Box<dyn ReadAt>>) -> Result<VolumeSet> {
        let mut found: Vec<(VolHeader, usize, Box<dyn ReadAt>)> = Vec::new();
        let mut notes = Vec::new();
        for (pos, part) in parts.into_iter().enumerate() {
            let parsed = (|| -> Option<VolHeader> {
                let fixed = read_vec(&part, 0, VOL_FIXED).ok()?;
                let (mut h, copy_len) = VolHeader::decode_fixed(&fixed)?;
                h.arch_header = read_vec(&part, VOL_FIXED as u64, copy_len).ok()?;
                let archive = Header::decode(&h.arch_header).ok()?;
                if archive.uuid != h.uuid
                    || h.count == 0
                    || h.count > MAX_VOLUMES
                    || h.index >= h.count
                    || h.std_len == 0
                    || h.std_len.checked_mul(u64::from(h.count)).is_none()
                    || h.std_len > u64::MAX - (VOL_FIXED + h.arch_header.len()) as u64
                    || (h.cut_index != NO_CUT && (h.cut_index >= h.count || h.cut_len == 0 || h.cut_len >= h.std_len))
                {
                    return None;
                }
                let l = Layout { std_len: h.std_len, cut_index: h.cut_index, cut_len: h.cut_len, count: h.count };
                if h.payload_len > l.cap(h.index)
                    || (h.index + 1 != h.count && h.payload_len != l.cap(h.index))
                    || (h.total_len != 0
                        && (h.total_len < l.start(h.count - 1)
                            || h.total_len > l.start(h.count)
                            || (h.index + 1 == h.count && h.total_len != l.start(h.index) + h.payload_len)))
                {
                    return None;
                }
                Some(h)
            })();
            match parsed {
                Some(h) => found.push((h, pos, part)),
                None => notes.push(format!("file #{} has no readable volume header and was ignored", pos + 1)),
            }
        }
        let Some(first) = found.first().map(|f| f.0.clone()) else { return Err(Error::NotArchive) };
        if found.iter().any(|f| f.0.uuid != first.uuid) {
            return Err(Error::Other("these volumes belong to different archives".into()));
        }
        if found.iter().any(|(h, _, _)| {
            h.count != first.count
                || h.std_len != first.std_len
                || h.cut_index != first.cut_index
                || h.cut_len != first.cut_len
                || h.total_len != first.total_len
                || h.arch_header != first.arch_header
        }) {
            return Err(Error::Corrupt("volume headers disagree about archive layout".into()));
        }
        let count = first.count;
        let layout = Layout { std_len: first.std_len, cut_index: first.cut_index, cut_len: first.cut_len, count };
        let mut short = false;
        let mut slots: Vec<Option<Box<dyn ReadAt>>> = (0..count).map(|_| None).collect();
        let mut payload = vec![0u64; count as usize];
        let mut supplied = vec![None; count as usize];
        for (h, pos, part) in found {
            let i = h.index as usize;
            if slots[i].is_some() {
                notes.push(format!("volume {} appears twice; using the first copy", h.index + 1));
                continue;
            }
            if part.len()? < (VOL_FIXED + h.arch_header.len()) as u64 + h.payload_len {
                notes.push(format!("volume {} of {} is truncated", h.index + 1, count));
                short = true;
            }
            payload[i] = h.payload_len;
            supplied[i] = Some(pos);
            slots[i] = Some(part);
        }
        for (i, s) in slots.iter().enumerate() {
            if s.is_none() {
                notes.push(format!("volume {} of {} is missing", i + 1, count));
            }
        }
        Ok(VolumeSet {
            parts: slots,
            layout,
            vh_len: (VOL_FIXED + first.arch_header.len()) as u64,
            payload,
            arch_header: first.arch_header,
            uuid: first.uuid,
            supplied,
            notes,
            total_len: first.total_len,
            short,
        })
    }

    /// Convenience for in-memory volumes (the browser build and tests).
    pub fn from_bytes(volumes: Vec<Vec<u8>>) -> Result<VolumeSet> {
        VolumeSet::from_parts(volumes.into_iter().map(|v| Box::new(v) as Box<dyn ReadAt>).collect())
    }

    pub fn count(&self) -> u32 {
        self.layout.count
    }

    pub fn missing(&self) -> Vec<u32> {
        (0..self.layout.count).filter(|&i| self.parts[i as usize].is_none()).collect()
    }

    /// Map logical repair patches onto volume files; recreate missing volumes.
    pub fn plan_volume_patches(&self, patches: &[Patch]) -> Vec<VolumeRewrite> {
        let l = self.layout;
        let mut per: BTreeMap<u32, Vec<Patch>> = BTreeMap::new();
        let mut extent: BTreeMap<u32, u64> = BTreeMap::new();
        // A recreated first volume must get the archive header (stored twice) written back, because
        // reads were being served from the copy in the other volumes' headers.
        let mut all: Vec<Patch> = patches.to_vec();
        if self.parts.first().map(|p| p.is_none()).unwrap_or(false) {
            all.push(Patch { offset: 0, data: [self.arch_header.clone(), self.arch_header.clone()].concat() });
        }
        for p in &all {
            let (mut off, mut data) = (p.offset, &p.data[..]);
            while !data.is_empty() {
                let (i, io) = l.locate(off);
                let n = (data.len() as u64).min(l.cap(i) - io) as usize;
                per.entry(i).or_default().push(Patch { offset: self.vh_len + io, data: data[..n].to_vec() });
                let e = extent.entry(i).or_insert(0);
                *e = (*e).max(io + n as u64);
                off += n as u64;
                data = &data[n..];
            }
        }
        let new_count = l.count.max(per.keys().max().map(|m| m + 1).unwrap_or(0));
        let new_len = patches.iter().map(|p| p.offset + p.data.len() as u64).max().unwrap_or(0).max(self.total_len);
        // Legacy sets have no declared total length. Keep that encoding until a new tail is written.
        let new_len = if new_count == l.count && self.total_len == 0 { 0 } else { new_len };

        let mut out = Vec::new();
        for i in 0..new_count {
            let present = i < l.count && self.parts[i as usize].is_some();
            let patches = per.remove(&i).unwrap_or_default();
            let declared = if present { self.payload[i as usize] } else { 0 };
            let ext = extent.get(&i).copied().unwrap_or(0);
            let payload = if i + 1 == new_count && new_len != 0 {
                new_len - l.start(i)
            } else if present {
                declared.max(ext)
            } else if i == new_count - 1 {
                ext
            } else {
                l.cap(i)
            };
            let header_changed = !present || payload != declared || new_count != l.count || new_len != self.total_len;
            let short = present
                && self.parts[i as usize]
                    .as_ref()
                    .and_then(|p| p.len().ok())
                    .is_some_and(|len| len < self.vh_len + payload);
            if present && patches.is_empty() && !header_changed && !short {
                continue;
            }
            let header = header_changed.then(|| {
                VolHeader {
                    uuid: self.uuid,
                    index: i,
                    count: new_count,
                    std_len: l.std_len,
                    cut_index: l.cut_index,
                    cut_len: l.cut_len,
                    payload_len: payload,
                    total_len: new_len,
                    arch_header: self.arch_header.clone(),
                }
                .encode()
            });
            out.push(VolumeRewrite { index: i, create: !present, header, payload_len: payload, patches });
        }
        out
    }
}

impl ReadAt for VolumeSet {
    fn read_exact_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        let hl = self.arch_header.len() as u64;
        let mut done = 0usize;
        while done < buf.len() {
            let off = offset + done as u64;
            let (idx, io_off) = self.layout.locate(off);
            let n = ((buf.len() - done) as u64).min(self.layout.cap(idx) - io_off) as usize;
            match self.parts.get(idx as usize) {
                Some(Some(p)) => {
                    if io_off + n as u64 > self.payload[idx as usize] {
                        return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "read past the end of a volume"));
                    }
                    p.read_exact_at(&mut buf[done..done + n], self.vh_len + io_off)?;
                }
                // Volume 1 gone: the archive header (stored twice at the very start) is
                // still available from the copy every other volume carries.
                Some(None) if idx == 0 && hl > 0 && off + n as u64 <= 2 * hl => {
                    for k in 0..n {
                        buf[done + k] = self.arch_header[((off + k as u64) % hl) as usize];
                    }
                }
                _ => return Err(io::Error::new(io::ErrorKind::NotFound, format!("volume {} is missing", idx + 1))),
            }
            done += n;
        }
        Ok(())
    }

    fn len(&self) -> io::Result<u64> {
        if self.total_len != 0 {
            return Ok(self.total_len);
        }
        let h = (0..self.layout.count).rev().find(|&i| self.parts[i as usize].is_some());
        match h {
            Some(h) => Ok(self.layout.start(h) + self.payload[h as usize]),
            None => Ok(0),
        }
    }

    fn notes(&self) -> Vec<String> {
        self.notes.clone()
    }

    fn is_incomplete(&self) -> bool {
        self.short || self.parts.iter().any(|p| p.is_none())
    }
}

/// Cut an existing single-file archive image into volumes of about `volume_size` bytes, using the
/// same layout rules as the volume writer (the recovery region starts a fresh volume). The recovery
/// data was sized for the original archive, so check `info` before relying on it to survive a lost
/// volume. Used by the browser demo and tests; the CLI splits while packing instead.
pub fn split_archive_bytes(archive: &[u8], volume_size: u64) -> Result<Vec<Vec<u8>>> {
    let a = crate::archive::Archive::open(archive.to_vec(), None)?;
    let header = a.header.encode();
    let vh_len = (VOL_FIXED + header.len()) as u64;
    if volume_size < vh_len + 1024 {
        return Err(Error::Other("volume size is too small".into()));
    }
    let std_len = volume_size - vh_len;
    let total = archive.len() as u64;
    let mut layout = Layout { std_len, cut_index: NO_CUT, cut_len: 0, count: 0 };
    if let Some(first) = a.index.regions.iter().map(|r| r.offset).min() {
        let (idx, off) = layout.locate(first);
        if off != 0 {
            layout.cut_index = idx;
            layout.cut_len = off;
        }
    }
    let (li, lo) = layout.locate(total);
    layout.count = if lo == 0 { li } else { li + 1 }.max(1);
    let mut out = Vec::new();
    for i in 0..layout.count {
        let start = layout.start(i);
        let end = if i + 1 == layout.count { total } else { start + layout.cap(i) };
        let h = VolHeader {
            uuid: a.header.uuid,
            index: i,
            count: layout.count,
            std_len,
            cut_index: layout.cut_index,
            cut_len: layout.cut_len,
            payload_len: end - start,
            total_len: total,
            arch_header: header.clone(),
        };
        let mut v = h.encode();
        v.extend_from_slice(&archive[start as usize..end as usize]);
        out.push(v);
    }
    Ok(out)
}

// ---------------------------------------------------------------- writing

#[cfg(feature = "fs")]
pub use writer_impl::{volume_file_name, VolumeWriter};

#[cfg(feature = "fs")]
mod writer_impl {
    use super::*;
    use crate::writer::ArchiveSink;
    use std::collections::HashMap;
    use std::fs::{File, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::{Path, PathBuf};

    /// Presents a numbered series of volume files as one seekable, writable address space.
    pub struct VolumeWriter {
        dir: PathBuf,
        base: String,
        target_len: u64,
        arch_header: Vec<u8>,
        uuid: [u8; 16],
        vh_len: u64,
        std_len: u64,
        cut: Option<(u32, u64)>,
        files: HashMap<u32, File>,
        written: HashMap<u32, u64>,
        pos: u64,
        end: u64,
    }

    pub fn volume_file_name(base: &str, index: u32) -> String {
        format!("{base}.{:03}", index + 1)
    }

    impl VolumeWriter {
        /// Volumes are named `<base>.001`, `<base>.002`, … inside `dir`, each about `volume_size` bytes.
        pub fn new(dir: &Path, base: &str, volume_size: u64) -> VolumeWriter {
            VolumeWriter {
                dir: dir.to_path_buf(),
                base: base.to_string(),
                target_len: volume_size,
                arch_header: Vec::new(),
                uuid: [0; 16],
                vh_len: 0,
                std_len: 0,
                cut: None,
                files: HashMap::new(),
                written: HashMap::new(),
                pos: 0,
                end: 0,
            }
        }

        pub fn volume_path(&self, i: u32) -> PathBuf {
            self.dir.join(volume_file_name(&self.base, i))
        }

        fn layout(&self, count: u32) -> Layout {
            let (cut_index, cut_len) = self.cut.unwrap_or((NO_CUT, 0));
            Layout { std_len: self.std_len, cut_index, cut_len, count }
        }

        fn file(&mut self, i: u32) -> io::Result<&mut File> {
            if i >= MAX_VOLUMES {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many volumes"));
            }
            if !self.files.contains_key(&i) {
                if self.files.len() >= 48 {
                    let victim = *self.files.keys().find(|&&k| k != i).unwrap();
                    self.files.remove(&victim);
                }
                let path = self.volume_path(i);
                let existed = path.exists();
                let mut f = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(&path)?;
                if !existed {
                    let h = VolHeader {
                        uuid: self.uuid,
                        index: i,
                        count: 0,
                        std_len: self.std_len,
                        cut_index: NO_CUT,
                        cut_len: 0,
                        payload_len: 0,
                        total_len: 0,
                        arch_header: self.arch_header.clone(),
                    };
                    f.write_all(&h.encode())?;
                }
                self.files.insert(i, f);
            }
            Ok(self.files.get_mut(&i).unwrap())
        }

        /// Write the final volume headers (count, layout, lengths). Returns the volume paths.
        pub fn finalize(mut self) -> io::Result<(Vec<PathBuf>, Layout)> {
            let (last_idx, last_off) = self.layout(0).locate(self.end);
            let count = if last_off == 0 && self.end > 0 { last_idx } else { last_idx + 1 }.max(1);
            if count > MAX_VOLUMES {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many volumes"));
            }
            let layout = self.layout(count);
            let mut paths = Vec::new();
            for i in 0..count {
                let payload = if i + 1 == count { self.end - layout.start(i) } else { layout.cap(i) };
                let h = VolHeader {
                    uuid: self.uuid,
                    index: i,
                    count,
                    std_len: layout.std_len,
                    cut_index: layout.cut_index,
                    cut_len: layout.cut_len,
                    payload_len: payload,
                    total_len: self.end,
                    arch_header: self.arch_header.clone(),
                };
                let vh = self.vh_len;
                let f = self.file(i)?;
                f.seek(SeekFrom::Start(0))?;
                f.write_all(&h.encode())?;
                f.set_len(vh + payload)?;
                f.sync_all()?;
                paths.push(self.volume_path(i));
            }
            Ok((paths, layout))
        }
    }

    impl ArchiveSink for VolumeWriter {
        fn note_header(&mut self, header: &[u8]) -> io::Result<()> {
            let h = Header::decode(header).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
            self.uuid = h.uuid;
            self.arch_header = header.to_vec();
            self.vh_len = (VOL_FIXED + header.len()) as u64;
            if self.target_len < self.vh_len + 64 * 1024 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "volume size is too small (minimum is about 70 KiB)",
                ));
            }
            self.std_len = self.target_len - self.vh_len;
            Ok(())
        }

        fn index_copy_boundary(&self, pos: u64) -> u64 {
            let l = self.layout(0);
            let (part, offset) = l.locate(pos);
            let gap = l.cap(part) - offset;
            if offset != 0 && gap <= 1 << 20 {
                pos + gap
            } else {
                pos
            }
        }

        fn cut_here(&mut self, pos: u64) -> io::Result<()> {
            if self.cut.is_none() {
                let (idx, off) = self.layout(0).locate(pos);
                if off != 0 {
                    self.cut = Some((idx, off));
                }
            }
            Ok(())
        }
    }

    impl Write for VolumeWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            let (idx, off) = self.layout(0).locate(self.pos);
            let n = (buf.len() as u64).min(self.layout(0).cap(idx) - off) as usize;
            let vh = self.vh_len;
            let f = self.file(idx)?;
            f.seek(SeekFrom::Start(vh + off))?;
            f.write_all(&buf[..n])?;
            let e = self.written.entry(idx).or_insert(0);
            *e = (*e).max(off + n as u64);
            self.pos += n as u64;
            self.end = self.end.max(self.pos);
            Ok(n)
        }
        fn flush(&mut self) -> io::Result<()> {
            for f in self.files.values_mut() {
                f.flush()?;
            }
            Ok(())
        }
    }

    impl Read for VolumeWriter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() || self.pos >= self.end {
                return Ok(0);
            }
            let (idx, off) = self.layout(0).locate(self.pos);
            let n = (buf.len() as u64).min(self.layout(0).cap(idx) - off).min(self.end - self.pos) as usize;
            let vh = self.vh_len;
            let f = self.file(idx)?;
            f.seek(SeekFrom::Start(vh + off))?;
            let got = f.read(&mut buf[..n])?;
            if got == 0 {
                buf[..n].fill(0);
                self.pos += n as u64;
                return Ok(n);
            }
            self.pos += got as u64;
            Ok(got)
        }
    }

    impl Seek for VolumeWriter {
        fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
            let np = match from {
                SeekFrom::Start(n) => n as i128,
                SeekFrom::Current(d) => self.pos as i128 + d as i128,
                SeekFrom::End(d) => self.end as i128 + d as i128,
            };
            if np < 0 {
                return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek before start"));
            }
            self.pos = np as u64;
            Ok(self.pos)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_maps_offsets() {
        let l = Layout { std_len: 100, cut_index: 2, cut_len: 40, count: 6 };
        assert_eq!(l.locate(0), (0, 0));
        assert_eq!(l.locate(239), (2, 39)); // last byte of the short volume (starts at 200, holds 40)
        assert_eq!(l.locate(250), (3, 10));
        assert_eq!(l.start(3), 240);
        assert_eq!(l.locate(240), (3, 0));
        assert_eq!(l.locate(339), (3, 99));
        assert_eq!(l.locate(340), (4, 0));
        assert_eq!(l.start(4), 340);
        assert_eq!(l.cap(2), 40);
    }

    #[test]
    fn split_bytes_matches_the_original_image() {
        use crate::progress::Quiet;
        use crate::writer::{ArchiveWriter, PackOptions};
        let mut o = PackOptions::default();
        o.block_size = 8192;
        o.symbol_size = Some(512);
        o.target_k = 128;
        let mut w = ArchiveWriter::create(std::io::Cursor::new(Vec::new()), o, &Quiet).unwrap();
        let mut x = 0x2545F4914F6CDD1Du64;
        let noise: Vec<u8> = (0..300_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        w.add_bytes("a.bin", 0o644, 0, &noise).unwrap();
        let image = w.finish().unwrap().0.into_inner();
        let vols = split_archive_bytes(&image, 60_000).unwrap();
        assert!(vols.len() >= 5);
        let set = VolumeSet::from_bytes(vols).unwrap();
        assert_eq!(set.len().unwrap(), image.len() as u64);
        let mut back = vec![0u8; image.len()];
        set.read_exact_at(&mut back, 0).unwrap();
        assert_eq!(back, image, "reading through the volume set reproduces the archive byte for byte");
    }

    #[test]
    fn volume_header_roundtrip() {
        let h = VolHeader {
            uuid: [4; 16],
            index: 3,
            count: 9,
            std_len: 1000,
            cut_index: NO_CUT,
            cut_len: 0,
            payload_len: 900,
            total_len: 0,
            arch_header: vec![7; 512],
        };
        let b = h.encode();
        let (mut d, n) = VolHeader::decode_fixed(&b).unwrap();
        d.arch_header = b[VOL_FIXED..VOL_FIXED + n].to_vec();
        assert_eq!(d, h);
    }
}
