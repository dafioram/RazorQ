//! Compression. The codec id lives in every block header, so defaults can change
//! later without breaking old archives, and codecs can be mixed within one archive.

use crate::error::{Error, Result};

pub const STORE: u8 = 0;
pub const ZSTD: u8 = 1;
pub const LZ4: u8 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    /// Store blocks as-is (ECC-only archives).
    None,
    /// LZ4: near disk speed, for backups.
    Fast,
    /// zstd level 6: the default.
    Normal,
    /// zstd level 19.
    Max,
    Zstd(i32),
}

impl Compression {
    pub fn parse(s: &str) -> Option<Compression> {
        match s {
            "none" | "store" => Some(Compression::None),
            "fast" | "lz4" => Some(Compression::Fast),
            "normal" => Some(Compression::Normal),
            "max" => Some(Compression::Max),
            _ => s.strip_prefix("zstd:")?.parse().ok().map(Compression::Zstd),
        }
    }
}

/// File types that are already compressed: store them raw instead of burning CPU.
pub fn looks_incompressible(path: &str) -> bool {
    let ext = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    matches!(
        ext.as_str(),
        "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "webp"
            | "heic"
            | "avif"
            | "mp3"
            | "aac"
            | "ogg"
            | "opus"
            | "flac"
            | "m4a"
            | "mp4"
            | "mkv"
            | "mov"
            | "webm"
            | "avi"
            | "zip"
            | "gz"
            | "bz2"
            | "xz"
            | "zst"
            | "7z"
            | "rar"
            | "br"
            | "lz4"
            | "jar"
            | "apk"
            | "docx"
            | "xlsx"
            | "pptx"
    )
}

/// Compress a block. Returns the codec actually used and the bytes; falls back
/// to `STORE` when compression does not help.
pub fn compress(c: Compression, raw: &[u8]) -> (u8, Vec<u8>) {
    let attempt: Option<(u8, Vec<u8>)> = match c {
        Compression::None => None,
        Compression::Fast => Some((LZ4, lz4_flex::block::compress(raw))),
        Compression::Normal => zstd_compress(raw, 6),
        Compression::Max => zstd_compress(raw, 19),
        Compression::Zstd(l) => zstd_compress(raw, l),
    };
    match attempt {
        Some((codec, out)) if out.len() + out.len() / 32 < raw.len() => (codec, out),
        _ => (STORE, raw.to_vec()),
    }
}

#[cfg(feature = "zstd-native")]
fn zstd_compress(raw: &[u8], level: i32) -> Option<(u8, Vec<u8>)> {
    zstd::bulk::compress(raw, level).ok().map(|v| (ZSTD, v))
}

#[cfg(not(feature = "zstd-native"))]
fn zstd_compress(raw: &[u8], _level: i32) -> Option<(u8, Vec<u8>)> {
    use ruzstd::encoding::{compress_to_vec, CompressionLevel};
    Some((ZSTD, compress_to_vec(raw, CompressionLevel::Fastest)))
}

pub fn decompress(codec: u8, stored: &[u8], raw_len: usize) -> Result<Vec<u8>> {
    let out = match codec {
        STORE => stored.to_vec(),
        LZ4 => lz4_flex::block::decompress(stored, raw_len).map_err(|e| Error::Corrupt(format!("lz4: {e}")))?,
        ZSTD => zstd_decompress(stored, raw_len)?,
        other => return Err(Error::Unsupported(format!("unknown codec id {other}"))),
    };
    if out.len() != raw_len {
        return Err(Error::Corrupt("decompressed length mismatch".into()));
    }
    Ok(out)
}

#[cfg(feature = "zstd-native")]
fn zstd_decompress(stored: &[u8], raw_len: usize) -> Result<Vec<u8>> {
    zstd::bulk::decompress(stored, raw_len).map_err(|e| Error::Corrupt(format!("zstd: {e}")))
}

#[cfg(not(feature = "zstd-native"))]
fn zstd_decompress(stored: &[u8], raw_len: usize) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut d = ruzstd::decoding::StreamingDecoder::new(stored).map_err(|e| Error::Corrupt(format!("zstd: {e}")))?;
    let mut out = Vec::with_capacity(raw_len);
    d.read_to_end(&mut out)?;
    Ok(out)
}
