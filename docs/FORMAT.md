# razerq container format, draft 0.1

This is the byte-level description of what `rqz-core` reads and writes. Format 0.x is **not frozen**:
expect changes until 1.0. The versioning rules below are what will keep 1.x archives readable.

Conventions: little-endian integers, absolute `u64` offsets, **CRC32C** for structure and localisation,
**BLAKE3 truncated to 128 bits** for payload integrity.

## 1. File layout

```
[Header A]            header_len bytes (4096 normal, 512 "tiny")
[Header B]            mirror of A
[Segment]*            data, recovery, meta, index, interleaved
[Footer A  64 B]
[Footer B  64 B]      mirror
```

`add` appends to a staged copy and updates both header copies to commit the new index generation.
Old indexes can aid salvage. The reader verifies the generation and inventory before treating an
index as complete.

## 2. Header

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `89 'R' 'Q' 'Z' 0D 0A 1A 0A` |
| 8 | 4 | `header_len` |
| 12 | 2 | `ver_major` (0 in this draft) |
| 14 | 2 | `ver_minor` |
| 16 | 2 | `min_reader`: lowest minor that can read this archive |
| 20 | 8 | `feat_required`: unknown bit, refuse to open |
| 28 | 8 | `feat_readonly`: unknown bit, extract/check only |
| 36 | 8 | `feat_optional`: ignore if unknown |
| 44 | 16 | archive UUID |
| 60 | 8 | created, unix seconds |
| 68 | 1 | `block_log2` (block size = 2^n, 12..=26) |
| 70 | 2 | `symbol_size` (multiple of 8; 4096 normal, 1024 tiny) |
| 72 | 4 | `target_k`: target source symbols per ECC group |
| 76 | … | TLV tail: `tag u16, len u16, bytes`; tag 0 ends it |
| last 4 | 4 | CRC32C of everything before it |

TLV tags: `1` writer string, `2` KDF (salt 16, m_kib u32, t u32, lanes u32), `3` key check (16 B),
`4` committed generation (u64), `5` committed inventory (16-byte block table hash followed by
16-byte file table hash). The hashes cover the fixed-integer bincode table encodings. The encrypted
file table uses keyed BLAKE3 with the domain string `rqz-file-inventory-v1` before the table bytes.

Required feature bits: `0` encrypted, `1` detached sidecar, `2` committed inventory and final index.
Optional bit `0` denotes the tiny profile.

If header A is damaged, the reader tries a mirror at offset 512 and then 4096.

## 3. Segments

Every segment starts with a 56-byte header. The fixed `sync` pattern lets a scanner re-find segment
boundaries after damage, and every segment is self-describing.

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | sync `D3 'R' 'Q' 'S' A5 5A C3 3C` |
| 8 | 1 | kind: 0 data · 1 recovery · 2 index · 3 dict (reserved) · 4 symbol-CRC table · 5 file metadata · 6 final index mirror · 7 protected catalog symbol |
| 9 | 1 | codec: 0 store · 1 zstd · 2 lz4 |
| 10 | 2 | flags: 1 encrypted · 2 dedup ref (reserved) · 4 has symbol CRCs · 8 random block nonce · 16 absolute logical block offset |
| 12 | 4 | `stored_len` |
| 16 | 4 | `raw_len` |
| 20 | 4 | `owner`: group id (recovery) |
| 24 | 8 | `seq`: block number (data) · ESI (recovery) |
| 32 | 16 | `payload_hash`: BLAKE3-128 of the **stored** bytes |
| 48 | 2 | `set_id` |
| 50 | 2 | `stripe`: group count of the set (recovery segments) |
| 52 | 4 | CRC32C of bytes 0..52 |

For data segments with flag 16, `owner` contains the low 32 bits of the logical block offset and
`stripe` the next 16 bits. This preserves the location of later files after a segment header is lost.

The payload hash covers stored bytes, i.e. *after* compression and encryption. That is why check and
repair work without the password and never see plaintext.

### Data segment payload

```
[CRC table][padded data][CRC table]
 table = crc32c per symbol (4 B each) + crc32c of the table
 padded data = stored bytes zero-padded to a symbol multiple
```

The table appears twice, on both sides of the data, so a single stretch of damage cannot erase both
the data and the map of where it is bad. A flipped bit then costs one symbol (4 KiB), not a block.
If both tables are unusable the whole block counts as erased.

### Recovery segment payload

Exactly one RaptorQ repair symbol (`symbol_size` bytes). `owner` is the group, `seq` the RaptorQ ESI.

### Metadata segment payload

`bincode(Vec<FileEntry>)`, sealed with XChaCha20-Poly1305 when encrypted. These make the stream
self-describing: a full scan can rebuild the file table even if every index copy is gone. The last
metadata segment is written *before* the recovery region, so an archive that lost its tail still
knows its file names.

## 4. Blocks, sets, groups and striping

* Files are concatenated into one logical stream and cut into independent blocks (default 2 MiB).
  Each file records `(stream_offset, size)`. Small files share blocks; there is no per-file padding.
* Each block is compressed (or stored) independently, optionally encrypted, hashed, then written.
* Blocks are grouped into **ECC sets** (default 1 GiB of stored data). A set is *striped*: block `i` of
  the set goes to group `i mod G`, with `G = ceil(total_symbols / target_k)`, capped at the block count.
  Neighbouring blocks land in different groups, so a dead stretch of disk costs every group a little
  instead of destroying a few groups outright.
* A group's source symbols are its member blocks' padded symbols, concatenated. The group is one
  RaptorQ source block (K ≤ 56,403).
* Repair symbols are written **round-robin** after the set: segment `(group g, symbol j)` lives at
  `region.offset + (j * G + g) * (56 + symbol_size)`. A damaged stretch of the recovery region
  therefore costs each group about the same few symbols.
* Repair symbols are interchangeable, so `add-protection` simply appends another region with higher ESIs.
* Damage is treated as **erasures**: hashes and CRCs say which symbols are bad; RaptorQ fills the gaps.
  After a decode, lost recovery symbols are regenerated deterministically.

Striping granularity is the block. Archives with very few blocks per group (tiny archives, or an
unusual `target_k`) get less benefit from striping; the tiny profile compensates with a floor of
4 repair symbols per group and a warning in `info`.

## 5. Index

An index segment holds an lz4-compressed (size-prefixed) TLV stream. Each section is
`tag u16 (bit 15 = critical), len u32, bincode bytes`. Unknown non-critical sections are skipped.

| Tag | Section |
|---|---|
| 1 | files (sealed separately when encrypted) |
| 2 | blocks: seq, offset, stored/raw length, raw offset, codec, flags, set, hash |
| 3 | ECC sets: first block, block count, stripe |
| 4 | recovery regions: set, offset, repairs per group, ESI base per group |
| 5 | snapshots |
| 6 | detached info (target name, length, CRC-segment offset) |

Because only the file table is encrypted, `check` and `repair` work without a password.
The writer emits intermediate indexes with `owner=0`. The final index and mirror have `owner=1`
and `seq` set to the committed generation. Both final copies contain the same compressed bytes.

### Protected catalog

Before the two final index copies, kind-7 segments independently encode the compressed index.
Each payload is the 16-byte BLAKE3 digest of the complete compressed index followed by a 4096-byte
symbol. The segment hash covers that entire payload. Groups use up to 64 source symbols, followed
by 25% RaptorQ repair symbols with a minimum of four. The final source symbol is zero-padded.
The flags are 0 for a systematic symbol and 1 for a repair symbol. `raw_len` is the complete
compressed index length, `owner` the symbol ID, `seq` the generation, `set_id` the zero-based group,
and `stripe` the source symbol count. The reader verifies the decoded catalog digest and the committed
inventory before using it. This catalog is separate from the user-selected data recovery ratio.

## 6. Footer

64 bytes, written twice: magic `89 'R' 'Q' 'F' 0D 0A 1A 0A`, `index_offset u64`, `index_len u32`,
`index_hash 16`, UUID 16, `total_segments u32`, `index_gap u32`, CRC32C 4. The mirror starts at
`index_offset - index_len - index_gap`.

## 7. Open path

1. Read the header copies, preferring the valid copy with the highest committed generation.
2. Check both footers and both final index copies.
3. Search backward for a final index matching the committed generation and inventory.
4. Scan for the protected catalog and verify the reconstructed index.
5. Salvage block and file metadata from surviving segments. Rebuilding a complete index requires
   matching the header’s inventory. An incomplete scan remains damaged and can still yield identifiable files.

A locked archive can verify stored bytes and reconstruct an intact sealed index. Unlocking lets the
reader verify the file table and decoded file data. Older 0.1 archives without a committed inventory
can be opened with an intact footer and index. Recovery from older checkpoints without that evidence
is treated as salvage.

## 8. Detached sidecars (`.rqzp`)

Same container with required feature bit 1. There are no data segments: block entries describe fixed
windows of the *external* file (hash + length), a contiguous run of symbol-CRC segments (kind 4) localises
damage inside a window, and the recovery regions are as above. Repair patches the protected file, never
the sidecar's view of it.

## 9. Split volumes

A split archive is the ordinary archive image cut into numbered volume files (`name.rqz.001`,
`.002`, …). Readers present the volumes as one address space (`VolumeSet`), so opening, checking,
repairing and extracting work unchanged: a missing or damaged volume is a stretch of erasures.

Each volume starts with a self-checking volume header, followed by that volume's slice of the image:

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | magic `89 'R' 'Q' 'V' 0D 0A 1A 0A` |
| 8 | 16 | archive UUID |
| 24 | 4 | volume index (0-based) |
| 28 | 4 | volume count |
| 32 | 8 | `std_len`: payload bytes in a regular volume |
| 40 | 4 | `cut_index`: the one short volume (`0xFFFFFFFF` = none) |
| 48 | 8 | `cut_len`: payload bytes in the short volume |
| 56 | 8 | `payload_len`: payload bytes in *this* volume |
| 64 | 4 | `copy_len`: length of the archive header copy |
| 72 | 4 | CRC32C of bytes 0..72 |
| 80 | `copy_len` | a copy of the archive header (self-checking) |

Layout rules (so a lost volume's size can always be derived from its neighbours):

* Every volume holds `std_len` payload bytes except the short volume and the last one.
* **The recovery region starts a fresh volume**: the volume where data ends is cut short. The tail
  volumes therefore hold only recovery data, the final index and the footers. Losing them never loses
  a data block, and the file table was already written before the cut.
* Volume 1 holds the archive header (A and B). If it is lost, readers serve those bytes from the
  header copy in any other volume, and repair writes them back.
* A split archive is **one ECC set**, so recovery data is striped across every volume.

Each volume header also stores the complete logical length. The low 32 bits are at offset 44 and
the high 32 bits at offset 68. A legacy zero length uses the last available part as a fallback.
Volume geometry and header copies must agree before the reader assembles the address space.

`--volume-size V` limits the total bytes of every part, including its header. An optional
`--survive-volumes N` increases data parity using a bounded sizing heuristic. The value is a
target. Actual repairability is determined from available metadata, decoding, and verification
of affected blocks. A repaired copy is staged before publication. The index mirror can be moved
to the next part boundary when the gap is at most 1 MiB.

## 10. Browsing: mount and serve

Both use one read-only tree built from the index (`Vfs`) and read through `Archive::read_range`, which
decodes through a small block cache and repairs damaged groups in memory. `rqz mount` exposes it via
FUSE (Linux). `rqz serve` exposes it as read-only WebDAV (class 1: `OPTIONS`, `GET` with `Range`,
`HEAD`, `PROPFIND`), which Windows, macOS and most Linux file managers can map as a drive.

## 11. Encryption

Argon2id (64 MiB, t=3) → 32-byte key → XChaCha20-Poly1305. New encrypted blocks prepend a random
24-byte nonce with `uuid || seq` as associated data. Earlier blocks without flag 8 retain their
sequence-derived nonce. Metadata and the file table use random nonces.
Encryption happens **before** hashing and erasure coding.

## 12. Versioning

* `ver_major`: incompatible changes. `ver_minor`: compatible additions.
* Writers use the lowest version that covers the features they use.
* Index sections are tagged and length-prefixed so new metadata can be added without breaking old readers.
* The per-block codec id lets default codecs change without touching the format version.

## 13. Known limitations in 0.1

* Streaming output (stdout) is not supported: ECC reads blocks back from the file.
* A full scan cannot recover a block whose segment header is damaged *and* whose index entry is gone.
* Striping works at block granularity (see §4).
* `add` and `add-protection` do not work on split archives yet.
* Missing consecutive volumes are recreated using the derived layout; it must be consistent with the surviving volume headers.
* No dedup, dictionaries or signatures (flag bits are reserved).
