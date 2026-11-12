# razerq

**Archives that heal.** One file format that is both a compressed archive *and* carries its own
repair data, so a few flipped bits, a bad sector or a truncated download don't cost you the archive.

Most archive formats can tell you something is wrong; very few can fix it. PAR2 can, but it is a separate
sidecar tool. razerq puts compression, integrity checks and **RaptorQ erasure coding** in one container
and makes health a first-class state: every archive is *healthy*, *repairable* or *damaged beyond recovery*,
and the tools always tell you which, and how much protection is left.

```console
$ rqz pack photos/ -o photos.rqz --protect 10%
  photos.rqz
  4,212 files · 18.4 GB → 11.9 GB
  + 1.2 GB recovery (survives about 1.2 GB of damage)
  ✓ verified after write (6,102 blocks, 0 errors)

$ rqz check photos.rqz          # after some damage
  ✗ 14 blocks damaged (0.2%)
  ✓ repairable · 9.8% headroom left
  Next: rqz repair photos.rqz

$ rqz repair photos.rqz
  → wrote photos.repaired.rqz (original untouched)
```

*(Output above is illustrative of the format; the numbers are examples.)*

## What's in the box

| Crate | What it is |
|---|---|
| `rqz-ecc` | RaptorQ grouping, striping, encode/decode. Knows nothing about files. |
| `rqz-core` | The format: segments, index, open/repair state machine, writer, encryption, fs operations. |
| `rqz-cli` | The `rqz` command. |
| `rqz-gui` | Desktop app (egui): health card, block map, per-group headroom, pack / repair / extract. |
| `rqz-wasm` | The same core in the browser: open, check, repair, extract, create small archives. |
| `web/` | Static viewer page for the WASM build (deployed to GitHub Pages by CI). |

## Status

Early, working, **format 0.1 is a draft** (nothing has been released, so it can still change freely) and may change before 1.0. It has tests, but it has not seen the
years of abuse that a backup format needs. Keep another copy of anything you care about.

| Feature | State |
|---|---|
| pack / x / ls / check / repair / info | ✅ |
| zstd, lz4, store; skips already-compressed file types | ✅ |
| Independent blocks, per-block BLAKE3, per-symbol CRC32C (stored twice) | ✅ |
| RaptorQ recovery, striped across groups, round-robin interleaved | ✅ |
| Redundant index checkpoints + self-describing segments (scan rebuild) | ✅ |
| Mirrored header and footer | ✅ |
| Verify-after-write (on by default) | ✅ |
| Tiny profile (small archives get a safety floor and an honest warning) | ✅ |
| Encryption (Argon2id + XChaCha20-Poly1305); check/repair need no password | ✅ |
| Snapshots via `add`; `add-protection` top-up | ✅ |
| `protect`: detached sidecar for any existing file | ✅ |
| `repair --with` a second damaged copy | ✅ |
| Import zip / tar / tar.gz (transcode) | ✅ |
| `manifest` (sha256sum-compatible), `bench`, shell completions | ✅ |
| Path-traversal and symlink-escape protection on extract | ✅ |
| Deterministic output (`--deterministic`) | ✅ |
| GUI (native) and WASM viewer/repairer/creator | ✅ |
| Split volumes (`--volume-size`): lose any volume(s) and still recover | ✅ |
| `mount` (Linux FUSE) and `serve` (read-only WebDAV for Windows, macOS, Linux) | ✅ |
| Dedup (dropped for now), signatures, 7z import, config file, native Windows mount (WinFsp) | planned |
| Symbol-level striping, shared zstd dictionaries | planned |

## Build

```console
cargo build --release -p rqz-cli          # target/release/rqz
cargo build --release -p rqz-gui          # target/release/rqz-gui
cargo test  -p rqz-ecc -p rqz-core -p rqz-cli
```

Rust 1.85+ (1.88+ for the GUI). The default build links the C `zstd` library for speed. The WASM build uses
pure-Rust codecs only, and can read everything the native build writes.

### WASM

```console
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
wasm-pack build crates/rqz-wasm --release --target web --out-dir ../../web/pkg
python3 -m http.server -d web 8000        # then open http://localhost:8000
```

The page has a **Try the demo** button that builds a real archive in your browser, lets you damage it,
then repairs it and redraws the block map.

## Usage

```text
rqz pack <paths> -o out.rqz [--compress none|fast|normal|max|zstd:N]
                            [--protect 0|low|normal|paranoid|N%] [--encrypt]
                            [--volume-size 700M [--survive-volumes N]]
                            [--deterministic] [--no-verify] [--jobs N]
rqz x <archive> [files] [-o dir] [--snapshot N]    extract; repairs in memory
rqz ls <archive> [--long] [--snapshot N]
rqz check <archive> [--target file]                verify only, never modifies
rqz repair <archive> [--with other-copy] [-o out] [--in-place --force]
rqz info <archive>
rqz add <archive> <paths>                          append as a new snapshot
rqz mount <archive> <dir>                          browse as a drive (Linux, FUSE)
rqz serve <archive> [--port 8080]                  browse as a drive (WebDAV, any OS)
rqz protect <file>                                 sidecar recovery data (file.rqzp)
rqz add-protection <archive> [--protect 10%]       top up redundancy
rqz import <zip|tar|tar.gz> -o out.rqz
rqz manifest <archive>                             sha256sum-compatible list
rqz bench                                          measure this machine
rqz completions <shell>
```

Global flags: `--json` (NDJSON progress events and JSON results on every command), `-q`.
Set `RQZ_PASSWORD` for non-interactive use of encrypted archives.

**Exit codes:** `0` healthy · `1` repaired or repairable · `2` unrecoverable damage or error · `3` usage error.
That makes scheduled scrubbing a one-liner, for example a cron job running `rqz check /backups/x.rqz --json`
and alerting on a non-zero exit.

**Safe by default:** `repair` writes a new file and never touches the original unless you pass
`--in-place --force`. If damage exceeds the recovery budget, `x` still extracts everything that is intact
and lists exactly which files were lost.

## Split volumes

```console
$ rqz pack photos/ -o backup.rqz --volume-size 700M --survive-volumes 1
  split into 9 volumes (backup.rqz.001 …); survives the loss of any 1 volume(s)

$ rm backup.rqz.003                      # a volume goes missing
$ rqz check backup.rqz.001
  • volume 3 of 9 is missing
  ✓ repairable · 225.2% headroom left
$ rqz x backup.rqz.001 -o out            # still extracts, rebuilding that volume's blocks in memory
$ rqz repair backup.rqz.001 -o fixed     # writes a complete, verified set of volumes to fixed/
```

The volumes are an ordinary archive cut into pieces, so recovery data is striped across *all* of them and
a lost volume is just erasures. `--survive-volumes N` sizes the recovery data so that any N volumes can be
lost (it warns when that would cost more than the data itself, which happens when volumes are large
compared with the archive). Any volume, or the bare name, opens the set; the **first volume can be lost
too** because every volume carries a copy of the archive header. Details: [`docs/FORMAT.md`](docs/FORMAT.md#9-split-volumes).

## Browse as a drive

```console
$ rqz mount backup.rqz /mnt/backup        # Linux (FUSE); unmount with: fusermount3 -u /mnt/backup
$ rqz serve backup.rqz                     # any OS: read-only WebDAV on http://127.0.0.1:8080/
```

Both are read-only and heal damage in memory as files are read, so a damaged or incomplete archive stays
browsable. To map the `serve` address as a drive:

* **Windows:** `net use Z: http://127.0.0.1:8080/` (or Explorer → Map network drive). The WebClient service must be running.
* **macOS:** Finder → Go → Connect to Server → `http://127.0.0.1:8080/`.
* **Linux:** `mount -t davfs http://127.0.0.1:8080/ /mnt/rqz`, or open the address in your file manager. Browsers show a plain file listing.

`serve` listens on this computer only by default. `--bind 0.0.0.0` exposes the archive to your network with no password.

## How it works

```
files ─► one logical stream ─► independent blocks (2 MiB) ─► compress ─► [encrypt] ─► hash
                                                                                       │
       ┌───────────────────────────────────────────────────────────────────────────────┘
       ▼
 blocks are grouped into ECC sets, striped across G groups (block i → group i mod G)
 each group = one RaptorQ source block; repair symbols are written round-robin after the set
 the index (file table, block table, set/recovery map) is written as a full copy at every checkpoint
```

* **Hashes locate damage, RaptorQ fills the gaps.** Checksums say *which* symbols are bad, so decoding only
  has to fill known holes. That is cheaper and stronger than blind error correction.
* **Striping** stops a dead stretch of disk from wiping out whole groups.
* **Everything is self-describing**, so if every index copy is destroyed a scan rebuilds it from the segments.
* **Encrypt before ECC.** Recovery works without the password and the repairer never sees plaintext.

Details and byte layouts: [`docs/FORMAT.md`](docs/FORMAT.md).

## Performance

Run `rqz bench` to measure your machine. For reference, the RaptorQ encoder alone (`cargo run --release -p rqz-ecc --example speed`)
did roughly 300-400 MB/s of source data per core on a small cloud VM, so with zstd 6 the compressor, not the
erasure code, is normally the bottleneck. Verification (`check`) is BLAKE3-bound and much faster than packing.
Debug builds are far slower; always benchmark with `--release`.

## Honest limits

* Small archives are weaker. A 10 KB archive cannot be as well protected as a 10 GB one; the tiny profile
  adds a floor of repair symbols and `info` says so plainly. For tiny data, a second copy elsewhere is the real protection.
* Recovery data lives in the same file (or next to it). It protects against corruption, not against losing the drive.
* Output must be a seekable file (no streaming to stdout yet).
* `add` and `add-protection` do not work on split archives yet. `mount` is Linux-only; other systems use `serve` (WebDAV `HEAD` replies omit `Content-Length`; `PROPFIND` and ranged `GET` are complete).
* The WASM build holds the whole archive in memory and runs single-threaded.

## License

MIT. See [`LICENSE`](LICENSE).
