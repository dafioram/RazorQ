#![allow(clippy::field_reassign_with_default, clippy::type_complexity)]
//! rqz: pack, check and repair self-healing archives.
//!
//! Exit codes: 0 healthy · 1 repaired or repairable · 2 unrecoverable damage · 3 usage error.

mod mount;
mod serve;

use anyhow::{anyhow, bail, Result};
use clap::{Args, CommandFactory, Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use rqz_core::archive::{Archive, Health};
use rqz_core::codec::Compression;
use rqz_core::format::SEG_HEADER_LEN;
use rqz_core::fsops::{self, Source};
use rqz_core::progress::{Event, Progress, Quiet};
use rqz_core::writer::{ArchiveWriter, PackOptions, Protect};
use serde_json::json;
use std::io::{Cursor, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Parser)]
#[command(name = "rqz", version, about = "Self-healing archives: compression + RaptorQ erasure coding")]
struct Cli {
    /// Machine-readable output (NDJSON progress events, JSON results)
    #[arg(long, global = true)]
    json: bool,
    /// Suppress progress output
    #[arg(short, long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct WriteFlags {
    /// none | fast | normal | max | zstd:N
    #[arg(long, default_value = "normal")]
    compress: String,
    /// 0 | low (2%) | normal (10%) | paranoid (30%) | N%
    #[arg(long, default_value = "normal")]
    protect: String,
    /// Encrypt with a password (prompted, or RQZ_PASSWORD)
    #[arg(long)]
    encrypt: bool,
    /// Worker threads (default: all cores)
    #[arg(long)]
    jobs: Option<usize>,
    /// Same input gives the same bytes
    #[arg(long)]
    deterministic: bool,
    /// Skip the read-back check after writing
    #[arg(long)]
    no_verify: bool,
    /// Split into volumes of this size, e.g. 700M or 4G (binary units)
    #[arg(long)]
    volume_size: Option<String>,
    /// With --volume-size: size recovery data so this many whole volumes can be lost (default 1)
    #[arg(long)]
    survive_volumes: Option<u32>,
    /// Block size in KiB (advanced)
    #[arg(long, hide = true)]
    block_kib: Option<u32>,
    /// Symbol size in bytes (advanced)
    #[arg(long, hide = true)]
    symbol_size: Option<u16>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create an archive
    #[command(alias = "a")]
    Pack {
        paths: Vec<PathBuf>,
        #[arg(short, long)]
        output: PathBuf,
        #[command(flatten)]
        w: WriteFlags,
    },
    /// Extract (auto-repairs in memory)
    X {
        archive: PathBuf,
        /// Only these files or folders
        files: Vec<String>,
        #[arg(short, long, default_value = ".")]
        output: PathBuf,
        #[arg(long)]
        snapshot: Option<u32>,
    },
    /// List contents
    Ls {
        archive: PathBuf,
        #[arg(long)]
        snapshot: Option<u32>,
        #[arg(short, long)]
        long: bool,
    },
    /// Verify only; never modifies anything
    Check {
        archive: PathBuf,
        /// Protected file, for sidecar (.rqzp) archives
        #[arg(long)]
        target: Option<PathBuf>,
    },
    /// Write a repaired copy (original untouched unless --in-place)
    Repair {
        archive: PathBuf,
        /// A second, possibly damaged copy of the same archive
        #[arg(long)]
        with: Option<PathBuf>,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long)]
        in_place: bool,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        target: Option<PathBuf>,
    },
    /// Size, ratio, health and headroom
    Info { archive: PathBuf },
    /// Append files as a new snapshot
    Add {
        archive: PathBuf,
        paths: Vec<PathBuf>,
        #[command(flatten)]
        w: WriteFlags,
    },
    /// Sidecar recovery data for an existing file (the file is not modified)
    Protect {
        file: PathBuf,
        #[arg(short, long)]
        output: Option<PathBuf>,
        #[arg(long, default_value = "normal")]
        protect: String,
        #[arg(long)]
        no_verify: bool,
    },
    /// Top up redundancy of an existing archive without recompressing
    AddProtection {
        archive: PathBuf,
        #[arg(long, default_value = "10%")]
        protect: String,
    },
    /// Transcode a zip / tar / tar.gz into an archive
    Import {
        input: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[command(flatten)]
        w: WriteFlags,
    },
    /// Print a sha256sum-compatible manifest
    Manifest {
        archive: PathBuf,
        #[arg(long)]
        snapshot: Option<u32>,
    },
    /// Mount an archive read-only as a drive (Linux, via FUSE)
    Mount {
        archive: PathBuf,
        mountpoint: PathBuf,
        #[arg(long)]
        snapshot: Option<u32>,
    },
    /// Serve an archive read-only over WebDAV: map it as a drive on Windows, macOS or Linux
    Serve {
        archive: PathBuf,
        #[arg(long, default_value_t = 8080)]
        port: u16,
        /// Address to listen on (default: this computer only)
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        #[arg(long)]
        snapshot: Option<u32>,
    },
    /// Measure compression and ECC speed on this machine
    Bench {
        #[arg(long, default_value_t = 32)]
        size_mb: usize,
    },
    /// Shell completions
    Completions { shell: clap_complete::Shell },
    /// Developer tools
    #[command(hide = true)]
    Dev {
        #[command(subcommand)]
        cmd: DevCmd,
    },
}

#[derive(Subcommand)]
enum DevCmd {
    /// Corrupt a copy of an archive (for demos and tests)
    Damage {
        archive: PathBuf,
        #[arg(short, long)]
        output: PathBuf,
        #[arg(long, default_value_t = 20)]
        spans: u32,
        #[arg(long, default_value_t = 4096)]
        len: usize,
        #[arg(long, default_value_t = 1)]
        seed: u64,
    },
}

// ------------------------------------------------------------------ progress

struct Ui {
    json: bool,
    bar: Option<ProgressBar>,
    last: Mutex<Instant>,
}

impl Ui {
    fn new(json: bool, quiet: bool) -> Ui {
        let bar = (!json && !quiet && std::io::stderr().is_terminal()).then(|| {
            let b = ProgressBar::new(100);
            b.set_style(
                ProgressStyle::with_template("  {msg:<26} {bar:30.cyan/blue} {percent:>3}%  {bytes_per_sec}")
                    .unwrap()
                    .progress_chars("█░ "),
            );
            b
        });
        Ui { json, bar, last: Mutex::new(Instant::now()) }
    }
    fn done(&self) {
        if let Some(b) = &self.bar {
            b.finish_and_clear();
        }
    }
}

impl Progress for Ui {
    fn emit(&self, e: Event) {
        match e {
            Event::Stage(s) => {
                if self.json {
                    println!("{}", json!({"event": "stage", "name": s}));
                } else if let Some(b) = &self.bar {
                    b.set_message(s);
                    b.set_position(0);
                }
            }
            Event::Progress { done, total } => {
                if let Ok(mut t) = self.last.lock() {
                    if t.elapsed().as_millis() < 100 && done != total {
                        return;
                    }
                    *t = Instant::now();
                }
                if self.json {
                    println!("{}", json!({"event": "progress", "done": done, "total": total}));
                } else if let Some(b) = &self.bar {
                    b.set_length(total.max(1));
                    b.set_position(done);
                }
            }
            Event::Note(n) => {
                if self.json {
                    println!("{}", json!({"event": "note", "message": n}));
                } else if let Some(b) = &self.bar {
                    b.println(format!("  note: {n}"));
                } else {
                    eprintln!("note: {n}");
                }
            }
        }
    }
}

// ------------------------------------------------------------------ helpers

fn human(n: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut i = 0;
    while v >= 1000.0 && i < U.len() - 1 {
        v /= 1000.0;
        i += 1;
    }
    if i == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", U[i])
    }
}

fn commas(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn password_for_write(encrypt: bool) -> Result<Option<String>> {
    if !encrypt {
        return Ok(None);
    }
    if let Ok(p) = std::env::var("RQZ_PASSWORD") {
        return Ok(Some(p));
    }
    if !std::io::stdin().is_terminal() {
        bail!("--encrypt needs a password: set RQZ_PASSWORD or run in a terminal");
    }
    let a = rpassword::prompt_password("Password: ")?;
    let b = rpassword::prompt_password("Repeat password: ")?;
    if a != b {
        bail!("passwords do not match");
    }
    if a.is_empty() {
        bail!("empty password");
    }
    Ok(Some(a))
}

fn password_for_read(path: &Path, needed: bool) -> Result<Option<String>> {
    if let Ok(p) = std::env::var("RQZ_PASSWORD") {
        return Ok(Some(p));
    }
    if !needed {
        return Ok(None);
    }
    let a = Archive::open(Source::open(path)?, None).map_err(|e| anyhow!("{}: {e}", path.display()))?;
    if !a.locked {
        return Ok(None);
    }
    if !std::io::stdin().is_terminal() {
        bail!("this archive is encrypted: set RQZ_PASSWORD");
    }
    Ok(Some(rpassword::prompt_password("Password: ")?))
}

fn pack_options(w: &WriteFlags) -> Result<PackOptions> {
    if let Some(j) = w.jobs {
        let _ = rayon::ThreadPoolBuilder::new().num_threads(j.max(1)).build_global();
    }
    let mut o = PackOptions::default();
    o.compression =
        Compression::parse(&w.compress).ok_or_else(|| anyhow!("unknown --compress value '{}'", w.compress))?;
    o.protect = Protect::parse(&w.protect).ok_or_else(|| anyhow!("unknown --protect value '{}'", w.protect))?;
    o.password = password_for_write(w.encrypt)?;
    o.deterministic = w.deterministic;
    if let Some(k) = w.block_kib {
        o.block_size = k * 1024;
    }
    o.symbol_size = w.symbol_size;
    if let Some(v) = &w.volume_size {
        o.volume_size = parse_size(v)?;
        o.survive_volumes = w.survive_volumes.unwrap_or(1);
    } else if w.survive_volumes.is_some() {
        bail!("--survive-volumes needs --volume-size");
    }
    Ok(o)
}

/// "700M", "4G", "64K", "123456" (binary units, like `split`).
fn parse_size(s: &str) -> Result<u64> {
    let t = s.trim();
    let (num, mult) = match t.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => {
            let m = match c.to_ascii_uppercase() {
                'K' => 1u64 << 10,
                'M' => 1 << 20,
                'G' => 1 << 30,
                'T' => 1 << 40,
                _ => bail!("unknown size suffix in '{s}' (use K, M, G or T)"),
            };
            (&t[..t.len() - 1], m)
        }
        _ => (t, 1),
    };
    let n: f64 = num.parse().map_err(|_| anyhow!("cannot read size '{s}'"))?;
    if n <= 0.0 {
        bail!("size must be positive");
    }
    Ok((n * mult as f64) as u64)
}

fn health_code(h: Health) -> i32 {
    match h {
        Health::Healthy => 0,
        Health::Repairable => 1,
        Health::Damaged => 2,
    }
}

// ------------------------------------------------------------------ commands

fn main() {
    let cli = match Cli::try_parse() {
        Ok(c) => c,
        Err(e) => {
            let _ = e.print();
            std::process::exit(if e.use_stderr() { 3 } else { 0 });
        }
    };
    let json = cli.json;
    match run(cli) {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            if json {
                println!("{}", json!({"event": "error", "message": format!("{e:#}")}));
            } else {
                eprintln!("error: {e:#}");
            }
            std::process::exit(2);
        }
    }
}

fn run(cli: Cli) -> Result<i32> {
    let ui = Ui::new(cli.json, cli.quiet);
    let json = cli.json;
    match cli.cmd {
        Cmd::Pack { paths, output, w } => {
            if paths.is_empty() {
                bail!("nothing to pack");
            }
            let opts = pack_options(&w)?;
            let survive = opts.survive_volumes;
            let r = fsops::pack_paths(&paths, &output, opts, !w.no_verify, &ui)?;
            ui.done();
            report_pack(json, &output, &r.summary, r.verified, survive);
            Ok(0)
        }
        Cmd::Add { archive, paths, w } => {
            let mut opts = pack_options(&w)?;
            opts.password = password_for_read(&archive, true)?;
            let r = fsops::add_paths(&archive, &paths, opts, !w.no_verify, &ui)?;
            ui.done();
            report_pack(json, &archive, &r.summary, r.verified, 0);
            Ok(0)
        }
        Cmd::Import { input, output, w } => {
            let opts = pack_options(&w)?;
            let survive = opts.survive_volumes;
            let n = input.to_string_lossy().to_ascii_lowercase();
            let r = if n.ends_with(".zip") {
                fsops::import_zip(&input, &output, opts, !w.no_verify, &ui)?
            } else if n.ends_with(".tar") || n.ends_with(".tar.gz") || n.ends_with(".tgz") {
                fsops::import_tar(&input, &output, opts, !w.no_verify, &ui)?
            } else {
                bail!("import supports .zip, .tar, .tar.gz and .tgz (7z is on the roadmap)");
            };
            ui.done();
            report_pack(json, &output, &r.summary, r.verified, survive);
            Ok(0)
        }
        Cmd::X { archive, files, output, snapshot } => {
            let pw = password_for_read(&archive, true)?;
            let a = Archive::open(Source::open(&archive)?, pw.as_deref())?;
            let rep = fsops::extract_archive(&a, &output, &files, snapshot, &ui)?;
            ui.done();
            if json {
                println!(
                    "{}",
                    json!({"files": rep.files, "bytes": rep.bytes, "lost": rep.lost, "skipped": rep.skipped, "repaired_groups": rep.healed_groups})
                );
            } else {
                if rep.healed_groups > 0 {
                    println!(
                        "  ⚠ repaired {} damaged group(s) in memory (the archive file was not changed)",
                        rep.healed_groups
                    );
                }
                println!("  {} files extracted ({})", commas(rep.files as usize), human(rep.bytes));
                for s in &rep.skipped {
                    println!("  skipped: {s}");
                }
                if !rep.lost.is_empty() {
                    println!("  ✗ {} file(s) lost to damage beyond the recovery budget:", rep.lost.len());
                    for l in &rep.lost {
                        println!("    - {l}");
                    }
                    println!("  Next: rqz repair {} --with <another copy>", archive.display());
                }
            }
            Ok(if !rep.lost.is_empty() {
                2
            } else if rep.healed_groups > 0 {
                1
            } else {
                0
            })
        }
        Cmd::Ls { archive, snapshot, long } => {
            let pw = password_for_read(&archive, true)?;
            let a = Archive::open(Source::open(&archive)?, pw.as_deref())?;
            let files = a.visible_files(snapshot);
            if json {
                let v: Vec<_> = files.iter().map(|f| json!({"path": f.path, "size": f.size, "kind": f.kind, "mode": f.mode, "mtime": f.mtime, "snapshot": f.snapshot})).collect();
                println!("{}", serde_json::to_string(&v)?);
            } else {
                for f in files {
                    if long {
                        let k = match f.kind {
                            1 => 'd',
                            2 => 'l',
                            _ => '-',
                        };
                        println!(
                            "{k}{:04o} {:>12}  {}{}",
                            f.mode & 0o7777,
                            f.size,
                            f.path,
                            f.link.as_ref().map(|l| format!(" -> {l}")).unwrap_or_default()
                        );
                    } else {
                        println!("{}", f.path);
                    }
                }
            }
            Ok(0)
        }
        Cmd::Check { archive, target } => {
            let pw = password_for_read(&archive, false)?;
            let (a, _) = fsops::open_any(&archive, pw.as_deref(), target.as_deref())?;
            let asm = a.assess(&ui);
            ui.done();
            let info = a.info();
            if json {
                let groups: Vec<_> = asm.groups.iter().filter(|g| g.state() != Health::Healthy).map(|g| json!({"set": g.set, "group": g.group, "erased_symbols": g.erased, "repair_ok": g.repair_ok, "repair_total": g.repair_total})).collect();
                println!(
                    "{}",
                    json!({
                        "health": format!("{:?}", asm.health).to_lowercase(),
                        "blocks": asm.blocks_total, "damaged_blocks": asm.blocks_damaged,
                        "headroom_ratio": asm.min_headroom_ratio, "headroom_symbols": asm.min_headroom_symbols,
                        "structural": asm.structural, "bad_groups": groups,
                        "opened_via": info.opened_via.describe(),
                    })
                );
            } else {
                for s in &asm.structural {
                    println!("  • {s}");
                }
                match asm.health {
                    Health::Healthy => {
                        println!("  ✓ healthy · {} blocks OK{}", commas(asm.blocks_total), headroom_text(&asm, " · "))
                    }
                    Health::Repairable => {
                        if asm.blocks_damaged > 0 {
                            println!(
                                "  ✗ {} blocks damaged ({:.1}%)",
                                commas(asm.blocks_damaged),
                                100.0 * asm.blocks_damaged as f64 / asm.blocks_total.max(1) as f64
                            );
                        }
                        println!("  ✓ repairable{}", headroom_text(&asm, " · "));
                        println!("  Next: rqz repair {}", archive.display());
                    }
                    Health::Damaged => {
                        let lost =
                            asm.block_states.iter().filter(|s| **s == rqz_core::archive::BlockState::Lost).count();
                        println!("  ✗ {} blocks damaged, {} beyond repair", commas(asm.blocks_damaged), commas(lost));
                        println!(
                            "  Next: rqz repair {} --with <another copy>, or rqz x to extract what is intact",
                            archive.display()
                        );
                    }
                }
            }
            Ok(health_code(asm.health))
        }
        Cmd::Repair { archive, with, output, in_place, force, target } => {
            if in_place && !force {
                if !std::io::stdin().is_terminal() {
                    bail!("--in-place overwrites the original: add --force to confirm");
                }
                eprint!("Overwrite {} in place? [y/N] ", archive.display());
                std::io::stderr().flush()?;
                let mut s = String::new();
                std::io::stdin().read_line(&mut s)?;
                if !s.trim().eq_ignore_ascii_case("y") {
                    bail!("cancelled");
                }
            }
            let pw = password_for_read(&archive, false)?;
            let opts = fsops::RepairOptions { out: output, in_place, donor: with, password: pw, target };
            let r = fsops::repair_file(&archive, &opts, &ui)?;
            ui.done();
            let lost = r.plan.lost_files.len()
                + if r.plan.lost_files.is_empty() { r.plan.lost_blocks.len().min(1) } else { 0 };
            if json {
                println!(
                    "{}",
                    json!({"before": format!("{:?}", r.before).to_lowercase(), "after": format!("{:?}", r.after).to_lowercase(), "blocks_fixed": r.plan.blocks_fixed, "recovery_regenerated": r.plan.recovery_regenerated, "structural_fixed": r.plan.structural_fixed, "lost_blocks": r.plan.lost_blocks.len(), "lost_files": r.plan.lost_files, "written": r.written})
                );
            } else if r.plan.is_empty() && lost == 0 {
                println!("  ✓ nothing to repair");
            } else {
                if let (Some(w), true) = (&r.written, r.split) {
                    println!(
                        "  → wrote the repaired volume set to {}{}",
                        w.parent().map(|p| p.display().to_string()).unwrap_or_default(),
                        if in_place { " (repaired in place)" } else { " (originals untouched)" }
                    );
                } else if let Some(w) = &r.written {
                    println!(
                        "  → wrote {} (original untouched{})",
                        w.display(),
                        if in_place { ": repaired in place" } else { "" }.replace("original untouched: ", "")
                    );
                }
                println!(
                    "  fixed {} block(s), regenerated {} recovery symbol(s), repaired {} structure item(s)",
                    r.plan.blocks_fixed, r.plan.recovery_regenerated, r.plan.structural_fixed
                );
                if !r.plan.lost_blocks.is_empty() {
                    println!("  ✗ {} block(s) could not be recovered. Lost files:", r.plan.lost_blocks.len());
                    for l in &r.plan.lost_files {
                        println!("    - {l}");
                    }
                } else {
                    println!("  Run `rqz add-protection` to top up redundancy if headroom is low.");
                }
            }
            Ok(if lost > 0 {
                2
            } else if r.plan.is_empty() {
                0
            } else {
                1
            })
        }
        Cmd::Info { archive } => {
            let pw = password_for_read(&archive, false)?;
            let (a, _) = fsops::open_any(&archive, pw.as_deref(), None)
                .or_else(|_| fsops::open_any(&archive, pw.as_deref(), Some(&archive)))?;
            let i = a.info();
            let vols = a.source().volume_set().map(|v| (v.count(), v.missing().len()));
            if json {
                println!(
                    "{}",
                    json!({
                        "volumes": vols.map(|v| v.0), "missing_volumes": vols.map(|v| v.1),
                        "version": format!("{}.{}", i.version.0, i.version.1), "writer": i.writer, "file_len": i.file_len,
                        "files": i.files, "dirs": i.dirs, "raw_bytes": i.raw_bytes, "stored_bytes": i.stored_bytes,
                        "recovery_bytes": i.recovery_bytes, "blocks": i.blocks, "sets": i.sets, "groups": i.groups,
                        "symbol_size": i.symbol_size, "block_size": i.block_size, "encrypted": i.encrypted, "locked": i.locked,
                        "detached": i.detached, "tiny_profile": i.tiny_profile, "snapshots": i.snapshots.len(),
                        "opened_via": i.opened_via.describe(), "protection_ratio": i.protection_ratio, "weak_protection": i.weak_protection,
                    })
                );
            } else {
                println!("  {}", archive.display());
                println!("  format {}.{} · {}", i.version.0, i.version.1, i.writer);
                if i.detached {
                    println!("  sidecar protecting a {} file", human(i.raw_bytes));
                } else {
                    println!(
                        "  {} files · {} → {} stored ({:.0}%)",
                        commas(i.files),
                        human(i.raw_bytes),
                        human(i.stored_bytes),
                        100.0 * i.stored_bytes as f64 / i.raw_bytes.max(1) as f64
                    );
                }
                println!(
                    "  + {} recovery ({:.1}% · survives about {} of damage)",
                    human(i.recovery_bytes),
                    100.0 * i.protection_ratio,
                    human(i.recovery_bytes)
                );
                println!(
                    "  {} blocks of {} KiB · {} ECC set(s) · {} groups · {} B symbols",
                    commas(i.blocks),
                    i.block_size / 1024,
                    i.sets,
                    i.groups,
                    i.symbol_size
                );
                if i.encrypted {
                    println!("  encrypted{}", if i.locked { " (locked: file names hidden)" } else { "" });
                }
                if i.snapshots.len() > 1 {
                    println!("  {} snapshots", i.snapshots.len());
                }
                if let Some((n, missing)) = vols {
                    println!(
                        "  split into {n} volumes{}",
                        if missing > 0 { format!(" ({missing} missing)") } else { String::new() }
                    );
                }
                println!("  index loaded from {}", i.opened_via.describe());
                if let Some(w) = i.weak_protection {
                    println!("  ⚠ {w}");
                }
            }
            Ok(0)
        }
        Cmd::Protect { file, output, protect, no_verify } => {
            let out = output.unwrap_or_else(|| fsops::sidecar_path(&file));
            let mut opts = PackOptions::default();
            opts.protect = Protect::parse(&protect).ok_or_else(|| anyhow!("unknown --protect value"))?;
            let s = fsops::protect_file(&file, &out, opts, !no_verify, &ui)?;
            ui.done();
            if json {
                println!("{}", json!({"sidecar": out, "recovery_bytes": s.recovery_bytes, "file_len": s.file_len}));
            } else {
                println!(
                    "  {} protects {} ({} of recovery data){}",
                    out.display(),
                    file.display(),
                    human(s.recovery_bytes),
                    if no_verify { "" } else { " · verified" }
                );
                println!("  Check later with: rqz check {}", out.display());
            }
            Ok(0)
        }
        Cmd::AddProtection { archive, protect } => {
            let p = Protect::parse(&protect).ok_or_else(|| anyhow!("unknown --protect value"))?;
            let pw = password_for_read(&archive, true)?;
            let n = fsops::add_protection_file(&archive, p, pw.as_deref(), &ui)?;
            ui.done();
            if json {
                println!("{}", json!({"symbols_added": n}));
            } else {
                println!("  added {n} recovery symbols");
            }
            Ok(0)
        }
        Cmd::Manifest { archive, snapshot } => {
            let pw = password_for_read(&archive, true)?;
            let a = Archive::open(Source::open(&archive)?, pw.as_deref())?;
            let mut out = std::io::stdout().lock();
            a.manifest(snapshot, &mut out)?;
            Ok(0)
        }
        Cmd::Mount { archive, mountpoint, snapshot } => {
            let pw = password_for_read(&archive, true)?;
            let a = Arc::new(Archive::open(Source::open(&archive)?, pw.as_deref())?);
            mount::run(a, &mountpoint, snapshot)?;
            Ok(0)
        }
        Cmd::Serve { archive, port, bind, snapshot } => {
            let pw = password_for_read(&archive, true)?;
            let a = Arc::new(Archive::open(Source::open(&archive)?, pw.as_deref())?);
            let health = a.assess(&Quiet).health;
            if health != Health::Healthy {
                eprintln!("  note: this archive is {health:?}; damaged parts are repaired in memory as files are read");
            }
            serve::run(a, &bind, port, snapshot)?;
            Ok(0)
        }
        Cmd::Bench { size_mb } => bench(size_mb, json),
        Cmd::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "rqz", &mut std::io::stdout());
            Ok(0)
        }
        Cmd::Dev { cmd: DevCmd::Damage { archive, output, spans, len, seed } } => {
            let hits = fsops::damage_copy(&archive, &output, spans, len, seed)?;
            println!("  corrupted {} span(s) in {}", hits.len(), output.display());
            Ok(0)
        }
    }
}

fn headroom_text(a: &rqz_core::archive::Assessment, sep: &str) -> String {
    match a.min_headroom_ratio {
        Some(r) => format!("{sep}{:.1}% headroom left", r * 100.0),
        None => format!("{sep}no recovery data"),
    }
}

fn report_pack(json: bool, out: &Path, s: &rqz_core::writer::Summary, verified: bool, survive: u32) {
    if json {
        println!(
            "{}",
            json!({"archive": out, "files": s.files, "raw_bytes": s.raw_bytes, "stored_bytes": s.stored_bytes, "recovery_bytes": s.recovery_bytes, "file_len": s.file_len, "groups": s.groups, "verified": verified, "volumes": s.volumes, "survive_volumes": survive, "warnings": s.warnings})
        );
        return;
    }
    println!("  {}", out.display());
    println!("  {} files · {} → {}", commas(s.files as usize), human(s.raw_bytes), human(s.stored_bytes));
    if s.recovery_bytes > 0 {
        println!("  + {} recovery (survives about {} of damage)", human(s.recovery_bytes), human(s.recovery_bytes));
    } else {
        println!("  no recovery data (damage can be detected but not repaired)");
    }
    if s.volumes > 1 {
        println!(
            "  split into {} volumes ({}.001 …); survives the loss of any {} volume(s)",
            s.volumes,
            out.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
            survive
        );
    }
    for w in &s.warnings {
        println!("  ⚠ {w}");
    }
    if s.tiny_profile {
        println!("  ⚠ small archive: protects against a bad sector, not a dead drive. Keep a second copy elsewhere.");
    }
    if verified {
        println!("  ✓ verified after write ({} blocks, 0 errors)", commas(s.blocks as usize));
    }
}

fn bench(size_mb: usize, json: bool) -> Result<i32> {
    let n = size_mb.max(4) << 20;
    let mut x = 0x2545F4914F6CDD1Du64;
    let words: Vec<&[u8]> = vec![b"razerq ", b"archive ", b"recovery ", b"symbol ", b"block ", b"group ", b"stripe "];
    let mut data = Vec::with_capacity(n);
    while data.len() < n {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        if x % 5 == 0 {
            data.extend_from_slice(&x.to_le_bytes());
        } else {
            data.extend_from_slice(words[(x % words.len() as u64) as usize]);
        }
    }
    data.truncate(n);
    let mut rows = Vec::new();
    for (name, c, p) in [
        ("store, no ECC", Compression::None, Protect::NONE),
        ("fast (lz4)", Compression::Fast, Protect::NONE),
        ("normal (zstd 6)", Compression::Normal, Protect::NONE),
        ("max (zstd 19)", Compression::Max, Protect::NONE),
        ("store + 10% ECC", Compression::None, Protect::NORMAL),
        ("normal + 10% ECC", Compression::Normal, Protect::NORMAL),
    ] {
        let mut o = PackOptions::default();
        o.compression = c;
        o.protect = p;
        let t = Instant::now();
        let mut w = ArchiveWriter::create(Cursor::new(Vec::new()), o, &Quiet)?;
        w.add_bytes("bench.bin", 0o644, 0, &data)?;
        let (cur, s) = w.finish()?;
        let secs = t.elapsed().as_secs_f64();
        let bytes = cur.into_inner();
        let t2 = Instant::now();
        let a = Archive::open(bytes, None)?;
        let ok = a.assess(&Quiet).is_healthy();
        let vsecs = t2.elapsed().as_secs_f64();
        rows.push((
            name,
            n as f64 / 1e6 / secs,
            n as f64 / 1e6 / vsecs.max(1e-9),
            s.stored_bytes as f64 / n as f64,
            ok,
        ));
    }
    if json {
        let v: Vec<_> =
            rows.iter().map(|r| json!({"mode": r.0, "pack_mb_s": r.1, "verify_mb_s": r.2, "ratio": r.3})).collect();
        println!("{}", serde_json::to_string(&v)?);
    } else {
        println!(
            "  {} MiB synthetic data · {} threads · header {} B\n",
            size_mb,
            rayon::current_num_threads(),
            SEG_HEADER_LEN
        );
        println!("  {:<20} {:>10} {:>12} {:>8}", "mode", "pack MB/s", "verify MB/s", "size");
        for r in &rows {
            println!(
                "  {:<20} {:>10.0} {:>12.0} {:>7.0}%{}",
                r.0,
                r.1,
                r.2,
                r.3 * 100.0,
                if r.4 { "" } else { "  (verify FAILED)" }
            );
        }
        println!("\n  Tip: `normal` + 10% ECC is the default. Use `--compress fast` if packing is your bottleneck.");
    }
    Ok(0)
}
