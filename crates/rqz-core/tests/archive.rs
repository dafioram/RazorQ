#![allow(clippy::field_reassign_with_default, clippy::type_complexity)]
use rqz_core::archive::*;
use rqz_core::codec::Compression;
use rqz_core::progress::Quiet;
use rqz_core::writer::*;
use rqz_core::Error;
use std::io::Cursor;

fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    move || {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        s
    }
}

fn noise(seed: u64, n: usize) -> Vec<u8> {
    let mut r = rng(seed);
    (0..n).map(|_| r() as u8).collect()
}

fn text(seed: u64, n: usize) -> Vec<u8> {
    let words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india"];
    let mut r = rng(seed);
    let mut v = Vec::new();
    while v.len() < n {
        v.extend_from_slice(words[(r() % words.len() as u64) as usize].as_bytes());
        v.push(b' ');
    }
    v.truncate(n);
    v
}

fn small_opts() -> PackOptions {
    PackOptions { block_size: 8192, symbol_size: Some(512), target_k: 64, set_bytes: 1 << 20, ..PackOptions::default() }
}

fn corpus() -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    for i in 0..12 {
        v.push((format!("docs/file{i}.txt"), text(i, 5_000 + i as usize * 7_000)));
    }
    v.push(("photos/a.jpg".into(), noise(99, 120_000)));
    v.push(("photos/b.jpg".into(), noise(98, 90_000)));
    v.push(("empty.bin".into(), vec![]));
    v.push(("tiny.txt".into(), b"hi".to_vec()));
    v
}

fn build(files: &[(String, Vec<u8>)], opts: PackOptions) -> Vec<u8> {
    let mut w = ArchiveWriter::create(Cursor::new(Vec::new()), opts, &Quiet).unwrap();
    for (p, d) in files {
        w.add_bytes(p, 0o644, 1_700_000_000, d).unwrap();
    }
    w.finish().unwrap().0.into_inner()
}

fn assert_contents(a: &Archive<Vec<u8>>, files: &[(String, Vec<u8>)]) {
    let vis = a.visible_files(None);
    for (p, d) in files {
        let f = vis.iter().find(|f| &f.path == p).unwrap_or_else(|| panic!("missing {p}"));
        assert_eq!(&a.read_file(f).unwrap(), d, "content of {p}");
    }
}

fn open(bytes: Vec<u8>) -> Archive<Vec<u8>> {
    Archive::open(bytes, None).unwrap()
}

fn damage(bytes: &mut [u8], from: usize, len: usize) {
    for b in &mut bytes[from..from + len] {
        *b ^= 0xA5;
    }
}

fn repair_and_reopen(bytes: Vec<u8>) -> (Vec<u8>, RepairPlan) {
    let a = open(bytes.clone());
    let asm = a.assess(&Quiet);
    let plan = a.plan_repair(&asm, None, &Quiet);
    let mut fixed = bytes;
    apply_patches_to_vec(&mut fixed, &plan.patches);
    (fixed, plan)
}

#[test]
fn roundtrip_and_healthy() {
    let files = corpus();
    let a = open(build(&files, small_opts()));
    assert_contents(&a, &files);
    let asm = a.assess(&Quiet);
    assert!(asm.is_healthy(), "{:?}", asm.structural);
    let info = a.info();
    assert!(info.groups > 1, "striping should create several groups");
    assert!(info.recovery_bytes > 0);
}

#[test]
fn contiguous_damage_is_repaired() {
    let files = corpus();
    let bytes = build(&files, small_opts());
    let a = open(bytes.clone());
    let start = a.index.blocks[8].offset as usize + 100;
    let mut bad = bytes.clone();
    damage(&mut bad, start, 30_000);
    let a = open(bad.clone());
    let asm = a.assess(&Quiet);
    assert_eq!(asm.health, Health::Repairable);
    assert!(asm.blocks_damaged >= 3);
    let (fixed, plan) = repair_and_reopen(bad);
    assert!(plan.lost_blocks.is_empty(), "lost {:?}", plan.lost_blocks);
    let a2 = open(fixed);
    assert!(a2.assess(&Quiet).is_healthy());
    assert_contents(&a2, &files);
}

#[test]
fn extract_heals_in_memory_without_repair() {
    let files = corpus();
    let bytes = build(&files, small_opts());
    let a = open(bytes.clone());
    let mut bad = bytes;
    damage(&mut bad, a.index.blocks[3].offset as usize + 60, 12_000);
    let a = open(bad);
    assert_contents(&a, &files);
    assert!(a.healed_groups() > 0);
}

#[test]
fn single_bit_flip_costs_one_symbol() {
    let bytes = build(&corpus(), small_opts());
    let a = open(bytes.clone());
    let b = &a.index.blocks[5];
    let mut bad = bytes;
    bad[b.offset as usize + 56 + (4 * 16 + 4) + 700] ^= 0x10;
    let a = open(bad);
    let h = a.check_block(5);
    assert!(!h.hash_ok);
    assert_eq!(h.bad_symbols, vec![1]);
}

#[test]
fn beyond_budget_reports_lost_files() {
    let files = corpus();
    let mut o = small_opts();
    o.protect = Protect::LOW;
    let bytes = build(&files, o);
    let a = open(bytes.clone());
    // wipe half the data region
    let from = a.index.blocks[0].offset as usize;
    let to = a.index.blocks[a.index.blocks.len() / 2].offset as usize;
    let mut bad = bytes;
    for b in &mut bad[from..to] {
        *b = 0;
    }
    let a = open(bad);
    let asm = a.assess(&Quiet);
    assert_eq!(asm.health, Health::Damaged);
    let plan = a.plan_repair(&asm, None, &Quiet);
    assert!(!plan.lost_files.is_empty());
    // files stored after the wiped region still extract
    let f = a.visible_files(None).into_iter().find(|f| f.path == "tiny.txt").unwrap();
    assert_eq!(a.read_file(f).unwrap(), b"hi");
    let first = a.visible_files(None).into_iter().find(|f| f.path == "docs/file0.txt").unwrap();
    assert!(matches!(a.read_file(first), Err(Error::BlockLost(_))));
}

#[test]
fn index_fallbacks_all_work() {
    let files = corpus();
    let mut o = small_opts();
    o.set_bytes = 64 * 1024; // several checkpoints
    let bytes = build(&files, o);
    let n = bytes.len();

    // 1: primary footer gone -> mirror
    let mut b1 = bytes.clone();
    b1[n - 128..n - 64].fill(0);
    let a = open(b1);
    assert_eq!(a.opened_via, OpenPath::MirrorFooter);
    assert_contents(&a, &files);

    // 2: both footers gone -> backward scan
    let mut b2 = bytes.clone();
    b2[n - 128..].fill(0);
    let a = open(b2.clone());
    assert_eq!(a.opened_via, OpenPath::ScanBackward);

    // 3: all index segments destroyed too -> full scan, still readable
    let a0 = open(bytes.clone());
    let _ = a0;
    let mut b3 = b2;
    let mut at = 0usize;
    while at + 8 < b3.len() {
        if b3[at..at + 8] == rqz_core::format::SYNC && b3[at + 8] == rqz_core::format::kind::INDEX {
            b3[at + 60] ^= 0xFF; // corrupt the payload so its hash fails
            at += 100;
        } else {
            at += 1;
        }
    }
    let a = open(b3.clone());
    assert_eq!(a.opened_via, OpenPath::FullScan);
    assert_contents(&a, &files);
    assert!(a.assess(&Quiet).health >= Health::Repairable);

    // repair rebuilds a clean footer + index
    let (fixed, _) = repair_and_reopen(b3);
    let a = open(fixed);
    assert_eq!(a.opened_via, OpenPath::Footer);
    assert!(a.assess(&Quiet).is_healthy());
    assert_contents(&a, &files);
}

#[test]
fn header_mirror_and_repair() {
    let files = corpus();
    let bytes = build(&files, small_opts());
    let mut bad = bytes.clone();
    bad[..4096].fill(0);
    let a = open(bad.clone());
    assert!(a.notes.iter().any(|n| n.contains("header")));
    let (fixed, plan) = repair_and_reopen(bad);
    assert!(plan.structural_fixed >= 1);
    assert_eq!(fixed[..4096], bytes[..4096]);
}

#[test]
fn encryption_roundtrip_and_password_free_repair() {
    let files = corpus();
    let mut o = small_opts();
    o.password = Some("hunter2".into());
    let bytes = build(&files, o);
    assert!(matches!(Archive::open(bytes.clone(), Some("nope")), Err(Error::WrongPassword)));
    let locked = Archive::open(bytes.clone(), None).unwrap();
    assert!(locked.locked && locked.index.files.is_empty());
    assert!(locked.assess(&Quiet).is_healthy());
    assert!(!bytes.windows(10).any(|w| w == b"alpha alph"), "plaintext must not appear on disk");

    let start = locked.index.blocks[4].offset as usize + 80;
    let mut bad = bytes;
    damage(&mut bad, start, 20_000);
    // repair with no password at all
    let (fixed, plan) = repair_and_reopen(bad);
    assert!(plan.lost_blocks.is_empty());
    let a = Archive::open(fixed, Some("hunter2")).unwrap();
    assert!(a.assess(&Quiet).is_healthy());
    assert_contents(&a, &files);
}

#[test]
fn append_creates_snapshots() {
    let files = corpus();
    let bytes = build(&files, small_opts());
    let a = open(bytes.clone());
    let mut w = ArchiveWriter::append(Cursor::new(bytes.clone()), &a, small_opts(), &Quiet).unwrap();
    // Cursor starts at position 0 but the writer seeks explicitly.
    w.add_bytes("docs/file0.txt", 0o644, 0, b"replaced").unwrap();
    w.add_bytes("new.txt", 0o644, 0, &text(7, 30_000)).unwrap();
    let out = w.finish().unwrap().0.into_inner();
    let a2 = open(out);
    assert!(a2.assess(&Quiet).is_healthy());
    assert_eq!(a2.index.snapshots.len(), 2);
    let latest = a2.visible_files(None).into_iter().find(|f| f.path == "docs/file0.txt").unwrap();
    assert_eq!(a2.read_file(latest).unwrap(), b"replaced");
    let old = a2.visible_files(Some(1)).into_iter().find(|f| f.path == "docs/file0.txt").unwrap();
    assert_eq!(a2.read_file(old).unwrap(), files[0].1);
    assert!(a2.visible_files(Some(1)).iter().all(|f| f.path != "new.txt"));
}

#[test]
fn detached_sidecar_repairs_target() {
    let target = noise(5, 700_000);
    let mut o = small_opts();
    o.block_size = 65536;
    o.target_k = 1000;
    let w = ArchiveWriter::create_detached(Cursor::new(Vec::new()), o, target.clone(), "data.bin", &Quiet).unwrap();
    let side = w.finish().unwrap().0.into_inner();

    let mut bad = target.clone();
    damage(&mut bad, 150_000, 30_000);
    let mut a = Archive::open(side, None).unwrap();
    a.attach_target(Box::new(bad.clone()));
    let asm = a.assess(&Quiet);
    assert_eq!(asm.health, Health::Repairable);
    let plan = a.plan_repair(&asm, None, &Quiet);
    assert!(plan.lost_blocks.is_empty());
    apply_patches_to_vec(&mut bad, &plan.target_patches);
    assert_eq!(bad, target);
}

#[test]
fn tiny_profile_survives_a_bad_sector() {
    let files = vec![("note.txt".to_string(), text(1, 10_000))];
    let mut o = PackOptions::default();
    o.total_hint = Some(10_000);
    let bytes = build(&files, o);
    let a = open(bytes.clone());
    let info = a.info();
    assert!(info.tiny_profile);
    assert_eq!(a.header.header_len, 512);
    assert!(info.weak_protection.is_some(), "tiny archives should say protection is weak");
    let b = &a.index.blocks[0];
    let mut bad = bytes;
    damage(&mut bad, b.offset as usize + 56 + (4 * 10 + 4) + 1024, 1024);
    let (fixed, plan) = repair_and_reopen(bad);
    assert!(plan.lost_blocks.is_empty());
    assert_contents(&open(fixed), &files);
}

#[test]
fn second_copy_donates_blocks() {
    let files = corpus();
    let mut o = small_opts();
    o.protect = Protect::NONE;
    let bytes = build(&files, o);
    let donor = open(bytes.clone());
    let mut bad = bytes;
    let off = donor.index.blocks[6].offset as usize;
    damage(&mut bad, off + 100, 500);
    let a = open(bad.clone());
    let asm = a.assess(&Quiet);
    assert_eq!(asm.health, Health::Damaged);
    let plan = a.plan_repair(&asm, Some(&donor), &Quiet);
    assert!(plan.lost_blocks.is_empty());
    apply_patches_to_vec(&mut bad, &plan.patches);
    assert_contents(&open(bad), &files);
}

#[test]
fn add_protection_raises_headroom() {
    let files = corpus();
    let mut o = small_opts();
    o.protect = Protect::LOW;
    let bytes = build(&files, o);
    let a = open(bytes.clone());
    let before = a.info().recovery_bytes;
    let mut w = ArchiveWriter::append(Cursor::new(bytes), &a, small_opts(), &Quiet).unwrap();
    let added = w.add_protection(Protect::NORMAL).unwrap();
    assert!(added > 0);
    let out = w.finish().unwrap().0.into_inner();
    let a2 = open(out);
    assert!(a2.info().recovery_bytes > before);
    assert!(a2.assess(&Quiet).is_healthy());
}

#[test]
fn damaged_recovery_symbols_are_regenerated() {
    let files = corpus();
    let bytes = build(&files, small_opts());
    let a = open(bytes.clone());
    let first_rec = a.index.regions[0].offset as usize;
    let mut bad = bytes;
    damage(&mut bad, first_rec, 20_000);
    let a = open(bad.clone());
    let asm = a.assess(&Quiet);
    assert_eq!(asm.health, Health::Repairable);
    let (fixed, plan) = repair_and_reopen(bad);
    assert!(plan.recovery_regenerated > 0);
    assert!(open(fixed).assess(&Quiet).is_healthy());
}

#[test]
fn random_damage_within_budget() {
    let files = corpus();
    let bytes = build(&files, small_opts());
    for seed in 0..6u64 {
        let mut r = rng(seed + 100);
        let mut bad = bytes.clone();
        let a = open(bytes.clone());
        let end = a.index.blocks.last().unwrap().offset as usize;
        for _ in 0..8 {
            let at = 4096 * 2 + (r() as usize % (end - 8192));
            let len = 1 + (r() as usize % 700);
            damage(&mut bad, at, len);
        }
        let (fixed, plan) = repair_and_reopen(bad);
        assert!(plan.lost_blocks.is_empty(), "seed {seed}");
        let a2 = open(fixed);
        assert!(a2.assess(&Quiet).is_healthy(), "seed {seed}");
        assert_contents(&a2, &files);
    }
}

#[test]
fn compression_modes_roundtrip() {
    let files = corpus();
    for c in [Compression::None, Compression::Fast, Compression::Normal, Compression::Max] {
        let mut o = small_opts();
        o.compression = c;
        let a = open(build(&files, o));
        assert_contents(&a, &files);
    }
}

#[test]
fn manifest_is_sha256sum_format() {
    let files = vec![("a.txt".to_string(), b"abc".to_vec())];
    let a = open(build(&files, small_opts()));
    let mut out = Vec::new();
    a.manifest(None, &mut out).unwrap();
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad  a.txt\n"
    );
}

#[test]
fn deterministic_output_is_identical() {
    let files = corpus();
    let mut o = small_opts();
    o.deterministic = true;
    assert_eq!(build(&files, o.clone()), build(&files, o));
}
