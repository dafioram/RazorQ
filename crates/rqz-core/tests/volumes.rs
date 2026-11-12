use rqz_core::archive::*;
use rqz_core::fsops::{self, Source};
use rqz_core::progress::Quiet;
use rqz_core::volume::*;
use rqz_core::writer::*;
use std::fs;
use std::path::{Path, PathBuf};

fn text(seed: u64, n: usize) -> Vec<u8> {
    let words = ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf"];
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    let mut v = Vec::new();
    while v.len() < n {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        v.extend_from_slice(words[(s % 7) as usize].as_bytes());
        v.push(b' ');
    }
    v.truncate(n);
    v
}

fn noise(seed: u64, n: usize) -> Vec<u8> {
    let mut s = seed.wrapping_mul(0x9E3779B97F4A7C15) | 1;
    (0..n)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            s as u8
        })
        .collect()
}

/// Make an input folder (~1.1 MB, mixed text and noise).
fn make_input(root: &Path) -> PathBuf {
    let d = root.join("input");
    fs::create_dir_all(d.join("sub")).unwrap();
    for i in 0..10 {
        fs::write(d.join(format!("doc{i}.txt")), text(i, 30_000 + i as usize * 9_000)).unwrap();
    }
    for i in 0..4 {
        fs::write(d.join("sub").join(format!("img{i}.jpg")), noise(50 + i, 120_000)).unwrap();
    }
    d
}

fn split_opts(volume: u64, survive: u32) -> PackOptions {
    PackOptions {
        block_size: 16 * 1024,
        symbol_size: Some(512),
        target_k: 256,
        volume_size: volume,
        survive_volumes: survive,
        protect: Protect::LOW,
        ..PackOptions::default()
    }
}

fn pack(root: &Path, volume: u64, survive: u32) -> (PathBuf, PackResult) {
    let input = make_input(root);
    let out = root.join("backup.rqz");
    let r = fsops::pack_paths(&[input], &out, split_opts(volume, survive), true, &Quiet).unwrap();
    (out, r)
}

use rqz_core::fsops::PackResult;

fn volume_paths(root: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = fs::read_dir(root)
        .unwrap()
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("backup.rqz."))
        .collect();
    v.sort();
    v
}

fn extract_and_compare(archive: &Path, root: &Path, tag: &str) {
    let a = Archive::open(Source::open(archive).unwrap(), None).unwrap();
    let dest = root.join(format!("out-{tag}"));
    let rep = fsops::extract_archive(&a, &dest, &[], None, &Quiet).unwrap();
    assert!(rep.lost.is_empty(), "lost: {:?}", rep.lost);
    let input = root.join("input");
    for e in walk(&input) {
        let rel = e.strip_prefix(root).unwrap();
        assert_eq!(fs::read(&e).unwrap(), fs::read(dest.join(rel)).unwrap(), "{rel:?}");
    }
}

fn walk(p: &Path) -> Vec<PathBuf> {
    let mut out = vec![];
    for e in fs::read_dir(p).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

fn assess_path(p: &Path) -> Assessment {
    Archive::open(Source::open(p).unwrap(), None).unwrap().assess(&Quiet)
}

#[test]
fn split_pack_roundtrips_and_is_healthy() {
    let t = tempfile::tempdir().unwrap();
    let (out, r) = pack(t.path(), 200_000, 1);
    assert!(r.summary.volumes >= 4, "expected several volumes, got {}", r.summary.volumes);
    let vols = volume_paths(t.path());
    assert_eq!(vols.len() as u32, r.summary.volumes);
    assert!(vols.iter().all(|v| fs::metadata(v).unwrap().len() <= 200_000));
    assert!(assess_path(&vols[0]).is_healthy());
    // any volume, or the bare name, opens the whole set
    assert!(assess_path(&vols[2]).is_healthy());
    assert!(assess_path(&out).is_healthy());
    extract_and_compare(&out, t.path(), "clean");
}

#[test]
fn any_single_missing_volume_is_recoverable() {
    let t = tempfile::tempdir().unwrap();
    let (out, r) = pack(t.path(), 200_000, 1);
    let n = r.summary.volumes as usize;
    for victim in 0..n {
        let dir = t.path().join(format!("case{victim}"));
        fs::create_dir_all(&dir).unwrap();
        for (i, v) in volume_paths(t.path()).iter().enumerate() {
            if i != victim {
                fs::copy(v, dir.join(v.file_name().unwrap())).unwrap();
            }
        }
        let first = dir.join("backup.rqz.001");
        let probe = if first.exists() { first } else { dir.join("backup.rqz.002") };
        let a = Archive::open(Source::open(&probe).unwrap(), None).unwrap();
        let asm = a.assess(&Quiet);
        assert!(asm.health >= Health::Repairable, "volume {victim}: missing volume must be noticed");
        assert!(a.notes.iter().any(|n| n.contains("missing")), "volume {victim}: {:?}", a.notes);
        drop(a);

        // repair into a fresh directory; the originals stay untouched
        let opts = fsops::RepairOptions { out: Some(dir.join("fixed")), ..Default::default() };
        let rep = fsops::repair_file(&probe, &opts, &Quiet).unwrap();
        assert!(rep.plan.lost_blocks.is_empty(), "volume {victim}: lost {:?}", rep.plan.lost_files);
        let fixed = dir.join("fixed").join("backup.rqz.001");
        assert!(fixed.exists(), "volume {victim}: repaired set has a first volume");
        let all: Vec<_> = fs::read_dir(dir.join("fixed")).unwrap().collect();
        assert!(all.len() >= n - 1, "volume {victim}: repaired set is complete ({} files)", all.len());
        assert!(assess_path(&fixed).is_healthy(), "volume {victim}: repaired set verifies");
        extract_and_compare(&fixed, t.path(), &format!("v{victim}"));
    }
    drop(out);
}

#[test]
fn missing_volume_extracts_without_repair() {
    let t = tempfile::tempdir().unwrap();
    let (_, _) = pack(t.path(), 200_000, 1);
    fs::remove_file(t.path().join("backup.rqz.002")).unwrap();
    // extraction heals in memory straight from the incomplete set
    extract_and_compare(&t.path().join("backup.rqz.001"), t.path(), "mem");
}

#[test]
fn two_missing_volumes_with_survive_two() {
    let t = tempfile::tempdir().unwrap();
    let (_, r) = pack(t.path(), 150_000, 2);
    assert!(r.summary.volumes >= 6);
    fs::remove_file(t.path().join("backup.rqz.002")).unwrap();
    fs::remove_file(t.path().join("backup.rqz.004")).unwrap();
    extract_and_compare(&t.path().join("backup.rqz.001"), t.path(), "two");
}

#[test]
fn damaged_bytes_inside_volumes_are_repaired() {
    let t = tempfile::tempdir().unwrap();
    pack(t.path(), 200_000, 1);
    let v = t.path().join("backup.rqz.002");
    let mut b = fs::read(&v).unwrap();
    for x in &mut b[5_000..9_000] {
        *x ^= 0xA5;
    }
    fs::write(&v, b).unwrap();
    let first = t.path().join("backup.rqz.001");
    assert_eq!(assess_path(&first).health, Health::Repairable);
    let opts = fsops::RepairOptions { out: Some(t.path().join("fixed")), ..Default::default() };
    let rep = fsops::repair_file(&first, &opts, &Quiet).unwrap();
    assert!(rep.plan.lost_blocks.is_empty());
    assert!(assess_path(&t.path().join("fixed").join("backup.rqz.001")).is_healthy());
}

#[test]
fn in_memory_volume_set_for_the_browser() {
    let t = tempfile::tempdir().unwrap();
    pack(t.path(), 200_000, 1);
    let vols: Vec<Vec<u8>> = volume_paths(t.path()).iter().map(|p| fs::read(p).unwrap()).collect();
    let n = vols.len();
    // drop volume 1 (header A and B live there; the volume headers carry copies)
    let rest: Vec<Vec<u8>> = vols.into_iter().skip(1).collect();
    let set = VolumeSet::from_bytes(rest).unwrap();
    assert_eq!(set.missing(), vec![0]);
    assert_eq!(set.count() as usize, n);
    let a = Archive::open(set, None).unwrap();
    assert!(a.assess(&Quiet).health >= Health::Repairable);
    assert!(a.visible_files(None).len() >= 14);
}

#[test]
fn volumes_must_belong_together() {
    let t = tempfile::tempdir().unwrap();
    pack(t.path(), 200_000, 1);
    let a = fs::read(t.path().join("backup.rqz.001")).unwrap();
    let t2 = tempfile::tempdir().unwrap();
    pack(t2.path(), 200_000, 1);
    let b = fs::read(t2.path().join("backup.rqz.002")).unwrap();
    assert!(VolumeSet::from_bytes(vec![a, b]).is_err());
}
