use rqz_core::archive::{Archive, Health};
use rqz_core::fsops::{self, RepairOptions, Source};
use rqz_core::progress::Quiet;
use rqz_core::writer::{PackOptions, Protect};
use std::fs;

#[test]
fn duplicate_basenames_and_existing_destinations_preserve_inputs() {
    let t = tempfile::tempdir().unwrap();
    let root = t.path();
    let a = root.join("a");
    let b = root.join("b");
    fs::create_dir(&a).unwrap();
    fs::create_dir(&b).unwrap();
    let first = a.join("same.txt");
    let second = b.join("same.txt");
    fs::write(&first, b"one").unwrap();
    fs::write(&second, b"two").unwrap();
    let out = root.join("out.rqz");
    assert!(fsops::pack_paths(&[first.clone(), second], &out, PackOptions::default(), true, &Quiet).is_err());
    assert!(!out.exists());
    assert!(fsops::pack_paths(std::slice::from_ref(&first), &first, PackOptions::default(), true, &Quiet).is_err());
    assert_eq!(fs::read(&first).unwrap(), b"one");

    fsops::pack_paths(&[first], &out, PackOptions::default(), true, &Quiet).unwrap();
    let mut data = fs::read(&out).unwrap();
    data[100] ^= 1;
    fs::write(&out, &data).unwrap();
    let alias = root.join("alias.rqz");
    fs::hard_link(&out, &alias).unwrap();
    assert!(
        fsops::repair_file(&out, &RepairOptions { out: Some(alias.clone()), ..Default::default() }, &Quiet).is_err()
    );
    assert_eq!(fs::read(alias).unwrap(), data);
    assert_eq!(fs::read(out).unwrap(), data);
}

#[test]
fn sidecar_respects_target_output_and_verifies_both_outputs() {
    let t = tempfile::tempdir().unwrap();
    let original = (0..64_000).map(|n| n as u8).collect::<Vec<_>>();
    let target = t.path().join("target.bin");
    let side = fsops::sidecar_path(&target);
    fs::write(&target, &original).unwrap();
    fsops::protect_file(&target, &side, PackOptions::default(), true, &Quiet).unwrap();
    let mut bad_target = original.clone();
    bad_target[1100] ^= 1;
    fs::write(&target, &bad_target).unwrap();
    let mut bad_side = fs::read(&side).unwrap();
    bad_side[100] ^= 1;
    fs::write(&side, &bad_side).unwrap();
    let out = t.path().join("choose.bin");
    let report =
        fsops::repair_file(&side, &RepairOptions { out: Some(out.clone()), ..Default::default() }, &Quiet).unwrap();
    assert_eq!(report.after, Health::Healthy);
    assert_eq!(report.outputs.len(), 2);
    assert_eq!(fs::read(&out).unwrap(), original);
    let (fixed, discovered) = fsops::open_any(&fsops::sidecar_path(&out), None, None).unwrap();
    assert_eq!(discovered, Some(out));
    assert!(fixed.assess(&Quiet).is_healthy());
    assert_eq!(fs::read(target).unwrap(), bad_target);
    assert_eq!(fs::read(side).unwrap(), bad_side);
}

#[test]
fn top_up_protects_an_unprotected_archive_without_a_snapshot() {
    let t = tempfile::tempdir().unwrap();
    let path = t.path().join("test.rqz");
    let src = t.path().join("input");
    fs::write(&src, b"some data").unwrap();
    let opts = PackOptions { protect: Protect::NONE, ..PackOptions::default() };
    fsops::pack_paths(&[src], &path, opts, true, &Quiet).unwrap();
    assert!(fsops::add_protection_file(&path, Protect::NORMAL, None, &Quiet).unwrap() > 0);
    let a = Archive::open(Source::open(&path).unwrap(), None).unwrap();
    assert_eq!(a.info().snapshots.len(), 1);
    assert!(a.info().recovery_bytes > 0);
    assert!(a.assess(&Quiet).is_healthy());
}

#[test]
fn extract_preserves_existing_files() {
    let t = tempfile::tempdir().unwrap();
    let input = t.path().join("input");
    let out = t.path().join("archive.rqz");
    let dest = t.path().join("restore");
    fs::write(&input, b"contents").unwrap();
    fsops::pack_paths(&[input], &out, PackOptions::default(), true, &Quiet).unwrap();
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("input"), b"keep this").unwrap();
    let a = Archive::open(Source::open(&out).unwrap(), None).unwrap();
    let report = fsops::extract_archive(&a, &dest, &[], None, &Quiet).unwrap();
    assert_eq!(report.skipped.len(), 1);
    assert_eq!(fs::read(dest.join("input")).unwrap(), b"keep this");
    #[cfg(unix)]
    {
        fs::remove_file(dest.join("input")).unwrap();
        let outside = t.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        std::os::unix::fs::symlink(&outside, dest.join("input")).unwrap();
        let report = fsops::extract_archive(&a, &dest, &[], None, &Quiet).unwrap();
        assert_eq!(report.skipped.len(), 1);
        assert_eq!(fs::read(outside).unwrap(), b"outside");
    }
}
