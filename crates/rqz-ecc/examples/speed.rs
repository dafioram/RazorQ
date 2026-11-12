//! Rough encode/decode throughput: `cargo run --release -p rqz-ecc --example speed`
use std::time::Instant;
fn main() {
    for (k, ss) in [(512usize, 4096u16), (2048, 4096), (8192, 4096), (12000, 4096)] {
        let src: Vec<u8> = (0..k * ss as usize).map(|i| (i.wrapping_mul(2654435761) >> 11) as u8).collect();
        let r = (k / 10) as u32;
        let t = Instant::now();
        let rep = rqz_ecc::encode_repair(&src, ss, 0, r);
        let enc = t.elapsed().as_secs_f64();
        let missing = r as usize - 2;
        let present: Vec<(u32, &[u8])> =
            (missing..k).map(|i| (i as u32, &src[i * ss as usize..(i + 1) * ss as usize])).collect();
        let reps: Vec<(u32, &[u8])> = rep.iter().map(|x| (x.esi, x.data.as_slice())).collect();
        let t = Instant::now();
        let out = rqz_ecc::decode(k, ss, &present, &reps).unwrap();
        let dec = t.elapsed().as_secs_f64();
        assert_eq!(out, src);
        let mb = (k * ss as usize) as f64 / 1e6;
        println!("K={k:>6} ({mb:>6.1} MB)  encode {:>7.1} MB/s  decode(10% erased) {:>7.1} MB/s", mb / enc, mb / dec);
    }
}
