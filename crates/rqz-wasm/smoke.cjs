// Smoke test for the WASM build, run under Node:
//   wasm-pack build crates/rqz-wasm --target nodejs --out-dir pkg-node
//   node crates/rqz-wasm/smoke.cjs
const assert = require("assert");
const w = require("./pkg-node/rqz_wasm.js");

const demo = w.demo_archive();
let a = new w.Rqz(demo, undefined);
let check = JSON.parse(a.check());
assert.strictEqual(check.health, "healthy", "demo archive starts healthy");
const files = JSON.parse(a.files());
assert.ok(files.length >= 10);
const original = a.read_file(files[3].path);

// Damage ~5% in the middle of the data, like the web demo does.
const bad = demo.slice();
const start = Math.floor(bad.length * 0.18), len = Math.floor(bad.length * 0.05);
for (let i = start; i < start + len; i++) bad[i] ^= 0xa5;
a = new w.Rqz(bad, undefined);
check = JSON.parse(a.check());
assert.strictEqual(check.health, "repairable");
assert.ok(check.states.includes("a"), "map shows amber blocks");

// Extraction heals in memory without a repair step.
assert.deepStrictEqual(Buffer.from(a.read_file(files[3].path)), Buffer.from(original));

// Repair and re-verify.
const report = JSON.parse(a.repair(undefined));
assert.strictEqual(report.lost_blocks, 0);
const fixed = a.repaired_bytes();
const b = new w.Rqz(fixed, undefined);
assert.strictEqual(JSON.parse(b.check()).health, "healthy");
assert.deepStrictEqual(Buffer.from(fixed), Buffer.from(demo), "repair restores the exact original bytes");

// Create, encrypt, reopen.
const blobs = [new TextEncoder().encode("hello razerq ".repeat(5000)), new Uint8Array([1, 2, 3])];
const packed = w.pack(["a.txt", "b.bin"], blobs, 10, "normal", "pw");
assert.throws(() => new w.Rqz(packed, "wrong"));
const locked = new w.Rqz(packed, undefined);
assert.strictEqual(JSON.parse(locked.info()).locked, true);
assert.strictEqual(JSON.parse(locked.check()).health, "healthy");
const open = new w.Rqz(packed, "pw");
assert.strictEqual(Buffer.from(open.read_file("b.bin")).toString("hex"), "010203");
// Split volumes: lose any one volume (including the first), heal it, get the exact bytes back.
const vols = w.demo_volumes();
assert.ok(vols.length >= 5, "demo is split into several volumes");
const full = new w.Rqz(demo, undefined); // sanity: the single-file demo still opens
assert.strictEqual(JSON.parse(full.check()).health, "healthy");
const whole = w.Rqz.open_volumes(vols, undefined);
assert.strictEqual(JSON.parse(whole.check()).health, "healthy");
assert.strictEqual(JSON.parse(whole.info()).volumes, vols.length);
for (const victim of [0, 2, vols.length - 1]) {
  const rest = vols.filter((_, i) => i !== victim);
  const broken = w.Rqz.open_volumes(rest, undefined);
  const info = JSON.parse(broken.info());
  assert.deepStrictEqual(info.missing_volumes, [victim + 1]);
  const c = JSON.parse(broken.check());
  assert.ok(c.health !== "healthy", `volume ${victim + 1} missing must be noticed`);
  const names = JSON.parse(broken.files());
  assert.ok(names.length >= 10, "file names survive a lost volume");
  assert.ok(broken.read_file(names[4].path).length > 1000, "extraction heals in memory");
  const rep = JSON.parse(broken.repair(undefined));
  assert.strictEqual(rep.lost_blocks, 0, `volume ${victim + 1}: nothing lost`);
  const fixed = broken.repaired_volumes();
  assert.strictEqual(fixed.length, vols.length, "repaired set has every volume again");
  const again = w.Rqz.open_volumes(fixed, undefined);
  assert.strictEqual(JSON.parse(again.check()).health, "healthy", `volume ${victim + 1}: repaired set verifies`);
}
console.log("wasm smoke test passed:", w.version());
