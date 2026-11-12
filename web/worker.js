// Runs razerq (WASM) off the main thread so big archives don't freeze the page.
import init, * as rqz from "./pkg/rqz_wasm.js";

const ready = init();
let current = null;

self.onmessage = async (e) => {
  const { id, op, args } = e.data;
  try {
    await ready;
    let result;
    let transfer = [];
    switch (op) {
      case "open": {
        if (current) current.free();
        current = new rqz.Rqz(args.bytes, args.password || undefined);
        result = { info: JSON.parse(current.info()), files: JSON.parse(current.files()), check: JSON.parse(current.check()) };
        break;
      }
      case "openVolumes": {
        if (current) current.free();
        current = rqz.Rqz.open_volumes(args.parts, args.password || undefined);
        result = { info: JSON.parse(current.info()), files: JSON.parse(current.files()), check: JSON.parse(current.check()) };
        break;
      }
      case "repair": {
        const report = JSON.parse(current.repair(args.donor || undefined));
        const vols = current.repaired_volumes();
        if (vols.length) {
          result = { report, volumes: vols };
          transfer = vols.map((v) => v.buffer);
        } else {
          const bytes = current.repaired_bytes();
          result = { report, bytes };
          transfer = [bytes.buffer];
        }
        break;
      }
      case "demoVolumes": {
        result = rqz.demo_volumes();
        transfer = result.map((v) => v.buffer);
        break;
      }
      case "read": {
        result = current.read_file(args.path);
        transfer = [result.buffer];
        break;
      }
      case "demo": {
        result = rqz.demo_archive();
        transfer = [result.buffer];
        break;
      }
      case "pack": {
        const blobs = args.blobs.map((b) => new Uint8Array(b));
        result = rqz.pack(args.names, blobs, args.protect, args.compression, args.password || undefined);
        transfer = [result.buffer];
        break;
      }
      case "version":
        result = rqz.version();
        break;
      default:
        throw new Error("unknown operation " + op);
    }
    self.postMessage({ id, ok: true, result }, transfer);
  } catch (err) {
    self.postMessage({ id, ok: false, error: String((err && err.message) || err) });
  }
};
