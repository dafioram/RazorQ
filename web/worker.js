// Keep WASM and archive reads off the page's main thread.
import init, * as rqz from "./pkg/rqz_wasm.js";

const ready = init();
let current = null;

function openArchive(candidate) {
  let result;
  try {
    result = {
      info: JSON.parse(candidate.info()),
      files: JSON.parse(candidate.files()),
      check: JSON.parse(candidate.check()),
    };
  } catch (error) {
    candidate.free();
    throw error;
  }
  current?.free();
  current = candidate;
  return result;
}

self.onmessage = async (e) => {
  const { id, op, args } = e.data;
  try {
    await ready;
    let result;
    let transfer = [];
    switch (op) {
      case "open":
        result = openArchive(new rqz.Rqz(args.bytes, args.password || undefined));
        break;
      case "openVolumes":
        result = openArchive(rqz.Rqz.open_volumes(args.parts, args.password || undefined));
        break;
      case "repair": {
        const report = JSON.parse(current.repair(args.donor || undefined));
        const volumes = current.repaired_volumes();
        const bytes = current.repaired_bytes();
        result = { report, volumes, bytes };
        transfer = volumes.length ? volumes.map((v) => v.buffer) : bytes ? [bytes.buffer] : [];
        break;
      }
      case "demoVolumes":
        result = rqz.demo_volumes();
        transfer = result.map((v) => v.buffer);
        break;
      case "read":
        result = current.read_file(args.path);
        transfer = [result.buffer];
        break;
      case "demo":
        result = rqz.demo_archive();
        transfer = [result.buffer];
        break;
      case "pack":
        result = rqz.pack(args.names, args.blobs, args.protect, args.compression, args.password || undefined);
        transfer = [result.buffer];
        break;
      case "version":
        result = rqz.version();
        break;
      default:
        throw new Error("unknown operation " + op);
    }
    self.postMessage({ id, ok: true, result }, transfer);
  } catch (error) {
    self.postMessage({ id, ok: false, error: String(error?.message || error) });
  }
};
