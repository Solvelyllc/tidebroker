import { chmod } from "node:fs/promises";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");

// npm-pack and non-npm artifact installers must be able to invoke the worker
// directly, without relying on npm to repair the bin entry's mode.
await chmod(resolve(root, "dist/worker/entry.js"), 0o755);
