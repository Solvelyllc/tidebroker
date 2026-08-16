import { lstat, readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { execFileSync } from "node:child_process";

const path = process.env.TIDEBROKER_RELEASE_EVIDENCE_PATH;
const fail = () => { throw new Error("RELEASE_GATES_NOT_PROVEN"); };
if (!path || !isAbsolute(path)) fail();
const info = await lstat(path);
if (!info.isFile() || info.isSymbolicLink() || (info.mode & 0o077) !== 0 || typeof process.getuid === "function" && info.uid !== process.getuid() || info.size > 64 * 1024) fail();
let evidence;
try { evidence = JSON.parse(await readFile(path, "utf8")); } catch { fail(); }
const exact = (value, keys) => value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
const gate = (value) => exact(value, ["status", "verifiedAt", "evidenceSha256"]) && value.status === "passed" && typeof value.verifiedAt === "string" && !Number.isNaN(Date.parse(value.verifiedAt)) && /^[a-f0-9]{64}$/.test(value.evidenceSha256);
const head = execFileSync("git", ["rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }).trim();
const worktree = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
if (worktree.length !== 0) fail();
if (!exact(evidence, ["version", "sourceCommit", "osIsolation", "realProviderSmoke", "mcpQuarantine"]) || evidence.version !== 1 || evidence.sourceCommit !== head || !gate(evidence.osIsolation) || !gate(evidence.realProviderSmoke) || !gate(evidence.mcpQuarantine)) fail();
process.stdout.write("RELEASE_GATES_PROVEN\n");
