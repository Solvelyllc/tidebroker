import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdir, open, readdir, readFile, writeFile } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const root = resolve(import.meta.dirname, "..");
function fail() { throw new Error("RELEASE_ARTIFACT_BUILD_FAILED"); }
const digest = (bytes) => createHash("sha256").update(bytes).digest("hex");

export async function buildReleaseArtifacts(outputDirectory) {
  if (typeof outputDirectory !== "string" || !isAbsolute(outputDirectory)) fail();
  await mkdir(outputDirectory, { mode: 0o700 }).catch(fail);
  if ((await readdir(outputDirectory)).length !== 0) fail();
  const packageJson = JSON.parse(await readFile(join(root, "package.json"), "utf8"));
  const sourceCommit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
  const worktree = execFileSync("git", ["status", "--porcelain=v1", "--untracked-files=all"], { cwd: root, encoding: "utf8" });
  if (worktree.length !== 0) fail();
  const releaseTag = `v${packageJson.version}`;
  const tags = execFileSync("git", ["tag", "--points-at", "HEAD"], { cwd: root, encoding: "utf8" }).trim().split("\n");
  if (!tags.includes(releaseTag)) fail();
  const packed = JSON.parse(execFileSync("npm", ["pack", "--json", "--ignore-scripts", "--pack-destination", outputDirectory], { cwd: root, encoding: "utf8" }));
  if (!Array.isArray(packed) || packed.length !== 1 || typeof packed[0]?.filename !== "string") fail();
  const tarballPath = join(outputDirectory, packed[0].filename);
  const sbomPath = join(outputDirectory, `tidebroker-${packageJson.version}.spdx.json`);
  const sbom = execFileSync("npm", ["sbom", "--sbom-format", "spdx", "--omit", "dev"], { cwd: root });
  await writeFile(sbomPath, sbom, { mode: 0o600, flag: "wx" });
  const artifacts = [];
  for (const path of [tarballPath, sbomPath]) {
    const bytes = await readFile(path);
    artifacts.push({ name: path.slice(outputDirectory.length + 1), sha256: digest(bytes), size: bytes.length });
  }
  const manifest = { version: 1, package: `${packageJson.name}@${packageJson.version}`, sourceCommit, artifacts };
  const manifestPath = join(outputDirectory, "release-manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600, flag: "wx" });
  const manifestBytes = await readFile(manifestPath);
  const checksums = [...artifacts, { name: "release-manifest.json", sha256: digest(manifestBytes) }]
    .sort((a, b) => a.name.localeCompare(b.name))
    .map((artifact) => `${artifact.sha256}  ${artifact.name}`)
    .join("\n");
  const checksumsPath = join(outputDirectory, "SHA256SUMS");
  const handle = await open(checksumsPath, "wx", 0o600).catch(fail);
  if (!handle) fail();
  try { await handle.writeFile(`${checksums}\n`, "utf8"); await handle.sync(); }
  finally { await handle.close(); }
  return Object.freeze({ outputDirectory, sourceCommit, artifacts: Object.freeze(artifacts) });
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    await buildReleaseArtifacts(process.argv[2]);
    process.stdout.write("RELEASE_ARTIFACTS_BUILT\n");
  } catch {
    process.stderr.write("RELEASE_ARTIFACT_BUILD_FAILED\n");
    process.exitCode = 1;
  }
}
