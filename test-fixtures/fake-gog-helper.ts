import { chmod, writeFile } from "node:fs/promises";
import { join } from "node:path";

export async function createFakeGog(root: string): Promise<string> {
  const executablePath = join(root, "fake-gog");
  const fixtureUrl = new URL("./fake-gog.mjs", import.meta.url).href;
  await writeFile(
    executablePath,
    `#!${process.execPath}\nimport(${JSON.stringify(fixtureUrl)});\n`,
    { mode: 0o700 },
  );
  await chmod(executablePath, 0o700);
  return executablePath;
}
