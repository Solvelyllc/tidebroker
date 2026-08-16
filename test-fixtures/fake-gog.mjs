#!/usr/bin/env node
import { createHash } from "node:crypto";

const argv = process.argv.slice(2);
let body = "";

function emit() {
  process.stdout.write(JSON.stringify({
    argv,
    envKeys: Object.keys(process.env).sort(),
    hasToken: Boolean(process.env.GOG_ACCESS_TOKEN),
    hasAccessToken: Boolean(process.env.GOG_ACCESS_TOKEN),
    access_token: process.env.GOG_ACCESS_TOKEN,
    refresh_token: "strip-me",
    nested: { client_secret: "strip-me", ok: true },
    items: [{ id: "event-1" }],
    bodyLength: body.length,
    bodyDigest: createHash("sha256").update(body).digest("hex"),
  }));
}

if (argv.includes("--body-file")) {
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => { body += chunk; });
  process.stdin.on("end", emit);
} else {
  emit();
}
