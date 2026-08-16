#!/usr/bin/env node
import { createHash } from "node:crypto";
import { writeFileSync } from "node:fs";
import { join } from "node:path";

const argv = process.argv.slice(2);
let body = "";

function emit() {
  const command = argv[argv.indexOf("--enable-commands-exact") + 1];
  const outputs = {
    "calendar.events": [{ id: "event-1", summary: "Review", start: { dateTime: "2026-08-15T15:00:00Z" }, end: { dateTime: "2026-08-15T15:30:00Z" } }],
    "calendar.create": { id: "event-created", summary: "Approved event", start: { dateTime: "2026-08-15T15:00:00Z" }, end: { dateTime: "2026-08-15T15:30:00Z" } },
    "calendar.update": { id: "event-updated", summary: "Approved event" },
    "calendar.delete": { deleted: true, calendarId: "primary", eventId: "event-deleted" },
    "gmail.messages.search": [{ id: "msg_123", threadId: "thread_123", subject: "Review", labels: ["INBOX"] }],
    "gmail.get": { id: "msg_456", threadId: "thread_456", headers: { subject: "Review" }, body: "Sanitized body" },
    "gmail.send": { messageId: "sent_123", threadId: "thread_123" },
  };
  writeFileSync(join(process.env.GOG_HOME, "fake-gog-invocation.json"), JSON.stringify({ argv, envKeys: Object.keys(process.env).sort(), hasToken: Boolean(process.env.GOG_ACCESS_TOKEN), bodyLength: body.length, bodyDigest: createHash("sha256").update(body).digest("hex") }), { mode: 0o600 });
  process.stdout.write(JSON.stringify(outputs[command]));
}

if (argv.includes("--body-file")) {
  process.stdin.setEncoding("utf8");
  process.stdin.on("data", (chunk) => { body += chunk; });
  process.stdin.on("end", emit);
} else {
  emit();
}
