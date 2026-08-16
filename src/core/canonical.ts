import { createHash } from "node:crypto";

function canonical(value: unknown, depth = 0): string {
  if (depth > 24) throw new TypeError("CANONICAL_VALUE_INVALID");
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number" && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map((item) => canonical(item, depth + 1)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const keys = Object.keys(record).sort();
    if (Object.getPrototypeOf(value) !== Object.prototype && Object.getPrototypeOf(value) !== null) throw new TypeError("CANONICAL_VALUE_INVALID");
    return `{${keys.map((key) => `${JSON.stringify(key)}:${canonical(record[key], depth + 1)}`).join(",")}}`;
  }
  throw new TypeError("CANONICAL_VALUE_INVALID");
}

/** Stable digest used to bind an approval and signed worker grant to exact input. */
export function canonicalPayloadDigest(value: unknown): string {
  return createHash("sha256").update(canonical(value), "utf8").digest("base64url");
}
