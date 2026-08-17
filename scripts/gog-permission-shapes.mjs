#!/usr/bin/env node

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";

const maxDepth = 8;
const maxArrayItems = 10_000;
const maxStringBytes = 256 * 1024;

function plain(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}

function exactKeys(value, required, allowed) {
  const keys = Object.keys(value);
  const permitted = new Set(allowed);
  return required.every((key) => Object.hasOwn(value, key)) && keys.every((key) => permitted.has(key));
}

function bounded(value, depth = 0) {
  if (depth > maxDepth) return false;
  if (typeof value === "string") return Buffer.byteLength(value) <= maxStringBytes;
  if (value === null || ["boolean", "number"].includes(typeof value)) return true;
  if (Array.isArray(value)) return value.length <= maxArrayItems && value.every((item) => bounded(item, depth + 1));
  if (!plain(value) || Object.keys(value).length > 128) return false;
  return Object.values(value).every((item) => bounded(item, depth + 1));
}

function validateRecord(value, contract) {
  if (!plain(value) || !exactKeys(value, contract.requiredKeys, contract.allowedKeys)) return false;
  return Object.entries(value).every(([key, item]) => {
    const expected = contract.fieldTypes[key];
    if (expected === "array") return Array.isArray(item);
    if (expected === "object") return plain(item);
    if (expected === "null") return item === null;
    return typeof item === expected;
  });
}

function validateContractDefinition(contract) {
  if (!plain(contract) || !["array", "object"].includes(contract.rootType) || !Array.isArray(contract.requiredKeys) || !Array.isArray(contract.allowedKeys) || !plain(contract.fieldTypes)) return false;
  const keysValid = [...contract.requiredKeys, ...contract.allowedKeys].every((key) => typeof key === "string" && /^[A-Za-z][A-Za-z0-9_.]{0,127}$/.test(key));
  if (!keysValid || new Set(contract.allowedKeys).size !== contract.allowedKeys.length || contract.requiredKeys.some((key) => !contract.allowedKeys.includes(key))) return false;
  const fieldTypeKeys = Object.keys(contract.fieldTypes);
  if (fieldTypeKeys.length !== contract.allowedKeys.length || fieldTypeKeys.some((key) => !contract.allowedKeys.includes(key)) || contract.allowedKeys.some((key) => !fieldTypeKeys.includes(key)) || Object.values(contract.fieldTypes).some((type) => !["array", "boolean", "number", "null", "object", "string"].includes(type))) return false;
  if (contract.rootType === "array") {
    if (!Number.isSafeInteger(contract.maxItems) || contract.maxItems < 0 || contract.maxItems > maxArrayItems) return false;
  } else if (contract.maxItems !== undefined) return false;
  return true;
}

export async function loadGogPermissionShapeContracts(path) {
  const value = JSON.parse(await readFile(path, "utf8"));
  if (!plain(value) || value.version !== 1 || value.gogVersion !== "v0.37.0" || !plain(value.commands)) throw new Error("GOG_PERMISSION_SHAPE_MANIFEST_INVALID");
  const commands = new Map();
  for (const [command, contract] of Object.entries(value.commands)) {
    if (!/^[a-z][a-z0-9]{0,31}$/.test(command) || !validateContractDefinition(contract)) throw new Error("GOG_PERMISSION_SHAPE_MANIFEST_INVALID");
    commands.set(command, Object.freeze({ ...contract, requiredKeys: Object.freeze([...contract.requiredKeys]), allowedKeys: Object.freeze([...contract.allowedKeys]) }));
  }
  return Object.freeze({ version: 1, gogVersion: value.gogVersion, commands });
}

export function validateGogPermissionShape(manifest, command, value) {
  const contract = manifest.commands.get(command);
  if (!contract) return "unreviewed";
  if (!bounded(value)) return "invalid";
  if (contract.rootType === "array") {
    if (!Array.isArray(value) || value.length > contract.maxItems || value.some((item) => !validateRecord(item, contract))) return "invalid";
  } else if (!validateRecord(value, contract)) return "invalid";
  return "valid";
}

async function selfTest() {
  const validContract = Object.freeze({ rootType: "array", maxItems: 2, requiredKeys: ["id"], allowedKeys: ["id", "label"], fieldTypes: Object.freeze({ id: "string", label: "string" }) });
  const manifest = Object.freeze({ version: 1, gogVersion: "v0.37.0", commands: new Map([["example", validContract]]) });
  assert.equal(validateGogPermissionShape(manifest, "unknown", []), "unreviewed");
  assert.equal(validateGogPermissionShape(manifest, "example", [{ id: "one", label: "ok" }]), "valid");
  assert.equal(validateGogPermissionShape(manifest, "example", [{}]), "invalid");
  assert.equal(validateGogPermissionShape(manifest, "example", [{ id: "one", extra: true }]), "invalid");
  assert.equal(validateGogPermissionShape(manifest, "example", [{ id: false }]), "invalid");
  assert.equal(validateGogPermissionShape(manifest, "example", { id: "one" }), "invalid");
  assert.equal(validateGogPermissionShape(manifest, "example", [{ id: "one" }, { id: "two" }, { id: "three" }]), "invalid");
  assert.equal(validateGogPermissionShape(manifest, "example", [{ id: "x".repeat(maxStringBytes + 1) }]), "invalid");
  process.stdout.write("gog permission shape contracts fail closed\n");
}

if (process.argv[1] && import.meta.url === new URL(`file://${process.argv[1]}`).href) {
  if (process.argv.length !== 3 || process.argv[2] !== "--self-test") throw new Error("Usage: gog-permission-shapes.mjs --self-test");
  await selfTest();
}
