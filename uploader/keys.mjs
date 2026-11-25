// Tenant and key management for a ZeppBridge Cloud site. Runs on Windows, macOS and Linux.
//
//   node uploader/keys.mjs init [--label <name>] [--local]
//       Create a tenant. Prints one line of JSON {tenant, dk, writeKey, readKey} to stdout.
//       Paste that whole line into ZeppBridge as the connection code; readKey is the
//       read-only key for your phone or Personal Agent.
//   node uploader/keys.mjs add-reader --label <name> [--local]      stdin: {"dk","writeKey"}
//       Issue one more read-only key. Prints {readKey}.
//   node uploader/keys.mjs revoke-reader --label <name> [--local]   stdin: {"writeKey"}
//       Delete that reader record; its read-only key stops working at once.
//
// Keys are written to stdout only. They are never printed to stderr, logged or saved to disk.
// The only local file is readers.json (labels and key hashes, no keys) in the state folder:
//   Windows %LOCALAPPDATA%\ZeppBridgeCloud, macOS ~/Library/Application Support/ZeppBridgeCloud,
//   Linux $XDG_STATE_HOME/zeppbridge-cloud (default ~/.local/state/zeppbridge-cloud).
//   Override with --state-dir <path>.
// --local writes into `wrangler dev`'s local storage (worker/.wrangler) for testing.
//
// Records are written straight to your KV namespace or R2 bucket through Wrangler, so
// run `npx wrangler login` first. The Worker itself never changes these records.

import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { b64url, fromB64url, newKey, newTenantId, parseKey, randomBytes, sha256Hex, wrapDataKey } from "../shared/crypto.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
const workerDir = resolve(here, "../worker");

// Throw instead of exiting, so the `finally` that deletes the temp file still runs.
class KeysError extends Error {}
function fail(message) {
  throw new KeysError(message);
}

// Wrangler: ZEPPBRIDGE_WRANGLER (path to wrangler.js), else the copy `npm ci` installed here.
const wranglerJs = [process.env.ZEPPBRIDGE_WRANGLER, resolve(here, "../node_modules/wrangler/bin/wrangler.js")]
  .filter(Boolean)
  .find((path) => existsSync(path));

function defaultStateDir() {
  if (process.platform === "win32") return join(process.env.LOCALAPPDATA ?? join(homedir(), "AppData", "Local"), "ZeppBridgeCloud");
  if (process.platform === "darwin") return join(homedir(), "Library", "Application Support", "ZeppBridgeCloud");
  return join(process.env.XDG_STATE_HOME || join(homedir(), ".local", "state"), "zeppbridge-cloud");
}

const [command, ...rest] = process.argv.slice(2);
const flag = (name) => {
  const index = rest.indexOf(name);
  return index >= 0 ? rest[index + 1] : undefined;
};
const local = rest.includes("--local");
const label = flag("--label");
const stateDir = resolve(flag("--state-dir") ?? defaultStateDir());
const readersPath = join(stateDir, "readers.json");

// Same choice as the Worker: an R2 binding wins, otherwise KV (binding STORE).
const config = readFileSync(join(workerDir, "wrangler.jsonc"), "utf8").replace(/^\s*\/\/.*$/gm, "");
const bucket = /"r2_buckets"[\s\S]*?"bucket_name"\s*:\s*"([^"]+)"/.exec(config)?.[1];

function wrangler(argv) {
  if (!wranglerJs) fail("Wrangler not found. Run `npm install` in this folder, or set ZEPPBRIDGE_WRANGLER to wrangler.js.");
  const target = local ? ["--local", "--persist-to", ".wrangler/state"] : ["--remote"];
  const result = spawnSync(process.execPath, [wranglerJs, ...argv, ...target], {
    cwd: workerDir,
    encoding: "utf8",
    windowsHide: true,
  });
  // Wrangler's own output never contains the keys (they travel in a temp file), so it is safe to show.
  if (result.status !== 0) fail(`wrangler ${argv.slice(0, 3).join(" ")} failed:\n${result.stderr}\n${result.stdout}`);
}

function putObject(key, text) {
  mkdirSync(stateDir, { recursive: true });
  const tmp = join(stateDir, `put-${process.pid}.tmp`);
  writeFileSync(tmp, text, { mode: 0o600 });
  try {
    wrangler(bucket ? ["r2", "object", "put", `${bucket}/${key}`, "--file", tmp] : ["kv", "key", "put", key, "--path", tmp, "--binding", "STORE"]);
  } finally {
    rmSync(tmp, { force: true });
  }
}

function deleteObject(key) {
  wrangler(bucket ? ["r2", "object", "delete", `${bucket}/${key}`] : ["kv", "key", "delete", key, "--binding", "STORE"]);
}

const readers = () => (existsSync(readersPath) ? JSON.parse(readFileSync(readersPath, "utf8")) : []);
const saveReaders = (list) => {
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(readersPath, JSON.stringify(list, null, 1));
};

async function addReader(tenant, dk, name) {
  const readKey = newKey("read", tenant);
  const hash = await sha256Hex(readKey);
  putObject(`t/${tenant}/readers/${hash}`, JSON.stringify(await wrapDataKey(dk, readKey, tenant, hash, name)));
  saveReaders([...readers().filter((r) => r.label !== name), { label: name, hash, created_at: new Date().toISOString() }]);
  return readKey;
}

const stdinJson = () => {
  try {
    return JSON.parse(readFileSync(0, "utf8"));
  } catch {
    return fail("expected JSON on stdin");
  }
};

async function main() {
  if (command === "init") {
    const tenant = newTenantId();
    const dk = randomBytes(32);
    const writeKey = newKey("write", tenant);
    putObject(`t/${tenant}/writer`, await sha256Hex(writeKey));
    const readKey = await addReader(tenant, dk, label ?? "agent");
    process.stdout.write(`${JSON.stringify({ tenant, dk: b64url(dk), writeKey, readKey })}\n`);
  } else if (command === "add-reader" || command === "revoke-reader") {
    if (!label) fail("--label is required");
    const secrets = stdinJson();
    const parsed = parseKey(secrets.writeKey);
    if (!parsed || parsed.kind !== "write") fail("writeKey is missing or malformed");
    if (command === "add-reader") {
      const readKey = await addReader(parsed.tenant, fromB64url(secrets.dk), label);
      process.stdout.write(`${JSON.stringify({ readKey })}\n`);
    } else {
      const target = readers().find((r) => r.label === label);
      if (!target) fail(`no reader labelled ${label} in ${readersPath}`);
      deleteObject(`t/${parsed.tenant}/readers/${target.hash}`);
      saveReaders(readers().filter((r) => r.label !== label));
      process.stdout.write(`${JSON.stringify({ revoked: label })}\n`);
    }
  } else {
    console.error("usage: node uploader/keys.mjs init | add-reader | revoke-reader [--label <name>] [--local] [--state-dir <path>]");
    process.exitCode = 2;
  }
}

try {
  await main();
} catch (error) {
  // Only our own messages are printed; they never contain a key.
  console.error(`keys.mjs: ${error instanceof KeysError ? error.message : "unexpected error"}`);
  if (!(error instanceof KeysError) && process.env.ZEPPBRIDGE_DEBUG) console.error(error);
  process.exitCode = 1;
}
