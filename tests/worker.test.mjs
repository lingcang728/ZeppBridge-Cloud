// Worker 进程内测试：KV 换成内存版，写入口和给助手的只读接口各走一遍。
// （不起 wrangler dev：免得整机满载；Workers 专有的 timingSafeEqual 在这里补上。）
import assert from "node:assert/strict";
import test from "node:test";
import { gunzipSync, gzipSync } from "node:zlib";
import { b64url, encryptObject, newKey, newTenantId, objectKey, randomBytes, sha256Hex, wrapDataKey } from "../shared/crypto.mjs";

if (!crypto.subtle.timingSafeEqual) {
  crypto.subtle.timingSafeEqual = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
}
const { default: worker } = await import("../worker/src/index.js");

function memoryKv() {
  const map = new Map();
  return {
    map,
    get: async (key) => (map.has(key) ? map.get(key).slice().buffer : null),
    put: async (key, value) => map.set(key, new Uint8Array(typeof value === "string" ? new TextEncoder().encode(value) : value)),
    delete: async (key) => map.delete(key),
    list: async ({ prefix }) => ({ keys: [...map.keys()].filter((k) => k.startsWith(prefix)).map((name) => ({ name })) }),
  };
}

async function site() {
  const STORE = memoryKv();
  const tenant = newTenantId();
  const dk = randomBytes(32);
  const writeKey = newKey("write", tenant);
  const readKey = newKey("read", tenant);
  const hash = await sha256Hex(readKey);
  await STORE.put(`t/${tenant}/writer`, await sha256Hex(writeKey));
  await STORE.put(`t/${tenant}/readers/${hash}`, JSON.stringify(await wrapDataKey(dk, readKey, tenant, hash, "test")));
  const call = (path, init = {}) => worker.fetch(new Request(`https://health.example.com${path}`, init), { STORE }, { waitUntil() {} });
  return { STORE, tenant, dk, writeKey, readKey, call };
}

test("写入密钥能放摘要和契约，只读密钥能读回原文", async () => {
  const s = await site();
  const summary = { schema: "zeppbridge-cloud.summary/1", days: [{ date: "2026-11-09", metrics: { steps: null } }] };
  const sealed = await encryptObject(s.dk, objectKey(s.tenant, "summary.json"), gzipSync(JSON.stringify(summary)));
  const put = await s.call("/v1/objects/summary.json", {
    method: "PUT",
    headers: { authorization: `Bearer ${s.writeKey}`, "content-length": String(sealed.length) },
    body: sealed,
  });
  assert.equal(put.status, 200);

  const read = await s.call("/v1/summary", { headers: { authorization: `Bearer ${s.readKey}` } });
  assert.equal(read.status, 200);
  assert.equal(read.headers.get("content-encoding"), "gzip");
  assert.deepEqual(JSON.parse(gunzipSync(Buffer.from(await read.arrayBuffer())).toString()), summary);

  const missing = await s.call("/v1/contract", { headers: { authorization: `Bearer ${s.readKey}` } });
  assert.equal(missing.status, 404);
});

test("GET /v1 是给助手的接口目录，没有密钥一律 401", async () => {
  const s = await site();
  const index = await s.call("/v1", { headers: { authorization: `Bearer ${s.readKey}` } });
  assert.equal(index.status, 200);
  const body = await index.json();
  assert.ok(body.routes["/v1/summary"] && body.routes["/v1/contract"]);
  assert.equal((await s.call("/v1")).status, 401);
  assert.equal((await s.call("/v1", { headers: { authorization: `Bearer ${s.writeKey}` } })).status, 401);
  assert.equal((await s.call("/v1/summary")).status, 401);
});

test("只读密钥写不了，写入密钥碰不到读者和写入者记录", async () => {
  const s = await site();
  const body = new Uint8Array(8);
  const headers = (key) => ({ authorization: `Bearer ${key}`, "content-length": "8" });
  assert.equal((await s.call("/v1/objects/summary.json", { method: "PUT", headers: headers(s.readKey), body })).status, 401);
  const before = [...s.STORE.map.keys()].sort();
  // URL 解析会先把 ..（含 %2e%2e）化掉，那种请求落到 /v1/<x> 变成 405；无论哪种，存储都不能多出东西。
  for (const rel of ["writer", "readers/x.json", "live.json", "%2e%2e/x.json", "days/../writer.json", "days/2026-11-09.json/../../writer"]) {
    const res = await s.call(`/v1/objects/${rel}`, { method: "PUT", headers: headers(s.writeKey), body });
    assert.ok(res.status === 404 || res.status === 405, `${rel} → ${res.status}`);
  }
  assert.deepEqual([...s.STORE.map.keys()].sort(), before);
  assert.equal((await s.call("/v1/summary", { method: "POST", headers: headers(s.readKey) })).status, 405);
  assert.ok(b64url(new Uint8Array([1])));
});
