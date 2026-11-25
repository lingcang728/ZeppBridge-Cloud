// ZeppBridge 云端中转：只存密文、只发文件，不替用户去 Zepp 拉任何东西。
//
// 读：只读密钥 → 找到读者记录 → 解开 DK → 解密对象 → 原样返回 gzip（不在 Worker 里解压，
// 逐秒大文件解压会贴着免费版 10 ms CPU 上限；不收 gzip 的客户端由运行时替它解）。
// 写：写入密钥只能 PUT / DELETE 白名单路径下的密文，读不了任何东西。
// 读者和写入者记录由电脑端 keys.mjs 直接写进存储，这个 Worker 永远不改它们。
//
// 浏览器仪表盘（public/）用同一套只读密钥：登录时贴一次，存进 HttpOnly Cookie。
// agent 照旧用 Authorization: Bearer。

import {
  decryptObject,
  fromB64url,
  importLivePrivate,
  isLiveSealed,
  objectKey,
  openLive,
  parseKey,
  sealWithServerKey,
  serverKey,
  sha256Hex,
  unwrapDataKey,
} from "../../shared/crypto.mjs";
import { TENANT_INDEX, keysPath, livePath, pullAll, pullTenant, tokenPath } from "./live.js";

const SINGLETONS = {
  status: "status.json",
  index: "index.json",
  profile: "profile.json",
  context: "context.json",
  plan: "plan.json",
  baselines: "baselines.json",
  "data-health": "data-health.json",
  // 给个人助手的只读接口：近 N 天每日摘要、读数契约（zeppbridge-cli contract 原样）。
  summary: "summary.json",
  contract: "contract.json",
  // 云端定时从官方接口拉的那份（live.js）；电脑写不了它。
  live: "live.json",
};

// 电脑端能写的相对路径（不含 .gz.enc 后缀）。writer / readers/ 不在里面。
const WRITABLE = [
  /^(status|index|profile|context|plan|baselines|data-health|summary|contract)\.json$/,
  /^days\/\d{4}-\d{2}-\d{2}\.json$/,
  /^workouts\/\d{1,20}(\.full)?\.json$/,
  // 网页复用桌面界面用的快照（cloud/snapshot）；详情按 id 的 base64url 存。
  /^ui\/snapshot\.json$/,
  /^ui\/(sleep|workouts)\/[A-Za-z0-9_-]{1,200}\.json$/,
];
const MAX_OBJECT_BYTES = 2 * 1024 * 1024;
const MAX_FULL_OBJECT_BYTES = 8 * 1024 * 1024;

const COOKIE = "zb_read";
const COOKIE_MAX_AGE = 30 * 24 * 3600;

/** 存储二选一：绑了 R2（BUCKET）用 R2，否则用 KV（STORE）。读写的都是字节。 */
function storage(env) {
  if (env.BUCKET) {
    return {
      get: async (key) => {
        const object = await env.BUCKET.get(key);
        return object ? new Uint8Array(await object.arrayBuffer()) : null;
      },
      put: (key, value) => env.BUCKET.put(key, value),
      delete: (key) => env.BUCKET.delete(key),
      list: async (prefix) => (await env.BUCKET.list({ prefix })).objects.map((o) => o.key),
    };
  }
  return {
    get: async (key) => {
      const value = await env.STORE.get(key, "arrayBuffer");
      return value ? new Uint8Array(value) : null;
    },
    put: (key, value) => env.STORE.put(key, value),
    delete: (key) => env.STORE.delete(key),
    list: async (prefix) => (await env.STORE.list({ prefix })).keys.map((k) => k.name),
  };
}

const text = (bytes) => new TextDecoder().decode(bytes);

function json(status, body, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...extraHeaders },
  });
}

// 认证失败一律同一个 401：不区分「没有这个租户」「密钥错」「拿错了读写密钥」。
const unauthorized = () => json(401, { error: "unauthorized" });

function bearer(request) {
  const m = /^Bearer\s+(\S+)$/.exec(request.headers.get("authorization") ?? "");
  return m ? m[1] : null;
}

function cookieKey(request) {
  for (const part of (request.headers.get("cookie") ?? "").split(";")) {
    const [name, ...rest] = part.trim().split("=");
    if (name === COOKIE) return rest.join("=");
  }
  return null;
}

function sameHex(a, b) {
  const x = new TextEncoder().encode(a);
  const y = new TextEncoder().encode(b);
  return x.length === y.length && crypto.subtle.timingSafeEqual(x, y);
}

async function authorizeWriter(store, key) {
  const parsed = parseKey(key);
  if (!parsed || parsed.kind !== "write") return null;
  const stored = await store.get(`t/${parsed.tenant}/writer`);
  if (!stored) return null;
  return sameHex(text(stored).trim(), await sha256Hex(key)) ? parsed.tenant : null;
}

async function authorizeReader(store, key) {
  const parsed = parseKey(key);
  if (!parsed || parsed.kind !== "read") return null;
  const hash = await sha256Hex(key);
  const record = await store.get(`t/${parsed.tenant}/readers/${hash}`);
  if (!record) return null;
  try {
    const dk = await unwrapDataKey(JSON.parse(text(record)), key, parsed.tenant, hash);
    return { tenant: parsed.tenant, dk };
  } catch {
    return null;
  }
}

function readTarget(segments, url) {
  if (segments.length === 1 && SINGLETONS[segments[0]]) return { rel: SINGLETONS[segments[0]], full: false };
  if (segments.length === 2 && segments[0] === "days" && /^\d{4}-\d{2}-\d{2}$/.test(segments[1])) {
    return { rel: `days/${segments[1]}.json`, full: false };
  }
  if (segments.length === 2 && segments[0] === "workouts" && /^\d{1,20}$/.test(segments[1])) {
    const res = url.searchParams.get("res");
    if (res !== null && res !== "full") return { error: json(400, { error: "bad_request", message: "res must be omitted or 'full'" }) };
    const full = res === "full";
    return { rel: `workouts/${segments[1]}${full ? ".full" : ""}.json`, full };
  }
  if (segments.length === 2 && segments[0] === "ui" && segments[1] === "snapshot") return { rel: "ui/snapshot.json", full: false };
  if (segments.length === 3 && segments[0] === "ui" && /^(sleep|workouts)$/.test(segments[1]) && /^[A-Za-z0-9_-]{1,200}$/.test(segments[2])) {
    return { rel: `ui/${segments[1]}/${segments[2]}.json`, full: false };
  }
  return null;
}

/** GET /v1：给助手的接口目录。只是路由说明，不含数据；照样要只读密钥。 */
const API_INDEX = {
  schema: "zeppbridge-cloud.api/1",
  auth: "Authorization: Bearer <read key>. Every route is read-only; responses are JSON (gzip-encoded).",
  start_here: ["/v1/summary", "/v1/contract", "/v1/status"],
  routes: {
    "/v1/summary": "Daily summary of recent days: one row per local day, units in `units`, null = no data (never filled in).",
    "/v1/contract": "Units, time zones, sources and missing-value rules shared by every export (zeppbridge-cli contract).",
    "/v1/status": "When this computer last uploaded and last pulled from the Zepp cloud; sync errors if any.",
    "/v1/index": "Which days and workouts are stored.",
    "/v1/days/<YYYY-MM-DD>": "Everything for one local day (daily metrics, sleep, workouts summary).",
    "/v1/workouts/<id>": "One workout with samples every 15 s. Add ?res=full for every sample when the owner enabled it.",
    "/v1/profile": "Athlete profile (zones, thresholds, injuries, races, shoes).",
    "/v1/context": "Training context for the last 28 days.",
    "/v1/plan": "Current training plan.",
    "/v1/baselines": "Personal baselines.",
    "/v1/data-health": "Data coverage and known gaps.",
    "/v1/live": "Data pulled from the official Zepp API by the site itself (present only if enabled).",
  },
  rules: [
    "GPS routes are never uploaded.",
    "Missing values are null; do not treat them as zero.",
    "Dates are the owner's local calendar days; timestamps carry their offset.",
  ],
};

async function handleRead(request, store, segments, url) {
  const target = readTarget(segments, url);
  // 路径不存在也要先过认证，免得未认证的人借 404 / 401 的差别探路由。
  const reader = await authorizeReader(store, bearer(request) ?? cookieKey(request));
  if (!reader) return unauthorized();
  if (segments.length === 0) return json(200, API_INDEX);
  if (!target) return json(404, { error: "not_found" });
  if (target.error) return target.error;

  const path = objectKey(reader.tenant, target.rel);
  const sealed = await store.get(path);
  if (!sealed) {
    return json(404, {
      error: "not_found",
      message: target.full
        ? "No full-resolution version. Either the owner has not enabled full-resolution workouts (see full_resolution_workouts in /v1/status), or this workout has none."
        : "Nothing uploaded for this path. Check /v1/index for what is available.",
    });
  }
  let gz;
  try {
    if (isLiveSealed(sealed)) {
      // 定时任务用公钥封的：先用 DK 解开私钥，再解对象。
      const keys = JSON.parse(text(await store.get(keysPath(reader.tenant))));
      const pkcs8 = await decryptObject(reader.dk, keysPath(reader.tenant), fromB64url(keys.private_sealed));
      gz = await openLive(await importLivePrivate(pkcs8), path, sealed);
    } else {
      gz = await decryptObject(reader.dk, path, sealed);
    }
  } catch {
    return json(500, { error: "decrypt_failed" });
  }

  // 一律原样返回 gzip。Workers 运行时会把请求的 Accept-Encoding 改写成 "br, gzip"，
  // 客户端声明不收 gzip 时由运行时替它解压（workerd 上验证过），
  // 所以这里不用、也没法按请求头分支。
  return new Response(gz, {
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-encoding": "gzip",
      "cache-control": "no-store",
    },
    encodeBody: "manual",
  });
}

async function handleWrite(request, store, rel) {
  const tenant = await authorizeWriter(store, bearer(request));
  if (!tenant) return unauthorized();
  if (!WRITABLE.some((re) => re.test(rel))) return json(404, { error: "not_found" });
  const path = objectKey(tenant, rel);

  if (request.method === "DELETE") {
    await store.delete(path);
    return json(200, { ok: true });
  }
  const limit = rel.endsWith(".full.json") ? MAX_FULL_OBJECT_BYTES : MAX_OBJECT_BYTES;
  const declared = Number(request.headers.get("content-length"));
  if (!Number.isFinite(declared) || declared <= 0) return json(411, { error: "length_required" });
  if (declared > limit) return json(413, { error: "too_large", limit });
  const body = await request.arrayBuffer();
  if (body.byteLength !== declared || body.byteLength > limit) return json(400, { error: "bad_length" });
  await store.put(path, body);
  return json(200, { ok: true, bytes: body.byteLength });
}

/**
 * 官方通道交接（只认写入密钥）：
 *   PUT /v1/live/keys   {public, private_sealed}          电脑生成的 ECDH 公钥 + 用 DK 包好的私钥
 *   PUT /v1/live/token  {access_token, expires_at, time_zone}  访问令牌（不收刷新令牌）
 *   DELETE /v1/live/token                                  桌面版断开官方授权时撤掉，云端停止拉取
 */
async function handleLive(request, env, ctx, store, action) {
  const tenant = await authorizeWriter(store, bearer(request));
  if (!tenant) return unauthorized();
  if (!env.LIVE_TOKEN_KEY) return json(503, { error: "live_not_configured" });

  if (action === "token" && request.method === "DELETE") {
    await Promise.all([store.delete(tokenPath(tenant)), store.delete(TENANT_INDEX + tenant), store.delete(livePath(tenant))]);
    return json(200, { ok: true });
  }
  if (request.method !== "PUT") return json(405, { error: "method_not_allowed" });
  let body;
  try {
    const raw = await request.text();
    if (raw.length > 16 * 1024) return json(413, { error: "too_large" });
    body = JSON.parse(raw);
  } catch {
    return json(400, { error: "bad_request" });
  }
  const b64 = /^[A-Za-z0-9_-]+$/;

  if (action === "keys") {
    if (!b64.test(body?.public ?? "") || !b64.test(body?.private_sealed ?? "") || fromB64url(body.public).length !== 65) {
      return json(400, { error: "bad_request" });
    }
    await store.put(keysPath(tenant), new TextEncoder().encode(JSON.stringify({ public: body.public, private_sealed: body.private_sealed })));
    return json(200, { ok: true });
  }
  if (action === "token") {
    const token = body?.access_token;
    const expires = body?.expires_at;
    const tz = body?.time_zone;
    if (typeof token !== "string" || !token || token.length > 4096) return json(400, { error: "bad_request" });
    if (expires !== null && !Number.isFinite(expires)) return json(400, { error: "bad_request" });
    try {
      new Intl.DateTimeFormat("en", { timeZone: tz });
    } catch {
      return json(400, { error: "bad_time_zone" });
    }
    if (!(await store.get(keysPath(tenant)))) return json(409, { error: "keys_missing" });
    const record = JSON.stringify({ access_token: token, expires_at: expires, time_zone: tz, received_at: new Date().toISOString() });
    const sealed = await sealWithServerKey(await serverKey(env.LIVE_TOKEN_KEY), tokenPath(tenant), new TextEncoder().encode(record));
    await store.put(tokenPath(tenant), sealed);
    await store.put(TENANT_INDEX + tenant, new TextEncoder().encode("1"));
    // 交上新令牌就立刻拉一次，不等下一个整点。
    ctx.waitUntil(pullTenant(env, store, tenant).catch(() => {}));
    return json(200, { ok: true });
  }
  return json(404, { error: "not_found" });
}

/** 仪表盘登录：校验只读密钥能解开，再放进 HttpOnly Cookie。只认同源 POST。 */
async function handleAuth(request, store, action, url) {
  if (request.method !== "POST") return json(405, { error: "method_not_allowed" });
  if (request.headers.get("origin") !== url.origin) return json(403, { error: "forbidden" });
  const secure = url.protocol === "https:" ? "; Secure" : "";
  if (action === "logout") {
    return json(200, { ok: true }, { "set-cookie": `${COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0${secure}` });
  }
  if (action !== "login") return json(404, { error: "not_found" });
  let key;
  try {
    key = String((await request.json()).key ?? "").trim();
  } catch {
    return json(400, { error: "bad_request" });
  }
  if (!(await authorizeReader(store, key))) return unauthorized();
  return json(200, { ok: true }, {
    "set-cookie": `${COOKIE}=${key}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${COOKIE_MAX_AGE}${secure}`,
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const segments = url.pathname.split("/").filter(Boolean);
    const store = storage(env);

    if (segments[0] === "auth" && segments.length === 2) return handleAuth(request, store, segments[1], url);
    if (segments[0] !== "v1") return json(404, { error: "not_found" });
    if (segments[1] === "live" && segments.length === 3) return handleLive(request, env, ctx, store, segments[2]);

    if (segments[1] === "objects") {
      if (request.method !== "PUT" && request.method !== "DELETE") return json(405, { error: "method_not_allowed" });
      return handleWrite(request, store, segments.slice(2).join("/"));
    }
    if (request.method !== "GET") return json(405, { error: "method_not_allowed" });
    return handleRead(request, store, segments.slice(1), url);
  },

  // 定时任务：每 30 分钟从官方接口拉一次（wrangler.jsonc 的 triggers）。
  async scheduled(_event, env, ctx) {
    if (!env.LIVE_TOKEN_KEY) return;
    ctx.waitUntil(pullAll(env, storage(env)));
  },
};
