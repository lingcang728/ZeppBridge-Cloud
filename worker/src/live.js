// 官方通道的云端定时拉取：电脑关着也能更新的那部分（睡眠、步数、逐分钟心率、运动、PAI）。
//
// 令牌归属：桌面版是唯一刷新令牌的一方。云端只拿电脑交上来的访问令牌（最长 90 天有效），
// 永远不刷新、不拿刷新令牌和 client_secret——两边抢同一把刷新令牌会互相挤掉。
// 令牌用 Worker secret（LIVE_TOKEN_KEY）加密存放：定时任务要用明文，只能这样。
// 拉到的数据用电脑给的 ECDH 公钥加密：定时任务写得进去，自己读不出来。
//
// 只拷贝白名单字段：官方运动的 `location` 是 12 位 geohash（厘米级位置），绝不上云。

import { fromB64url, openWithServerKey, sealForLive, sealWithServerKey, serverKey } from "../../shared/crypto.mjs";

const API = "https://api-open.zepp.com";
const DAYS_BACK = 3; // 接住晚到的睡眠
const WORKOUT_DAYS = 7;
export const TENANT_INDEX = "live/tenants/";
export const tokenPath = (tenant) => `t/${tenant}/live/token`;
export const keysPath = (tenant) => `t/${tenant}/live/keys`;
export const livePath = (tenant) => `t/${tenant}/live.json.gz.enc`;

/** 某个时区里的日期 YYYY-MM-DD，往前推 offset 天。 */
function localDate(timeZone, offsetDays = 0) {
  const d = new Date(Date.now() - offsetDays * 86_400_000);
  return new Intl.DateTimeFormat("en-CA", { timeZone, year: "numeric", month: "2-digit", day: "2-digit" }).format(d);
}

const num = (v) => (typeof v === "number" && Number.isFinite(v) ? v : typeof v === "string" && v.trim() !== "" && Number.isFinite(Number(v)) ? Number(v) : null);
const iso = (seconds) => (num(seconds) && seconds > 0 ? new Date(seconds * 1000).toISOString() : null);
const minutes = (v) => {
  const n = num(v);
  return n !== null && n >= 0 && n <= 1440 ? n : null;
};

class OfficialError extends Error {
  constructor(kind, status) {
    super(kind);
    this.kind = kind;
    this.status = status;
  }
}

async function getItems(token, path, query) {
  const url = `${API}${path}?${new URLSearchParams(query)}`;
  const response = await fetch(url, { headers: { authorization: `Bearer ${token}` } });
  if (response.status === 401 || response.status === 403) throw new OfficialError("token_rejected", response.status);
  if (!response.ok) throw new OfficialError(response.status === 404 || response.status === 400 ? "unavailable" : "upstream", response.status);
  const body = await response.json();
  if (num(body?.code) && body.code !== 0) throw new OfficialError("cloud_rejected", body.code);
  if (!Array.isArray(body?.items)) throw new OfficialError("unrecognized", response.status);
  return body.items;
}

function sleepOf(item) {
  const start = num(item.start);
  const stop = num(item.stop);
  if (!start || !stop || stop <= start) return null; // 没睡的那天官方给 0
  const score = num(item.sleepScore);
  const rhr = num(item.rhr);
  return {
    start: iso(start),
    end: iso(stop),
    score: score !== null && score >= 1 && score <= 100 ? score : null,
    deep_minutes: minutes(item.deepSleepTime),
    light_minutes: minutes(item.shallowSleepTime),
    rem_minutes: minutes(item.rem),
    awake_minutes: minutes(item.wakeTime),
    resting_hr: rhr !== null && rhr >= 25 && rhr <= 150 ? rhr : null,
  };
}

function heartRateToday(items) {
  const readings = items
    .map((item) => ({ t: num(item.timestamp), bpm: num(item.heartRateData) }))
    .filter((r) => r.t && r.bpm !== null && r.bpm >= 25 && r.bpm <= 250) // 没戴表的分钟官方给 0，不是读数
    .sort((a, b) => a.t - b.t);
  if (!readings.length) return { latest: null, hourly: [] };
  const hours = new Map();
  for (const r of readings) {
    const hour = new Date(Math.floor(r.t / 3600) * 3600 * 1000).toISOString();
    const h = hours.get(hour) ?? { hour, min: Infinity, max: -Infinity, sum: 0, count: 0 };
    h.min = Math.min(h.min, r.bpm);
    h.max = Math.max(h.max, r.bpm);
    h.sum += r.bpm;
    h.count += 1;
    hours.set(hour, h);
  }
  const last = readings[readings.length - 1];
  return {
    latest: { at: iso(last.t), bpm: last.bpm },
    hourly: [...hours.values()].map((h) => ({ hour: h.hour, min: h.min, avg: Math.round(h.sum / h.count), max: h.max, minutes: h.count })),
  };
}

function workoutOf(item) {
  // 白名单：location（geohash）、trackId 以外的设备信息一概不拷。
  return {
    workout_id: item.trackId != null ? String(item.trackId) : null,
    type: typeof item.type === "string" ? item.type.toLowerCase() : null,
    start: iso(num(item.startTime)),
    end: iso(num(item.endTime)),
    duration_seconds: num(item.sportTime),
    distance_meters: num(item.distance),
    avg_hr: num(item.averageHeartRate),
    calories: num(item.calories),
    ascent_m: num(item.altitudeAscend),
  };
}

/** 拉一个租户。每类单独失败，失败的那类记进 errors，不让一类挂掉整份。 */
export async function pullTenant(env, store, tenant) {
  const tokenSealed = await store.get(tokenPath(tenant));
  const keysRaw = await store.get(keysPath(tenant));
  if (!tokenSealed || !keysRaw) return { tenant, skipped: "not_configured" };
  const key = await serverKey(env.LIVE_TOKEN_KEY);
  const token = JSON.parse(new TextDecoder().decode(await openWithServerKey(key, tokenPath(tenant), tokenSealed)));
  const keys = JSON.parse(new TextDecoder().decode(keysRaw));
  if (token.invalid) return { tenant, skipped: "token_invalid" };
  if (token.expires_at && Date.now() / 1000 >= token.expires_at) return { tenant, skipped: "token_expired" };

  const tz = token.time_zone || "Asia/Shanghai";
  const today = localDate(tz);
  const from = localDate(tz, DAYS_BACK - 1);
  const errors = [];
  const attempt = async (kind, fn) => {
    try {
      return await fn();
    } catch (error) {
      errors.push({ kind, error: error.kind ?? "network", status: error.status ?? null });
      return null;
    }
  };

  const [sleep, activity, heart, sports, pai] = await Promise.all([
    attempt("sleep", () => getItems(token.access_token, "/users/-/sleep", { startDate: from, endDate: today, interval: "daily" })),
    attempt("activity", () => getItems(token.access_token, "/users/-/activities", { startDate: from, endDate: today, interval: "daily" })),
    attempt("heart_rate", () => getItems(token.access_token, "/users/-/heartrates", { startDate: today, endDate: today, timezone: tz, type: "ALL" })),
    attempt("workouts", () => getItems(token.access_token, "/users/-/sports", { startDate: localDate(tz, WORKOUT_DAYS - 1), endDate: today, timezone: tz })),
    attempt("pai", () => getItems(token.access_token, "/users/-/openData/PaiSummary", { startDate: from, endDate: today })),
  ]);

  // 令牌被拒：标记失效，停止拉取，直到电脑交来新令牌（桌面版重新授权或刷新后）。
  if (errors.some((e) => e.error === "token_rejected")) {
    const sealed = await sealWithServerKey(key, tokenPath(tenant), new TextEncoder().encode(JSON.stringify({ ...token, invalid: true })));
    await store.put(tokenPath(tenant), sealed);
  }

  const days = [];
  for (let i = DAYS_BACK - 1; i >= 0; i--) {
    const date = localDate(tz, i);
    const s = sleep?.find((item) => item.date === date);
    const a = activity?.find((item) => item.date === date);
    const found = pai?.find((item) => typeof item.calendarDay === "string" && item.calendarDay.startsWith(date));
    // 当天还没算出来时官方给 daily=0、total=0；total 是 7 天滚动值，昨天还有今天不可能是 0，按缺失处理。
    const p = found && !(num(found.dailyPai) === 0 && num(found.totalPai) === 0) ? found : null;
    days.push({
      date,
      sleep: s ? sleepOf(s) : null,
      steps: a ? num(a.steps) : null,
      distance_meters: a ? num(a.distance) : null,
      calories: a ? num(a.calories) : null,
      pai_daily: p ? num(p.dailyPai) : null,
      pai_total: p ? num(p.totalPai) : null,
    });
  }

  const live = {
    schema: "zeppbridge-cloud-live/1",
    source: "Zepp official API, pulled by the cloud relay on a schedule (no computer needed)",
    fetched_at: new Date().toISOString(),
    time_zone: tz,
    token_expires_at: token.expires_at ? iso(token.expires_at) : null,
    days,
    heart_rate_today: heart ? heartRateToday(heart) : null,
    workouts: sports ? sports.map(workoutOf).sort((a, b) => ((a.start ?? "") < (b.start ?? "") ? 1 : -1)) : null,
    errors,
    note: "Missing values are null, never 0. Stress, SpO2, readiness, HRV (RMSSD/SDNN), training load and VO2max are not in the official API; they come from the computer upload (/v1/days, /v1/context). No GPS or location.",
  };

  const gz = new Uint8Array(await new Response(new Blob([JSON.stringify(live)]).stream().pipeThrough(new CompressionStream("gzip"))).arrayBuffer());
  await store.put(livePath(tenant), await sealForLive(fromB64url(keys.public), livePath(tenant), gz));
  return { tenant, errors: errors.length };
}

/** 定时任务：逐个租户拉。KV list 一次最多 1000 个，个人版远够用。 */
export async function pullAll(env, store) {
  const tenants = await store.list(TENANT_INDEX);
  const results = [];
  for (const name of tenants) {
    try {
      results.push(await pullTenant(env, store, name.slice(TENANT_INDEX.length)));
    } catch {
      results.push({ failed: true });
    }
  }
  return results;
}
