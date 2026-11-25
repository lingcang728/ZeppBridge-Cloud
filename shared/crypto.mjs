// 云端中转的加解密，Worker 和电脑端上传程序共用这一份（都只用 WebCrypto）。
//
// 服务器只存密文：数据密钥 DK 只在电脑上；每个读者存一份「用它的只读密钥派生出的
// 钥匙包裹后的 DK」，读请求那一刻才解开，用完就丢。

const enc = new TextEncoder();
const FORMAT_VERSION = 1;
const HKDF_SALT = enc.encode("zeppbridge-cloud-v1");

export const KEY_PREFIX = { read: "zbr", write: "zbw" };

/** R2 里的完整路径；它同时是对象加密的 AAD，两边必须一字不差。 */
export const objectKey = (tenant, rel) => `t/${tenant}/${rel}.gz.enc`;

export function b64url(bytes) {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}

export function fromB64url(text) {
  const s = atob(text.replaceAll("-", "+").replaceAll("_", "/"));
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export async function sha256Hex(text) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", enc.encode(text)));
  return [...digest].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** 租户 id：10 位小写 base32，进 R2 路径和密钥前缀，不含任何个人信息。 */
export function newTenantId() {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  return [...randomBytes(10)].map((b) => alphabet[b % 32]).join("");
}

export function newKey(kind, tenant) {
  return `${KEY_PREFIX[kind]}_${tenant}_${b64url(randomBytes(32))}`;
}

/** `zbr_<租户>_<随机>` → { kind, tenant }；格式不对返回 null（调用方一律回 401）。 */
export function parseKey(key) {
  const m = /^(zbr|zbw)_([a-z2-7]{10})_([A-Za-z0-9_-]{43})$/.exec(key ?? "");
  if (!m) return null;
  return { kind: m[1] === "zbr" ? "read" : "write", tenant: m[2] };
}

async function aesKey(raw, usages) {
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, usages);
}

/** 只读密钥 → 包裹 DK 用的 AES 钥匙（HKDF-SHA256，info 绑定租户）。 */
async function readerWrapKey(readKey, tenant) {
  const ikm = await crypto.subtle.importKey("raw", enc.encode(readKey), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: enc.encode(`reader-wrap:${tenant}`) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function seal(key, plain, aad) {
  const nonce = randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: enc.encode(aad) }, key, plain),
  );
  const out = new Uint8Array(1 + 12 + ct.length);
  out[0] = FORMAT_VERSION;
  out.set(nonce, 1);
  out.set(ct, 13);
  return out;
}

async function open(key, sealed, aad) {
  const bytes = sealed instanceof Uint8Array ? sealed : new Uint8Array(sealed);
  if (bytes[0] !== FORMAT_VERSION || bytes.length < 13 + 16) throw new Error("bad_ciphertext");
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes.subarray(1, 13), additionalData: enc.encode(aad) },
      key,
      bytes.subarray(13),
    ),
  );
}

/** 读者记录（存 R2 的 JSON）：包裹后的 DK。AAD 绑定租户 + 密钥哈希，记录不能挪给别人用。 */
export async function wrapDataKey(dk, readKey, tenant, readerHash, label) {
  const sealed = await seal(await readerWrapKey(readKey, tenant), dk, `reader:${tenant}:${readerHash}`);
  return { v: FORMAT_VERSION, wrapped_dk: b64url(sealed), label: label ?? "", created_at: new Date().toISOString() };
}

export async function unwrapDataKey(record, readKey, tenant, readerHash) {
  const dk = await open(await readerWrapKey(readKey, tenant), fromB64url(record.wrapped_dk), `reader:${tenant}:${readerHash}`);
  return aesKey(dk, ["decrypt"]);
}

/** 对象加密：AAD = R2 完整路径，防止把一个文件的密文换到另一个路径下。 */
export async function encryptObject(dkBytes, path, gzBytes) {
  return seal(await aesKey(dkBytes, ["encrypt"]), gzBytes, `object:${path}`);
}

export async function decryptObject(dkKey, path, sealed) {
  return open(dkKey, sealed, `object:${path}`);
}

/* ---------------- 云端定时拉取（官方通道）用的非对称封装 ----------------
 *
 * 定时任务手上没有任何读者密钥，所以拿不到 DK。它用电脑生成的 ECDH 公钥加密：
 * 写得进去，自己读不出来。私钥用 DK 包好存在云端，只有带只读密钥的读者能解开。
 * 格式：版本 2 | 临时公钥(65) | nonce(12) | 密文+tag。
 */
const LIVE_VERSION = 2;
const ECDH = { name: "ECDH", namedCurve: "P-256" };

export async function newLiveKeyPair() {
  const pair = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
  return {
    publicRaw: new Uint8Array(await crypto.subtle.exportKey("raw", pair.publicKey)),
    privatePkcs8: new Uint8Array(await crypto.subtle.exportKey("pkcs8", pair.privateKey)),
  };
}

export async function importLivePrivate(pkcs8) {
  return crypto.subtle.importKey("pkcs8", pkcs8, ECDH, false, ["deriveBits"]);
}

async function liveAesKey(privateKey, peerPublic, path, usage) {
  const bits = await crypto.subtle.deriveBits({ name: "ECDH", public: peerPublic }, privateKey, 256);
  const ikm = await crypto.subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: HKDF_SALT, info: enc.encode(`live:${path}`) },
    ikm,
    { name: "AES-GCM", length: 256 },
    false,
    [usage],
  );
}

export async function sealForLive(publicRaw, path, plain) {
  const recipient = await crypto.subtle.importKey("raw", publicRaw, ECDH, false, []);
  const eph = await crypto.subtle.generateKey(ECDH, true, ["deriveBits"]);
  const ephRaw = new Uint8Array(await crypto.subtle.exportKey("raw", eph.publicKey));
  const key = await liveAesKey(eph.privateKey, recipient, path, "encrypt");
  const nonce = randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: nonce, additionalData: enc.encode(`object:${path}`) }, key, plain),
  );
  const out = new Uint8Array(1 + 65 + 12 + ct.length);
  out[0] = LIVE_VERSION;
  out.set(ephRaw, 1);
  out.set(nonce, 66);
  out.set(ct, 78);
  return out;
}

export function isLiveSealed(sealed) {
  return sealed[0] === LIVE_VERSION;
}

export async function openLive(privateKey, path, sealed) {
  const bytes = sealed instanceof Uint8Array ? sealed : new Uint8Array(sealed);
  if (bytes[0] !== LIVE_VERSION || bytes.length < 78 + 16) throw new Error("bad_ciphertext");
  const peer = await crypto.subtle.importKey("raw", bytes.subarray(1, 66), ECDH, false, []);
  const key = await liveAesKey(privateKey, peer, path, "decrypt");
  return new Uint8Array(
    await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: bytes.subarray(66, 78), additionalData: enc.encode(`object:${path}`) },
      key,
      bytes.subarray(78),
    ),
  );
}

/** 服务器自己的钥匙（Worker secret）加解密官方令牌：定时任务要用明文令牌，只能这样。 */
export async function serverKey(secretB64url) {
  const raw = fromB64url(secretB64url);
  if (raw.length !== 32) throw new Error("server key must be 32 bytes");
  return crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export async function sealWithServerKey(key, path, plain) {
  return seal(key, plain, `server:${path}`);
}

export async function openWithServerKey(key, path, sealed) {
  return open(key, sealed, `server:${path}`);
}

/** 上传前的硬检查：任何坐标字段出现就整次中止。 */
export function findCoordinateField(jsonText) {
  const m = /"(latitude|longitude|lat|lng|lon)"\s*:/.exec(jsonText);
  return m ? m[1] : null;
}
