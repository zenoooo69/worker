/**
 * REDEEM + GET KEY: 4 bước
 *   Bước 1: Link4Sub (Worker tạo link riêng qua API, mỗi bước 2 nhiệm vụ)
 *   Bước 2: trang verify đếm ngược 60 giây (Worker ký mã và tự đo thời gian)
 *   Bước 3: Linkvertise (kiểm tra hash chống bypass của Linkvertise)
 *   Bước 4: trang verify đếm ngược 60 giây lần nữa
 *
 * Ý tưởng chống bỏ qua bước:
 *   - Mỗi lần người dùng bấm START ở bước 1-4, Worker TỰ TẠO một link Link4Sub riêng qua API.
 *     Đích đến của link chứa một mã dùng một lần (nonce) chỉ Worker biết; người dùng chỉ nhận được
 *     link rút gọn, và chỉ thấy mã khi vượt qua cổng nhiệm vụ của Link4Sub và được chuyển về.
 *   - Quay về với ?step=N&n=NONCE -> Worker so khớp nonce với thiết bị + bước đó, rồi mới cho qua.
 *
 * Endpoint (POST, JSON): /progress, /step/start, /step/complete, /redeem
 *
 * Cài đặt:
 *  1. Dán file này vào Worker, bấm Deploy.
 *  2. Bindings: KV namespace, tên biến RATE.
 *  3. Variables and Secrets:
 *       WEBHOOK_URL         (Secret) = webhook Discord
 *       LINK4SUB_API_TOKEN  (Secret) = API token của Link4Sub (KHÔNG đặt trong file HTML)
 *       ALLOWED_ORIGIN      (Text)   = địa chỉ website, ví dụ https://ten-ban.pages.dev (không có / ở cuối)
 *       VISIT_SECRET        (Secret) = chuỗi ngẫu nhiên dài (từ 32 ký tự) để ký mã của trang đếm ngược
 *       COUNTDOWN_URL       (Text)   = địa chỉ trang verify, ví dụ https://verify-zen.pages.dev/verify.html
 *       LINKVERTISE_URL     (Text)   = link Linkvertise của bước 3 (đích đến: https://gemfreee.pages.dev/getkey.html?step=3)
 *       LINKVERTISE_TOKEN   (Secret) = Anti-bypass Token trong Account Settings của Linkvertise
 *       DEBUG               (Text, CHỈ để tìm lỗi) = 1 -> lỗi sẽ ghi rõ lý do. Tắt khi chạy thật.
 *     Có thể xóa STEP_SECRET_*, LINKVERTISE_TOKEN và TEST_MODE, không còn dùng.
 *  4. SỬA STEP_ACTIONS bên dưới: nhiệm vụ Link4Sub cho từng bước (theo tài liệu của Link4Sub).
 *
 * Lưu ý: KV không "nguyên tử" 100%, hai request gửi cùng lúc có thể cùng lọt qua.
 */

const REWARD_TEXT = "Gems";

const TOTAL_STEPS = 4;
const KEY_LIFETIME_SECONDS = 3600;      // key hết hạn sau 1 giờ
const KEY_RECORD_TTL = 24 * 3600;       // giữ bản ghi 24 giờ để còn báo được "expired"/"used"
const PROGRESS_TTL_SECONDS = 7200;      // phải hoàn thành các bước trong 2 giờ
const MIN_STEP_SECONDS = 30;            // thời gian tối thiểu giữa lúc bấm START và lúc quay lại
const BIND_TO_DEVICE = true;            // key chỉ dùng được trên trình duyệt đã tạo ra nó
const MAX_FAILS = 15;                   // nhập sai key tối đa mỗi IP
const FAIL_WINDOW_SECONDS = 600;        // trong 10 phút
const MAX_STARTS_PER_IP_PER_HOUR = 30;  // giới hạn số link Link4Sub được tạo cho mỗi IP mỗi giờ
const SEND_FULL_KEY = false;            // false = chỉ gửi Key ID rút gọn về webhook

const L4S_API = "https://link4sub.com/api/v1/social-links";
const GETKEY_PATH = "/getkey.html";     // trang nhận người dùng quay về
const L4S_TIMEOUT_MS = 10000;

// Loại của từng bước: link4sub | countdown (trang verify) | linkvertise
const STEP_TYPES = { 1: "link4sub", 2: "countdown", 3: "linkvertise", 4: "countdown" };
const VISIT_COUNTDOWN_SECONDS = 60;               // thời gian đếm ngược tối thiểu (Worker tự đo)
const VISIT_TOKEN_TTL_MS = 2 * 3600 * 1000;       // mã có hiệu lực 2 giờ

// ------------------------------------------------------------------
// NHIỆM VỤ LINK4SUB CHO TỪNG BƯỚC (mỗi bước 2 nhiệm vụ)
// Cấu trúc theo ví dụ trong tài liệu API: { platform, action, url }.
// Hai loại dưới đây lấy từ ví dụ bạn gửi: youtube/watch và other/visit-page.
// Muốn mỗi bước một nhiệm vụ khác nhau thì sửa riêng từng bước.
// ------------------------------------------------------------------
const TASK_WATCH = { platform: "youtube", action: "watch", url: "https://youtu.be/tJl3cBILHY0?si=2Oo2vtHzwetIGUkc" };
const TASK_VISIT = { platform: "other", action: "visit-page", url: "https://abc123-7c4.pages.dev/" };

const STEP_ACTIONS = {
  1: [TASK_WATCH, TASK_VISIT],
};
const STEP_TITLES = {
  1: "Step 1 of 4 - Unlock your key",
};

const USER_RE = /^[A-Za-z0-9_]{3,20}$/;
const DEVICE_RE = /^[A-Za-z0-9-]{16,64}$/;
const KEY_RE = /^RK-[A-Z2-9]{4}-[A-Z2-9]{4}-[A-Z2-9]{4}$/;
const NONCE_RE = /^[a-f0-9]{32}$/;
const HASH_RE = /^[\x21-\x7E]{6,500}$/; // hash Linkvertise: ký tự in được, không khoảng trắng

// Endpoint kiểm tra anti-bypass của Linkvertise (đã thử: trả về JSON {"status":true} khi hợp lệ)
const LINKVERTISE_VERIFY_URL = "https://publisher.linkvertise.com/api/v1/anti_bypassing";

export default {
  async fetch(request, env) {
    const path = new URL(request.url).pathname.replace(/\/+$/, "");
    // /task/* được gọi từ trang đếm ngược (khác tên miền với website chính)
    const isTask = path === "/task/begin" || path === "/task/complete";

    const allowed = (env.ALLOWED_ORIGIN || "").replace(/\/$/, "");
    let visitOrigin = "";
    try { visitOrigin = env.COUNTDOWN_URL ? new URL(env.COUNTDOWN_URL).origin : ""; } catch (_) {}
    const corsOrigin = isTask ? visitOrigin : allowed;
    const origin = request.headers.get("Origin") || "";

    const cors = {
      "Access-Control-Allow-Origin": corsOrigin || "null",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Vary": "Origin",
    };
    const reply = (obj, status = 200) =>
      new Response(JSON.stringify(obj), {
        status,
        headers: { "Content-Type": "application/json", ...cors },
      });

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
    if (request.method !== "POST") return reply({ ok: false, error: "method" }, 405);
    if (!corsOrigin || origin !== corsOrigin) return reply({ ok: false, error: "forbidden" }, 403);

    const missing = [];
    if (!env.RATE) missing.push("RATE (KV binding)");
    if (!isTask && !env.WEBHOOK_URL) missing.push("WEBHOOK_URL");
    if (isTask && !env.VISIT_SECRET) missing.push("VISIT_SECRET");
    if (isTask && !visitOrigin) missing.push("COUNTDOWN_URL");
    if (missing.length) {
      console.error("[redeem] thiếu cấu hình: " + missing.join(", "));
      return reply({ ok: false, error: "server_config", missing: env.DEBUG === "1" ? missing : undefined }, 500);
    }

    let body;
    try {
      body = await request.json();
    } catch (_) {
      return reply({ ok: false, error: "bad_request" }, 400);
    }

    const now = Date.now();

    try {
      if (path === "/task/begin") return await handleTaskBegin({ env, reply, body, now });
      if (path === "/task/complete") return await handleTaskComplete({ env, reply, body, now });

      const deviceId = String(body.deviceId || "").trim();
      if (!DEVICE_RE.test(deviceId)) return reply({ ok: false, error: "bad_request" }, 400);

      const ip = request.headers.get("CF-Connecting-IP") || "unknown";
      const ipH = await sha256Hex(ip);
      const ctx = { env, reply, body, deviceId, ipH, allowed, now };

      if (path === "/progress") return await handleProgress(ctx);
      if (path === "/step/start") return await handleStepStart(ctx);
      if (path === "/step/complete") return await handleStepComplete(ctx);
      if (path === "/redeem") return await handleRedeem(ctx);
      return reply({ ok: false, error: "not_found" }, 404);
    } catch (err) {
      console.error("[redeem] lỗi tại " + path + ": " + ((err && err.stack) || err));
      return reply({
        ok: false,
        error: "exception",
        detail: env.DEBUG === "1" ? String((err && err.message) || err) : undefined,
      }, 500);
    }
  },
};

// ------------------------------------------------------------------
// TIẾN TRÌNH CÁC BƯỚC
// ------------------------------------------------------------------
async function handleProgress({ env, reply, deviceId, now }) {
  const active = await getActiveKey(env, deviceId, now);
  if (active) return reply(keyReply(active));

  const prog = await getProgress(env, deviceId);
  const step = prog && prog.step < TOTAL_STEPS ? prog.step : 0;
  return reply({ ok: true, step });
}

async function handleStepStart({ env, reply, body, deviceId, ipH, allowed, now }) {
  const debug = env.DEBUG === "1";
  const step = Number(body.step);
  if (!Number.isInteger(step) || step < 1 || step > TOTAL_STEPS) {
    return reply({ ok: false, error: "bad_request" }, 400);
  }

  const active = await getActiveKey(env, deviceId, now);
  if (active) return reply(keyReply(active));

  let prog = await getProgress(env, deviceId);
  if (!prog || prog.step >= TOTAL_STEPS) prog = { step: 0 };

  if (step !== prog.step + 1) {
    return reply({ ok: false, error: "wrong_step", step: prog.step }, 409);
  }

  // Bước Linkvertise: chuyển sang link Linkvertise của bạn (đích đến: .../getkey.html?step=N)
  if (STEP_TYPES[step] === "linkvertise") {
    if (!env.LINKVERTISE_URL) {
      return reply({ ok: false, error: "server_config", missing: debug ? ["LINKVERTISE_URL"] : undefined }, 500);
    }
    prog.linkStep = step;
    prog.stepStartedAt = now;
    delete prog.shortUrl;
    delete prog.nonceHash;
    delete prog.visitIssuedAt;
    await putProgress(env, deviceId, prog);
    return reply({ ok: true, url: env.LINKVERTISE_URL });
  }

  // Bước đếm ngược: chuyển sang trang verify kèm mã đã ký (gắn với thiết bị + bước)
  if (STEP_TYPES[step] === "countdown") {
    if (!env.VISIT_SECRET || !env.COUNTDOWN_URL) {
      return reply({ ok: false, error: "server_config", missing: debug ? ["VISIT_SECRET", "COUNTDOWN_URL"] : undefined }, 500);
    }
    const token = await makeVisitToken(env, deviceId, step, now);
    prog.linkStep = step;
    prog.visitIssuedAt = now;
    prog.stepStartedAt = now;
    delete prog.shortUrl;
    delete prog.nonceHash;
    await putProgress(env, deviceId, prog);
    return reply({ ok: true, url: addQueryParam(env.COUNTDOWN_URL, "s", token) });
  }

  // Tạo link Link4Sub cho bước này
  if (!cleanToken(env.LINK4SUB_API_TOKEN)) {
    console.error("[redeem] thiếu LINK4SUB_API_TOKEN");
    return reply({ ok: false, error: "server_config", missing: debug ? ["LINK4SUB_API_TOKEN"] : undefined }, 500);
  }
  if (!allowed) {
    return reply({ ok: false, error: "server_config", missing: debug ? ["ALLOWED_ORIGIN"] : undefined }, 500);
  }

  // Đã có link của chính bước này (bấm START lại, tải lại trang) -> dùng lại, không tạo link mới
  if (prog.linkStep === step && prog.shortUrl && prog.nonceHash) {
    prog.stepStartedAt = now;
    await putProgress(env, deviceId, prog);
    return reply({ ok: true, url: prog.shortUrl });
  }

  // Giới hạn số link tạo ra theo IP
  const rlKey = "start:" + ipH;
  const startedCount = Number((await env.RATE.get(rlKey)) || 0);
  if (startedCount >= MAX_STARTS_PER_IP_PER_HOUR) {
    return reply({ ok: false, error: "limit" }, 429);
  }

  const actions = STEP_ACTIONS[step];
  if (!actions || !actions.length || actions.some((a) => String(a.url || "").includes("@example"))) {
    console.error("[redeem] STEP_ACTIONS bước " + step + " chưa được cấu hình");
    return reply({ ok: false, error: "server_config", missing: debug ? ["STEP_ACTIONS[" + step + "]"] : undefined }, 500);
  }

  const nonce = randomHex(16);
  const destinationUrl = allowed + GETKEY_PATH + "?step=" + step + "&n=" + nonce;

  const created = await createLink4SubLink(env, {
    destinationUrl,
    title: STEP_TITLES[step] || "Unlock your key",
    actions,
  });
  if (!created.ok) {
    return reply({ ok: false, error: "provider_error", reason: debug ? created.reason : undefined }, 502);
  }

  prog.linkStep = step;
  prog.shortUrl = created.shortUrl;
  prog.nonceHash = await sha256Hex(nonce);
  prog.stepStartedAt = now;
  await Promise.all([
    putProgress(env, deviceId, prog),
    env.RATE.put(rlKey, String(startedCount + 1), { expirationTtl: 3600 }),
  ]);

  return reply({ ok: true, url: created.shortUrl });
}

async function handleStepComplete({ env, reply, body, deviceId, now }) {
  const debug = env.DEBUG === "1";
  const step = Number(body.step);
  const nonce = String(body.nonce || "").trim().toLowerCase();
  const hash = String(body.hash || "").trim();

  if (!Number.isInteger(step) || step < 1 || step > TOTAL_STEPS) {
    return reply({ ok: false, error: "invalid_token", reason: debug ? "bad_step" : undefined }, 400);
  }

  // Đã có key còn hạn (ví dụ tải lại trang) -> trả lại key
  const active = await getActiveKey(env, deviceId, now);
  if (active) return reply(keyReply(active));

  const prog = await getProgress(env, deviceId);
  if (!prog) return reply({ ok: false, error: "no_session" }, 409);

  // Bước này đã hoàn thành trước đó (tải lại trang) -> báo lại tiến trình
  if (prog.step === step && prog.step < TOTAL_STEPS) {
    return reply({ ok: true, step: prog.step, duplicate: true });
  }
  if (step !== prog.step + 1) {
    return reply({ ok: false, error: "wrong_step", step: Math.min(prog.step, TOTAL_STEPS - 1) }, 409);
  }
  if (!prog.stepStartedAt) return reply({ ok: false, error: "no_session" }, 409);

  const minSeconds = STEP_TYPES[step] === "countdown" ? VISIT_COUNTDOWN_SECONDS : MIN_STEP_SECONDS;
  if (now - prog.stepStartedAt < minSeconds * 1000) {
    return reply({ ok: false, error: "too_fast" }, 429);
  }

  if (prog.linkStep !== step) {
    return reply({ ok: false, error: "no_session" }, 409);
  }

  const type = STEP_TYPES[step];
  if (type === "linkvertise") {
    // Hash Linkvertise: đúng định dạng, chưa dùng, và được Linkvertise xác nhận
    if (!HASH_RE.test(hash)) {
      return reply({ ok: false, error: "invalid_token", reason: debug ? "hash_format" : undefined }, 400);
    }
    const hashKey = "lv:" + (await sha256Hex(hash));
    if (await env.RATE.get(hashKey)) {
      return reply({ ok: false, error: "invalid_token", reason: debug ? "replay" : undefined }, 400);
    }
    const v = await verifyLinkvertiseHash(env, hash);
    if (v.valid === null) {
      return reply({ ok: false, error: "server_config", missing: debug ? ["LINKVERTISE_TOKEN"] : undefined }, 500);
    }
    if (!v.valid) {
      return reply({ ok: false, error: "invalid_token", reason: debug ? v.reason : undefined }, 400);
    }
    await env.RATE.put(hashKey, "1", { expirationTtl: 86400 });
  } else {
    // Link4Sub và countdown dùng mã dùng một lần (nonce)
    if (!NONCE_RE.test(nonce)) {
      return reply({ ok: false, error: "invalid_token", reason: debug ? "nonce_format" : undefined }, 400);
    }
    if (type === "countdown") {
      // Mã được Worker tính ra từ khóa bí mật và chỉ gửi cho người dùng khi đếm ngược xong
      if (!env.VISIT_SECRET || !prog.visitIssuedAt) return reply({ ok: false, error: "no_session" }, 409);
      const expected = await countdownNonce(env, deviceId, step, prog.visitIssuedAt);
      if (!safeEqual(nonce, expected)) {
        return reply({ ok: false, error: "invalid_token", reason: debug ? "nonce_mismatch" : undefined }, 400);
      }
    } else {
      if (!prog.nonceHash) return reply({ ok: false, error: "no_session" }, 409);
      if (!safeEqual(await sha256Hex(nonce), prog.nonceHash)) {
        return reply({ ok: false, error: "invalid_token", reason: debug ? "nonce_mismatch" : undefined }, 400);
      }
    }
  }

  prog.step = step;
  delete prog.stepStartedAt;
  delete prog.linkStep;
  delete prog.shortUrl;
  delete prog.nonceHash;
  delete prog.visitIssuedAt;
  await putProgress(env, deviceId, prog);

  if (step < TOTAL_STEPS) return reply({ ok: true, step });

  // Hoàn thành bước cuối -> tạo key riêng cho thiết bị này
  const key = await generateUniqueKey(env);
  if (!key) return reply({ ok: false, error: "server_busy" }, 503);

  const rec = {
    createdAt: now,
    expiresAt: now + KEY_LIFETIME_SECONDS * 1000,
    deviceId,
    used: false,
  };
  await Promise.all([
    env.RATE.put("key:" + key, JSON.stringify(rec), { expirationTtl: KEY_RECORD_TTL }),
    env.RATE.put("devkey:" + deviceId, key, { expirationTtl: KEY_LIFETIME_SECONDS }),
  ]);

  return reply({ ok: true, step: TOTAL_STEPS, key, expiresAt: rec.expiresAt });
}

// ------------------------------------------------------------------
// REDEEM
// ------------------------------------------------------------------
async function handleRedeem({ env, reply, body, deviceId, ipH, now }) {
  const username = String(body.username || "").trim();
  const code = String(body.code || "").trim().toUpperCase();

  if (!USER_RE.test(username)) return reply({ ok: false, error: "invalid_username" }, 400);

  // Chống dò key: quá nhiều lần nhập sai từ cùng IP
  const fails = Number((await env.RATE.get("fail:" + ipH)) || 0);
  if (fails >= MAX_FAILS) return reply({ ok: false, error: "too_many" }, 429);

  if (!KEY_RE.test(code)) {
    await recordFail(env, ipH);
    return reply({ ok: false, error: "invalid_code" }, 400);
  }

  const keyName = "key:" + code;
  const rec = await readRecord(env, code);

  if (!rec) {
    await recordFail(env, ipH);
    return reply({ ok: false, error: "invalid_code" }, 400);
  }
  if (BIND_TO_DEVICE && rec.deviceId !== deviceId) {
    await recordFail(env, ipH);
    return reply({ ok: false, error: "invalid_code" }, 400); // không tiết lộ là key của người khác
  }
  if (rec.used) return reply({ ok: false, error: "used" }, 409);
  if (now > rec.expiresAt) return reply({ ok: false, error: "expired" }, 410);

  // Đánh dấu đã dùng TRƯỚC khi gửi webhook để thu hẹp khoảng hở dùng trùng
  rec.used = true;
  rec.usedAt = now;
  rec.username = username;
  await env.RATE.put(keyName, JSON.stringify(rec), { expirationTtl: KEY_RECORD_TTL });

  const keyId = (await sha256Hex(code)).slice(0, 8);
  const fields = [
    { name: "👤 Roblox Username", value: username, inline: true },
    { name: "🆔 Key ID", value: "`" + keyId + "`", inline: true },
  ];
  if (SEND_FULL_KEY) fields.push({ name: "🔑 Key", value: "`" + code + "`", inline: false });
  fields.push(
    { name: "💎 Reward", value: REWARD_TEXT, inline: true },
    { name: "🕒 Time", value: new Date(now).toISOString().replace("T", " ").slice(0, 19) + " UTC", inline: true },
    { name: "✅ Status", value: "VERIFIED", inline: true },
  );

  let hookOk = false;
  try {
    const res = await fetch(env.WEBHOOK_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        allowed_mentions: { parse: [] },
        embeds: [{ title: "🎉 REDEEM SUCCESSFUL", color: 5763719, fields }],
      }),
    });
    hookOk = res.ok;
  } catch (_) {
    hookOk = false;
  }

  if (!hookOk) {
    // Hoàn lại để người dùng thử lại, không mất key
    rec.used = false;
    delete rec.usedAt;
    delete rec.username;
    await env.RATE.put(keyName, JSON.stringify(rec), { expirationTtl: KEY_RECORD_TTL });
    return reply({ ok: false, error: "webhook" }, 502);
  }

  return reply({ ok: true });
}

// ------------------------------------------------------------------
// API TRANG ĐẾM NGƯỢC (gọi từ trang xác minh, không cần deviceId: mã s đã chứa và được ký)
//   POST /task/begin     {s}          -> {ok, begin, seconds}   (bắt đầu đếm)
//   POST /task/complete  {s, begin}   -> {ok}                   (đã đủ thời gian, ghi nhận cho hệ thống get key)
// ------------------------------------------------------------------
async function handleTaskBegin({ env, reply, body, now }) {
  const t = await parseVisitToken(env, body.s, now);
  if (!t || STEP_TYPES[t.step] !== "countdown") return reply({ ok: false, error: "invalid_token" }, 400);

  const sig = (await hmacHex(env.VISIT_SECRET, "b|" + t.p + "|" + now)).slice(0, 32);
  return reply({ ok: true, begin: now + "." + sig, seconds: VISIT_COUNTDOWN_SECONDS });
}

async function handleTaskComplete({ env, reply, body, now }) {
  const t = await parseVisitToken(env, body.s, now);
  if (!t) return reply({ ok: false, error: "invalid_token" }, 400);

  const [tsStr, bsig] = String(body.begin || "").split(".");
  const ts = Number(tsStr);
  if (!Number.isFinite(ts) || !bsig) return reply({ ok: false, error: "invalid_token" }, 400);

  const expect = (await hmacHex(env.VISIT_SECRET, "b|" + t.p + "|" + tsStr)).slice(0, 32);
  if (!safeEqual(bsig, expect)) return reply({ ok: false, error: "invalid_token" }, 400);

  const elapsed = now - ts;
  if (elapsed < VISIT_COUNTDOWN_SECONDS * 1000) return reply({ ok: false, error: "too_fast" }, 429);
  if (elapsed > VISIT_TOKEN_TTL_MS) return reply({ ok: false, error: "expired" }, 410);

  if (STEP_TYPES[t.step] !== "countdown") return reply({ ok: false, error: "invalid_token" }, 400);

  // Không cần ghi KV: mã dùng một lần được tính từ khóa bí mật, chỉ trả về sau khi đủ thời gian
  const allowed = (env.ALLOWED_ORIGIN || "").replace(/\/$/, "");
  const nonce = await countdownNonce(env, t.deviceId, t.step, t.issuedAt);
  return reply({ ok: true, next: allowed + GETKEY_PATH + "?step=" + t.step + "&n=" + nonce });
}

function toB64Url(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64Url(b64) {
  let x = String(b64).replace(/-/g, "+").replace(/_/g, "/");
  while (x.length % 4) x += "=";
  return atob(x);
}

async function hmacHex(secret, data) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  return [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Mã s = base64url("deviceId|step|issuedAt") + "." + chữ ký HMAC
async function makeVisitToken(env, deviceId, step, issuedAt) {
  const p = toB64Url(deviceId + "|" + step + "|" + issuedAt);
  const sig = (await hmacHex(env.VISIT_SECRET, p)).slice(0, 32);
  return p + "." + sig;
}

async function parseVisitToken(env, token, now) {
  const str = String(token || "");
  if (str.length > 300) return null;
  const parts = str.split(".");
  if (parts.length !== 2) return null;
  const [p, sig] = parts;

  const expect = (await hmacHex(env.VISIT_SECRET, p)).slice(0, 32);
  if (!safeEqual(sig, expect)) return null;

  let payload;
  try { payload = fromB64Url(p); } catch (_) { return null; }
  const [deviceId, stepStr, issuedStr] = payload.split("|");
  const step = Number(stepStr);
  const issuedAt = Number(issuedStr);

  if (!DEVICE_RE.test(deviceId || "")) return null;
  if (!Number.isInteger(step) || step < 1 || step > TOTAL_STEPS) return null;
  if (!Number.isFinite(issuedAt) || issuedAt > now + 60000 || now - issuedAt > VISIT_TOKEN_TTL_MS) return null;

  return { deviceId, step, issuedAt, p };
}

// Mã dùng một lần của bước đếm ngược, tính từ khóa bí mật + thiết bị + bước + thời điểm cấp
async function countdownNonce(env, deviceId, step, issuedAt) {
  const p = toB64Url(deviceId + "|" + step + "|" + issuedAt);
  return (await hmacHex(env.VISIT_SECRET, "n|" + p)).slice(0, 32);
}

function addQueryParam(url, key, value) {
  return url + (url.includes("?") ? "&" : "?") + key + "=" + encodeURIComponent(value);
}

// ------------------------------------------------------------------
// LINKVERTISE ANTI-BYPASS
// ------------------------------------------------------------------
async function verifyLinkvertiseHash(env, hash) {
  if (!env.LINKVERTISE_TOKEN) return { valid: null };

  const url = LINKVERTISE_VERIFY_URL +
    "?token=" + encodeURIComponent(String(env.LINKVERTISE_TOKEN).trim()) +
    "&hash=" + encodeURIComponent(hash);

  let res;
  try {
    res = await fetch(url);
  } catch (err) {
    console.error("[redeem] không gọi được Linkvertise: " + ((err && err.message) || err));
    return { valid: false, reason: "lv_fetch_error" };
  }

  const raw = (await res.text()).trim();
  // Không ghi token vào log; chỉ ghi trạng thái và phần đầu của phản hồi
  console.log("[redeem] linkvertise status=" + res.status + " body=" + raw.slice(0, 120));
  if (!res.ok) return { valid: false, reason: "lv_http_" + res.status + ": " + raw.slice(0, 60) };

  let parsed = null;
  try { parsed = JSON.parse(raw); } catch (_) {}
  if (parsed === true || (parsed && typeof parsed === "object" && parsed.status === true)) return { valid: true };
  if (raw.replace(/"/g, "").toUpperCase() === "TRUE") return { valid: true };
  return { valid: false, reason: "lv_said: " + raw.slice(0, 60) };
}

// ------------------------------------------------------------------
// LINK4SUB API
// ------------------------------------------------------------------
async function createLink4SubLink(env, payload) {
  const apiToken = cleanToken(env.LINK4SUB_API_TOKEN);
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), L4S_TIMEOUT_MS);
  try {
    const headers = {
      "Authorization": "Bearer " + apiToken,
      "Content-Type": "application/json",
    };
    const bodyText = JSON.stringify(payload);

    // Tự xử lý chuyển hướng: fetch mặc định sẽ bỏ header Authorization nếu bị chuyển sang tên miền khác
    // (ví dụ link4sub.com -> www.link4sub.com). Ở đây chỉ đi theo nếu vẫn thuộc link4sub.com.
    let url = L4S_API;
    let hops = 0;
    let res;
    for (; hops < 3; hops++) {
      res = await fetch(url, { method: "POST", headers, body: bodyText, signal: ctrl.signal, redirect: "manual" });
      const loc = res.headers.get("Location");
      if (res.status >= 300 && res.status < 400 && loc) {
        const next = new URL(loc, url).toString();
        if (!/^https:\/\/([a-z0-9-]+\.)*link4sub\.com\//i.test(next)) {
          return { ok: false, reason: "l4s_redirect_blocked " + res.status };
        }
        url = next;
        continue;
      }
      break;
    }

    const text = await res.text();
    // Không ghi token vào log; chỉ ghi trạng thái và phần đầu phản hồi
    console.log("[redeem] link4sub status=" + res.status + " hops=" + hops + " url=" + url + " body=" + text.slice(0, 200));

    let json = null;
    try { json = JSON.parse(text); } catch (_) {}

    if (!res.ok || !json || json.success !== true || !json.data || typeof json.data.shortUrl !== "string") {
      return {
        ok: false,
        reason: "l4s_" + res.status + " len=" + apiToken.length + " tail=" + apiToken.slice(-4) + " hops=" + hops + ": " + text.slice(0, 40),
      };
    }

    // Chỉ chấp nhận link https thuộc link4sub.com
    const shortUrl = json.data.shortUrl;
    if (!/^https:\/\/([a-z0-9-]+\.)*link4sub\.com\//i.test(shortUrl)) {
      return { ok: false, reason: "bad_short_url" };
    }
    return { ok: true, shortUrl };
  } catch (err) {
    console.error("[redeem] không gọi được Link4Sub: " + ((err && err.message) || err));
    return { ok: false, reason: "l4s_fetch_error" };
  } finally {
    clearTimeout(timer);
  }
}

// ------------------------------------------------------------------
// TIỆN ÍCH
// ------------------------------------------------------------------
function generateKey() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // 32 ký tự, bỏ I/O/0/1 cho dễ đọc
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  const c = [...bytes].map((b) => alphabet[b % 32]); // 256 chia hết cho 32 nên không bị lệch
  return "RK-" + c.slice(0, 4).join("") + "-" + c.slice(4, 8).join("") + "-" + c.slice(8, 12).join("");
}

// Mỗi key là ngẫu nhiên mật mã; vẫn kiểm tra trùng trong KV để đảm bảo không ai nhận cùng một key
async function generateUniqueKey(env) {
  for (let i = 0; i < 5; i++) {
    const key = generateKey();
    if (!(await env.RATE.get("key:" + key))) return key;
  }
  return null;
}

// Làm sạch token: bỏ khoảng trắng/xuống dòng, dấu ngoặc kép và chữ "Bearer " nếu lỡ dán vào Secret
function cleanToken(t) {
  return String(t || "").trim().replace(/^["']+|["']+$/g, "").replace(/^Bearer\s+/i, "").trim();
}

function randomHex(bytes) {
  return [...crypto.getRandomValues(new Uint8Array(bytes))].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// So sánh chuỗi không phụ thuộc thời gian
function safeEqual(a, b) {
  const x = new TextEncoder().encode(String(a));
  const y = new TextEncoder().encode(String(b));
  let diff = x.length ^ y.length;
  const n = Math.max(x.length, y.length);
  for (let i = 0; i < n; i++) diff |= (x[i] || 0) ^ (y[i] || 0);
  return diff === 0;
}

async function getProgress(env, deviceId) {
  const raw = await env.RATE.get("prog:" + deviceId);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

async function putProgress(env, deviceId, prog) {
  await env.RATE.put("prog:" + deviceId, JSON.stringify(prog), { expirationTtl: PROGRESS_TTL_SECONDS });
}

async function getActiveKey(env, deviceId, now) {
  const key = await env.RATE.get("devkey:" + deviceId);
  if (!key) return null;
  const rec = await readRecord(env, key);
  if (rec && !rec.used && now < rec.expiresAt) return { key, rec };
  return null;
}

function keyReply(active) {
  return { ok: true, step: TOTAL_STEPS, key: active.key, expiresAt: active.rec.expiresAt, reused: true };
}

async function readRecord(env, key) {
  const raw = await env.RATE.get("key:" + key);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch (_) {
    return null;
  }
}

async function recordFail(env, ipH) {
  const k = "fail:" + ipH;
  const n = Number((await env.RATE.get(k)) || 0) + 1;
  await env.RATE.put(k, String(n), { expirationTtl: FAIL_WINDOW_SECONDS });
}

async function sha256Hex(text) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
