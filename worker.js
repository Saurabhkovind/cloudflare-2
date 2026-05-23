// ═══════════════════════════════════════════════════════════
//  NexIIT Backend Worker v7.0
//  Cloudflare Workers + D1
//
//  AUTH:    SMS OTP · Email OTP · Telegram · Guest (local)
//  ROOMS:   Telegram-backed chat with D1 relay cache
//  NOTES:   PDF + HTML via Telegram storage
//  MUSIC:   Study tracks via Telegram storage
//  CHAPTERS:D1-backed with static fallback
//  LEADERBOARD: XP-based ranking
//  SECURITY:CORS origin check · Rate limiting · Session-based identity
// ═══════════════════════════════════════════════════════════

// ─── ALLOWED ORIGINS ───────────────────────────────────────
const ALLOWED_ORIGINS = [
  "https://nexiit.netlify.app",
  "https://nexiit.pages.dev",
];
// Add your custom domain here when you have one

function getCors(req) {
  const origin  = req.headers.get("Origin") || "";
  const allowed = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin":   allowed,
    "Access-Control-Allow-Methods":  "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":  "Content-Type, Range, X-Auth-Token",
    "Access-Control-Expose-Headers": "Content-Length, Content-Range, Accept-Ranges",
    "Vary": "Origin",
  };
}

// ─── RESPONSE HELPERS ──────────────────────────────────────
function json(data, status = 200, cors = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...cors,
      "Content-Type":           "application/json",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options":        "DENY",
      "Referrer-Policy":        "no-referrer",
    },
  });
}

// ─── UTILITIES ─────────────────────────────────────────────
function generateToken() {
  const arr = new Uint8Array(32);
  crypto.getRandomValues(arr);
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}

function generateOtp() {
  // Cryptographically secure — Math.random() is NOT safe
  const arr = new Uint8Array(3);
  crypto.getRandomValues(arr);
  const num = ((arr[0] << 16) | (arr[1] << 8) | arr[2]) % 900000 + 100000;
  return num.toString();
}

function formatSize(bytes) {
  if (!bytes) return "";
  if (bytes < 1024)        return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function getRooms(env) {
  return { "ARAVALLI": env.ARAVALLI_CHAT_ID };
}

// ─── SESSION MANAGEMENT ────────────────────────────────────
async function verifySession(req, env) {
  const token = req.headers.get("X-Auth-Token");
  if (!token) return null;
  // Reject guest tokens — they are local-only, never sent to backend
  if (token.startsWith("guest_token_")) return null;
  try {
    const session = await env.DB.prepare(
      `SELECT * FROM sessions WHERE token=? AND expires_at > ?`
    ).bind(token, Date.now()).first();
    return session || null;
  } catch {
    return null;
  }
}

// Blocks unauthenticated AND guest users
async function requireAuth(req, env) {
  const session = await verifySession(req, env);
  if (!session)                          return json({ ok: false, error: "Authentication required" }, 401);
  if (session.user_type === "guest")     return json({ ok: false, error: "Login required to access this feature" }, 403);
  return null; // null = allowed
}

// Blocks only unauthenticated — allows guest
async function requireAnyAuth(req, env) {
  const session = await verifySession(req, env);
  if (!session) return json({ ok: false, error: "Authentication required" }, 401);
  return null;
}

// ─── RATE LIMITING HELPER ──────────────────────────────────
async function checkRateLimit(env, key, windowMs = 60000) {
  try {
    const record = await env.DB.prepare(
      `SELECT expires_at FROM otp_store WHERE id=?`
    ).bind(key).first();
    if (record) {
      const sentAt = record.expires_at - 10 * 60 * 1000;
      if (Date.now() - sentAt < windowMs) return false; // rate limited
    }
  } catch {}
  return true; // allowed
}

// ═══════════════════════════════════════════════════════════
//  AUTH HANDLERS
// ═══════════════════════════════════════════════════════════

// ─── SEND SMS OTP ──────────────────────────────────────────
async function handleSendSmsOtp(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid request body" }, 400); }

  const { phone } = body;
  if (!phone || !/^[6-9]\d{9}$/.test(phone))
    return json({ ok: false, error: "Enter a valid 10 digit Indian mobile number" }, 400);

  // Rate limit — 1 OTP per 60 seconds per number
  const allowed = await checkRateLimit(env, "sms_" + phone, 60000);
  if (!allowed) return json({ ok: false, error: "Please wait 60 seconds before requesting another OTP" }, 429);

  const otp     = generateOtp();
  const expires = Date.now() + 10 * 60 * 1000;

  try {
    await env.DB.prepare(
      `INSERT OR REPLACE INTO otp_store (id, otp, expires_at, attempts) VALUES (?, ?, ?, 0)`
    ).bind("sms_" + phone, otp, expires).run();
  } catch (e) {
    return json({ ok: false, error: "Database error" }, 500);
  }

  try {
    const smsRes  = await fetch(
      `https://www.fast2sms.com/dev/bulkV2?authorization=${env.FAST2SMS_KEY}&variables_values=${otp}&route=otp&numbers=${phone}`,
      { method: "GET" }
    );
    const smsData = await smsRes.json();
    if (!smsData.return) return json({ ok: false, error: "SMS could not be sent. Please try again." }, 500);
  } catch (e) {
    return json({ ok: false, error: "SMS service unavailable. Please try again." }, 500);
  }

  return json({ ok: true, message: "OTP sent — valid for 10 minutes" });
}

// ─── VERIFY SMS OTP ────────────────────────────────────────
async function handleVerifySmsOtp(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid request body" }, 400); }

  const { phone, otp, name } = body;
  if (!phone || !otp) return json({ ok: false, error: "Phone and OTP are required" }, 400);

  try {
    const record = await env.DB.prepare(`SELECT * FROM otp_store WHERE id=?`).bind("sms_" + phone).first();
    if (!record)                        return json({ ok: false, error: "OTP not found — please request a new one" }, 404);
    if (Date.now() > record.expires_at) return json({ ok: false, error: "OTP has expired — please request a new one" }, 400);
    if (record.attempts >= 3)           return json({ ok: false, error: "Too many incorrect attempts — please request a new OTP" }, 429);
    if (record.otp !== otp) {
      await env.DB.prepare(`UPDATE otp_store SET attempts=attempts+1 WHERE id=?`).bind("sms_" + phone).run();
      return json({ ok: false, error: "Incorrect OTP" }, 400);
    }
    await env.DB.prepare(`DELETE FROM otp_store WHERE id=?`).bind("sms_" + phone).run();

    const token    = generateToken();
    const now      = Date.now();
    const expires  = now + 30 * 24 * 60 * 60 * 1000; // 30 days
    const userId   = "sms_" + phone;
    const userName = (name || "").trim() || ("User_" + phone.slice(-4));

    // Upsert user record
    await env.DB.prepare(
      `INSERT OR REPLACE INTO users (id, name, type, phone, xp, streak, created_at, last_seen)
       VALUES (?, ?, 'sms', ?, COALESCE((SELECT xp FROM users WHERE id=?), 0),
       COALESCE((SELECT streak FROM users WHERE id=?), 0), ?, ?)`
    ).bind(userId, userName, phone, userId, userId, now, now).run().catch(() => {});

    await env.DB.prepare(
      `INSERT OR REPLACE INTO sessions (token, user_id, user_name, user_type, phone, created_at, expires_at)
       VALUES (?, ?, ?, 'sms', ?, ?, ?)`
    ).bind(token, userId, userName, phone, now, expires).run();

    return json({ ok: true, token, user: { id: userId, name: userName, type: "sms", phone } });
  } catch (e) {
    return json({ ok: false, error: "Server error. Please try again." }, 500);
  }
}

// ─── SEND EMAIL OTP ────────────────────────────────────────
async function handleSendEmailOtp(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid request body" }, 400); }

  const { email } = body;
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))
    return json({ ok: false, error: "Enter a valid email address" }, 400);

  // Rate limit — 1 OTP per 60 seconds
  const allowed = await checkRateLimit(env, "email_" + email, 60000);
  if (!allowed) return json({ ok: false, error: "Please wait 60 seconds before requesting another OTP" }, 429);

  const otp     = generateOtp();
  const expires = Date.now() + 10 * 60 * 1000;

  try {
    await env.DB.prepare(
      `INSERT OR REPLACE INTO otp_store (id, otp, expires_at, attempts) VALUES (?, ?, ?, 0)`
    ).bind("email_" + email, otp, expires).run();
  } catch (e) {
    return json({ ok: false, error: "Database error" }, 500);
  }

  try {
    const mailRes = await fetch("https://api.brevo.com/v3/smtp/email", {
      method: "POST",
      headers: { "api-key": env.BREVO_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({
        sender:      { name: "NexIIT", email: "noreply@nexiit.in" },
        to:          [{ email }],
        subject:     "NexIIT — Your Verification Code",
        htmlContent: `
          <div style="font-family:'Segoe UI',sans-serif;max-width:420px;margin:auto;padding:32px;background:#0a0a0f;color:#f1f0ff;border-radius:16px;border:1px solid rgba(124,92,252,0.2)">
            <div style="font-size:28px;font-weight:700;margin-bottom:4px;color:#a78bfa">NexIIT</div>
            <div style="font-size:12px;color:#7b7a9a;margin-bottom:28px;letter-spacing:2px;text-transform:uppercase">Learn · Understand · Master</div>
            <p style="font-size:14px;color:#7b7a9a;margin-bottom:12px">Your verification code:</p>
            <div style="font-size:48px;font-weight:700;letter-spacing:12px;color:#a78bfa;margin-bottom:20px">${otp}</div>
            <p style="font-size:12px;color:#3d3c55">Valid for 10 minutes. Do not share this code with anyone.</p>
          </div>
        `,
      }),
    });
    if (!mailRes.ok) return json({ ok: false, error: "Email could not be sent. Please try again." }, 500);
  } catch (e) {
    return json({ ok: false, error: "Email service unavailable." }, 500);
  }

  return json({ ok: true, message: "OTP sent to your email — valid for 10 minutes" });
}

// ─── VERIFY EMAIL OTP ──────────────────────────────────────
async function handleVerifyEmailOtp(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid request body" }, 400); }

  const { email, otp, name } = body;
  if (!email || !otp) return json({ ok: false, error: "Email and OTP are required" }, 400);

  try {
    const record = await env.DB.prepare(`SELECT * FROM otp_store WHERE id=?`).bind("email_" + email).first();
    if (!record)                        return json({ ok: false, error: "OTP not found — please request a new one" }, 404);
    if (Date.now() > record.expires_at) return json({ ok: false, error: "OTP has expired — please request a new one" }, 400);
    if (record.attempts >= 3)           return json({ ok: false, error: "Too many incorrect attempts — please request a new OTP" }, 429);
    if (record.otp !== otp) {
      await env.DB.prepare(`UPDATE otp_store SET attempts=attempts+1 WHERE id=?`).bind("email_" + email).run();
      return json({ ok: false, error: "Incorrect OTP" }, 400);
    }
    await env.DB.prepare(`DELETE FROM otp_store WHERE id=?`).bind("email_" + email).run();

    const token    = generateToken();
    const now      = Date.now();
    const expires  = now + 30 * 24 * 60 * 60 * 1000;
    const userId   = "email_" + email;
    const userName = (name || "").trim() || email.split("@")[0];

    await env.DB.prepare(
      `INSERT OR REPLACE INTO users (id, name, type, email, xp, streak, created_at, last_seen)
       VALUES (?, ?, 'email', ?, COALESCE((SELECT xp FROM users WHERE id=?), 0),
       COALESCE((SELECT streak FROM users WHERE id=?), 0), ?, ?)`
    ).bind(userId, userName, email, userId, userId, now, now).run().catch(() => {});

    await env.DB.prepare(
      `INSERT OR REPLACE INTO sessions (token, user_id, user_name, user_type, email, created_at, expires_at)
       VALUES (?, ?, ?, 'email', ?, ?, ?)`
    ).bind(token, userId, userName, email, now, expires).run();

    return json({ ok: true, token, user: { id: userId, name: userName, type: "email", email } });
  } catch (e) {
    return json({ ok: false, error: "Server error. Please try again." }, 500);
  }
}

// ─── TELEGRAM AUTH ─────────────────────────────────────────
async function handleTelegramAuth(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid request body" }, 400); }

  const { id, first_name, last_name, username, hash, auth_date } = body;
  if (!id || !hash) return json({ ok: false, error: "Invalid Telegram data" }, 400);

  // HMAC-SHA256 signature verification (Telegram Login Widget spec)
  const checkArr = Object.entries({ auth_date, first_name, id, last_name, username })
    .filter(([, v]) => v !== undefined && v !== null && v !== "")
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join("\n");

  const botTokenBytes = new TextEncoder().encode(env.BOT_TOKEN);
  const secretKey     = await crypto.subtle.digest("SHA-256", botTokenBytes);
  const hmacKey       = await crypto.subtle.importKey("raw", secretKey, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig           = await crypto.subtle.sign("HMAC", hmacKey, new TextEncoder().encode(checkArr));
  const computed      = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");

  if (computed !== hash)
    return json({ ok: false, error: "Invalid Telegram signature" }, 401);
  if (Date.now() / 1000 - parseInt(auth_date) > 86400)
    return json({ ok: false, error: "Telegram session expired — please login again" }, 401);

  const token    = generateToken();
  const now      = Date.now();
  const expires  = now + 30 * 24 * 60 * 60 * 1000;
  const userId   = "tg_" + id;
  const userName = first_name + (last_name ? " " + last_name : "");

  try {
    await env.DB.prepare(
      `INSERT OR REPLACE INTO users (id, name, type, telegram_id, xp, streak, created_at, last_seen)
       VALUES (?, ?, 'telegram', ?, COALESCE((SELECT xp FROM users WHERE id=?), 0),
       COALESCE((SELECT streak FROM users WHERE id=?), 0), ?, ?)`
    ).bind(userId, userName, String(id), userId, userId, now, now).run().catch(() => {});

    await env.DB.prepare(
      `INSERT OR REPLACE INTO sessions (token, user_id, user_name, user_type, created_at, expires_at)
       VALUES (?, ?, ?, 'telegram', ?, ?)`
    ).bind(token, userId, userName, now, expires).run();
  } catch (e) {
    return json({ ok: false, error: "Database error" }, 500);
  }

  return json({ ok: true, token, user: { id: userId, name: userName, type: "telegram", username } });
}

// ─── VERIFY TOKEN ──────────────────────────────────────────
async function handleVerifyToken(req, env) {
  const session = await verifySession(req, env);
  if (!session) return json({ ok: false, error: "Invalid or expired session" }, 401);

  // Update last_seen
  await env.DB.prepare(`UPDATE users SET last_seen=? WHERE id=?`).bind(Date.now(), session.user_id).run().catch(() => {});

  // Fetch full user profile
  const user = await env.DB.prepare(`SELECT * FROM users WHERE id=?`).bind(session.user_id).first().catch(() => null);

  return json({ ok: true, user: {
    id:          session.user_id,
    name:        session.user_name,
    type:        session.user_type,
    phone:       session.phone   || null,
    email:       session.email   || null,
    xp:          user?.xp        || 0,
    streak:      user?.streak    || 0,
    exam:        user?.exam      || null,
    class:       user?.class     || null,
    target_year: user?.target_year || null,
    plan:        user?.plan      || "free",
    solved:      user?.solved    || 0,
    accuracy:    user?.accuracy  || 0,
  }});
}

// ─── LOGOUT ────────────────────────────────────────────────
async function handleLogout(req, env) {
  const token = req.headers.get("X-Auth-Token");
  if (token) await env.DB.prepare(`DELETE FROM sessions WHERE token=?`).bind(token).run().catch(() => {});
  return json({ ok: true });
}

// ─── UPDATE PROFILE ────────────────────────────────────────
async function handleUpdateProfile(req, env) {
  const guard = await requireAnyAuth(req, env);
  if (guard) return guard;
  const session = await verifySession(req, env);

  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid request body" }, 400); }

  const allowed = ["name", "exam", "class", "target_year"];
  const updates = Object.fromEntries(Object.entries(body).filter(([k]) => allowed.includes(k)));
  if (!Object.keys(updates).length) return json({ ok: false, error: "No valid fields to update" }, 400);

  // Sanitize name
  if (updates.name && (updates.name.length < 2 || updates.name.length > 40))
    return json({ ok: false, error: "Name must be 2–40 characters" }, 400);

  const setClauses = Object.keys(updates).map(k => `${k}=?`).join(", ");
  const values     = [...Object.values(updates), session.user_id];

  try {
    await env.DB.prepare(`UPDATE users SET ${setClauses} WHERE id=?`).bind(...values).run();
    if (updates.name) {
      await env.DB.prepare(`UPDATE sessions SET user_name=? WHERE user_id=?`).bind(updates.name, session.user_id).run();
    }
    return json({ ok: true });
  } catch (e) {
    return json({ ok: false, error: "Database error" }, 500);
  }
}

// ═══════════════════════════════════════════════════════════
//  CHAPTERS
// ═══════════════════════════════════════════════════════════

const STATIC_CHAPTERS = {
  Physics: [
    { id: "physics_motion",       name: "Laws of Motion",          status: "free", lectures_count: 0 },
    { id: "physics_kinematics",   name: "Kinematics",              status: "free", lectures_count: 0 },
    { id: "physics_thermo",       name: "Thermodynamics",          status: "free", lectures_count: 0 },
    { id: "physics_electro",      name: "Electrostatics",          status: "free", lectures_count: 0 },
    { id: "physics_current",      name: "Current Electricity",     status: "free", lectures_count: 0 },
    { id: "physics_waves",        name: "Waves & Sound",           status: "free", lectures_count: 0 },
    { id: "physics_optics",       name: "Ray Optics",              status: "free", lectures_count: 0 },
    { id: "physics_modern",       name: "Modern Physics",          status: "free", lectures_count: 0 },
  ],
  Chemistry: [
    { id: "chem_periodic",        name: "Periodic Table",          status: "free", lectures_count: 0 },
    { id: "chem_bonding",         name: "Chemical Bonding",        status: "free", lectures_count: 0 },
    { id: "chem_thermo",          name: "Thermochemistry",         status: "free", lectures_count: 0 },
    { id: "chem_equilibrium",     name: "Chemical Equilibrium",    status: "free", lectures_count: 0 },
    { id: "chem_electrochemistry",name: "Electrochemistry",        status: "free", lectures_count: 0 },
    { id: "chem_organic",         name: "Organic Chemistry",       status: "free", lectures_count: 0 },
    { id: "chem_solutions",       name: "Solutions",               status: "free", lectures_count: 0 },
  ],
  Maths: [
    { id: "maths_sets",           name: "Sets & Relations",        status: "free", lectures_count: 0 },
    { id: "maths_trigonometry",   name: "Trigonometry",            status: "free", lectures_count: 0 },
    { id: "maths_calculus",       name: "Calculus",                status: "free", lectures_count: 0 },
    { id: "maths_vectors",        name: "Vectors & 3D",            status: "free", lectures_count: 0 },
    { id: "maths_probability",    name: "Probability",             status: "free", lectures_count: 0 },
    { id: "maths_matrices",       name: "Matrices & Determinants", status: "free", lectures_count: 0 },
    { id: "maths_coordinate",     name: "Coordinate Geometry",     status: "free", lectures_count: 0 },
  ],
};

async function handleChaptersList(req, env) {
  const subject = new URL(req.url).searchParams.get("subject");
  try {
    let rows;
    if (subject) rows = await env.DB.prepare(`SELECT * FROM chapters WHERE subject=? ORDER BY sort_order ASC, id ASC`).bind(subject).all();
    else         rows = await env.DB.prepare(`SELECT * FROM chapters ORDER BY subject ASC, sort_order ASC`).all();
    const dbChapters = rows.results || [];
    if (dbChapters.length > 0) return json({ ok: true, chapters: dbChapters });
    const fallback = subject ? (STATIC_CHAPTERS[subject] || []) : Object.values(STATIC_CHAPTERS).flat();
    return json({ ok: true, chapters: fallback.map(c => ({ ...c, subject: subject || c.id.split("_")[0] })) });
  } catch(e) {
    const fallback = subject ? (STATIC_CHAPTERS[subject] || []) : Object.values(STATIC_CHAPTERS).flat();
    return json({ ok: true, chapters: fallback });
  }
}

async function handleChaptersAdd(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400); }
  if (body.admin_key !== env.ADMIN_KEY) return json({ ok: false, error: "Unauthorized" }, 401);

  const { id, name, subject, status = "free", sort_order = 0, lectures_count = 0 } = body;
  if (!id || !name || !subject) return json({ ok: false, error: "id, name, subject required" }, 400);

  try {
    await env.DB.prepare(
      `INSERT OR REPLACE INTO chapters (id, name, subject, status, sort_order, lectures_count) VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(id, name, subject, status, sort_order, lectures_count).run();
    return json({ ok: true });
  } catch (e) {
    return json({ ok: false, error: "Database error" }, 500);
  }
}

async function handleChaptersDelete(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400); }
  if (body.admin_key !== env.ADMIN_KEY) return json({ ok: false, error: "Unauthorized" }, 401);
  if (!body.id) return json({ ok: false, error: "id required" }, 400);
  try {
    await env.DB.prepare(`DELETE FROM chapters WHERE id=?`).bind(body.id).run();
    return json({ ok: true });
  } catch (e) { return json({ ok: false, error: "Database error" }, 500); }
}

// ═══════════════════════════════════════════════════════════
//  LEADERBOARD
// ═══════════════════════════════════════════════════════════
async function handleLeaderboard(req, env) {
  const url    = new URL(req.url);
  const period = url.searchParams.get("period") || "weekly";
  const limit  = Math.min(parseInt(url.searchParams.get("limit") || "20"), 50);

  try {
    let rows;
    if (period === "weekly") {
      const weekStart = Date.now() - 7 * 24 * 60 * 60 * 1000;
      rows = await env.DB.prepare(
        `SELECT user_id, user_name, SUM(xp_delta) as xp FROM xp_log WHERE created_at > ? GROUP BY user_id ORDER BY xp DESC LIMIT ?`
      ).bind(weekStart, limit).all();
    } else if (period === "monthly") {
      const monthStart = Date.now() - 30 * 24 * 60 * 60 * 1000;
      rows = await env.DB.prepare(
        `SELECT user_id, user_name, SUM(xp_delta) as xp FROM xp_log WHERE created_at > ? GROUP BY user_id ORDER BY xp DESC LIMIT ?`
      ).bind(monthStart, limit).all();
    } else {
      rows = await env.DB.prepare(
        `SELECT id as user_id, name as user_name, xp FROM users WHERE type != 'guest' ORDER BY xp DESC LIMIT ?`
      ).bind(limit).all();
    }
    return json({ ok: true, leaderboard: rows.results || [] });
  } catch (e) {
    return json({ ok: true, leaderboard: [] });
  }
}

// ─── ADD XP ────────────────────────────────────────────────
async function handleAddXp(req, env) {
  const guard = await requireAnyAuth(req, env);
  if (guard) return guard;
  const session = await verifySession(req, env);
  if (session.user_type === "guest") return json({ ok: false, error: "Guests cannot earn XP" }, 403);

  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400); }
  const delta  = Math.min(Math.max(parseInt(body.xp) || 0, 0), 500); // max 500 XP per action
  const reason = (body.reason || "action").slice(0, 50);
  if (!delta) return json({ ok: false, error: "xp must be > 0" }, 400);

  try {
    await env.DB.prepare(`UPDATE users SET xp = xp + ? WHERE id=?`).bind(delta, session.user_id).run();
    await env.DB.prepare(
      `INSERT INTO xp_log (user_id, user_name, xp_delta, reason, created_at) VALUES (?, ?, ?, ?, ?)`
    ).bind(session.user_id, session.user_name, delta, reason, Date.now()).run();
    const user = await env.DB.prepare(`SELECT xp, streak FROM users WHERE id=?`).bind(session.user_id).first();
    return json({ ok: true, xp: user?.xp || 0 });
  } catch (e) {
    return json({ ok: false, error: "Database error" }, 500);
  }
}

// ═══════════════════════════════════════════════════════════
//  ROOM (CHAT)
// ═══════════════════════════════════════════════════════════

async function handleSend(req, env) {
  const guard = await requireAuth(req, env);
  if (guard) return guard;
  const session = await verifySession(req, env); // get session for identity

  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400); }

  const { room_id, text, reply_to_id } = body;
  // Identity from SESSION — never trust client body for this
  const sender_id   = session.user_id;
  const sender_name = session.user_name;

  if (!room_id || !text)          return json({ ok: false, error: "room_id and text required" }, 400);
  if (text.length > 2000)         return json({ ok: false, error: "Message cannot exceed 2000 characters" }, 400);
  if (text.trim().length === 0)   return json({ ok: false, error: "Message cannot be empty" }, 400);

  const ROOMS  = getRooms(env);
  const TG_API = `https://api.telegram.org/bot${env.BOT_TOKEN}`;
  const chatId = ROOMS[room_id];
  if (!chatId) return json({ ok: false, error: "Room not found" }, 404);

  const now = Math.floor(Date.now() / 1000);
  let result;
  try {
    result = await env.DB.prepare(
      `INSERT INTO messages (room_id, sender_id, sender_name, text, msg_type, reply_to_id, created_at)
       VALUES (?, ?, ?, ?, 'text', ?, ?)`
    ).bind(room_id, sender_id, sender_name, text.trim(), reply_to_id || null, now).run();
  } catch (e) {
    return json({ ok: false, error: "Database error" }, 500);
  }

  // Fire-and-forget to Telegram
  fetch(`${TG_API}/sendMessage`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ chat_id: chatId, text: `[NEXIIT_MSG]\n👤 ${sender_name}\n💬 ${text.trim()}` }),
  }).catch(() => {});

  return json({ ok: true, id: result.meta?.last_row_id });
}

async function handleUpload(req, env) {
  const guard = await requireAuth(req, env);
  if (guard) return guard;
  const session = await verifySession(req, env);

  let formData;
  try { formData = await req.formData(); } catch { return json({ ok: false, error: "Invalid form data" }, 400); }

  const room_id     = formData.get("room_id");
  const reply_to_id = formData.get("reply_to_id") || null;
  const file        = formData.get("file");
  // Identity from SESSION
  const sender_id   = session.user_id;
  const sender_name = session.user_name;

  if (!room_id || !file) return json({ ok: false, error: "room_id and file required" }, 400);
  if (file.size > 20 * 1024 * 1024) return json({ ok: false, error: "File cannot exceed 20MB" }, 400);

  const ROOMS  = getRooms(env);
  const TG_API = `https://api.telegram.org/bot${env.BOT_TOKEN}`;
  const chatId = ROOMS[room_id];
  if (!chatId) return json({ ok: false, error: "Room not found" }, 404);

  const mime     = file.type || "application/octet-stream";
  const fileName = file.name || "file";
  const fileSize = formatSize(file.size);
  const now      = Math.floor(Date.now() / 1000);

  let msgType = "doc", tgMethod = "sendDocument", tgField = "document";
  if (mime.startsWith("image/"))      { msgType = "image"; tgMethod = "sendPhoto";    tgField = "photo";    }
  else if (mime.startsWith("video/")) { msgType = "video"; tgMethod = "sendVideo";    tgField = "video";    }
  else if (mime.startsWith("audio/")) { msgType = "audio"; tgMethod = "sendAudio";    tgField = "audio";    }

  const tgForm = new FormData();
  tgForm.append("chat_id", chatId);
  tgForm.append(tgField, file, fileName);
  tgForm.append("caption", `[NEXIIT_FILE]\n👤 ${sender_name}`);

  let tgData;
  try {
    const tgRes = await fetch(`${TG_API}/${tgMethod}`, { method: "POST", body: tgForm });
    tgData = await tgRes.json();
  } catch (e) { return json({ ok: false, error: "Upload failed. Please try again." }, 500); }
  if (!tgData.ok) return json({ ok: false, error: tgData.description }, 500);

  const rm = tgData.result;
  let file_id, thumb_id;
  if (msgType === "image")      { file_id = rm.photo[rm.photo.length-1].file_id; thumb_id = rm.photo[0].file_id; }
  else if (msgType === "video") { file_id = rm.video.file_id; thumb_id = rm.video.thumbnail?.file_id || null; }
  else if (msgType === "audio") { file_id = rm.audio.file_id; }
  else                          { file_id = rm.document.file_id; thumb_id = rm.document.thumbnail?.file_id || null; }

  let dbResult;
  try {
    dbResult = await env.DB.prepare(
      `INSERT INTO messages (room_id, sender_id, sender_name, msg_type, file_id, file_name, file_size, file_mime, thumb_id, reply_to_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(room_id, sender_id, sender_name, msgType, file_id, fileName, fileSize, mime, thumb_id || null, reply_to_id, now).run();
  } catch (e) { return json({ ok: false, error: "Database error" }, 500); }

  return json({ ok: true, id: dbResult.meta?.last_row_id, file_id, msg_type: msgType });
}

async function handleMessages(req, env) {
  const guard = await requireAuth(req, env);
  if (guard) return guard;

  const url      = new URL(req.url);
  const room_id  = url.searchParams.get("room_id");
  const before   = parseInt(url.searchParams.get("before")   || "0");
  const after_id = parseInt(url.searchParams.get("after_id") || "0");
  const limit    = Math.min(parseInt(url.searchParams.get("limit") || "50"), 100);

  if (!room_id)              return json({ ok: false, error: "room_id required" }, 400);
  const ROOMS = getRooms(env);
  if (!ROOMS[room_id])       return json({ ok: false, error: "Room not found" }, 404);

  try {
    let rows;
    if (after_id > 0)      rows = await env.DB.prepare(`SELECT * FROM messages WHERE room_id=? AND id > ? ORDER BY id ASC  LIMIT ?`).bind(room_id, after_id, limit).all();
    else if (before === 0) rows = await env.DB.prepare(`SELECT * FROM messages WHERE room_id=? ORDER BY id DESC LIMIT ?`).bind(room_id, limit).all();
    else                   rows = await env.DB.prepare(`SELECT * FROM messages WHERE room_id=? AND id < ? ORDER BY id DESC LIMIT ?`).bind(room_id, before, limit).all();

    const messages = (rows.results || []).reverse();
    const hasMore  = messages.length === limit;

    // Fetch reply previews in one query
    const replyIds = messages.filter(m => m.reply_to_id).map(m => m.reply_to_id);
    let replyMap   = {};
    if (replyIds.length > 0) {
      const placeholders = replyIds.map(() => "?").join(",");
      const replyRows    = await env.DB.prepare(`SELECT id, sender_name, text, msg_type, file_name FROM messages WHERE id IN (${placeholders})`).bind(...replyIds).all();
      (replyRows.results || []).forEach(r => { replyMap[r.id] = r; });
    }

    return json({
      ok: true,
      messages: messages.map(m => ({ ...m, reply_msg: m.reply_to_id ? (replyMap[m.reply_to_id] || null) : null })),
      has_more: hasMore
    });
  } catch (e) { return json({ ok: false, error: "Database error" }, 500); }
}

async function handleDelete(req, env) {
  const guard = await requireAuth(req, env);
  if (guard) return guard;
  const session = await verifySession(req, env);

  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400); }
  const { msg_id } = body;
  if (!msg_id) return json({ ok: false, error: "msg_id required" }, 400);

  try {
    const msg = await env.DB.prepare(`SELECT sender_id FROM messages WHERE id=?`).bind(msg_id).first();
    if (!msg) return json({ ok: false, error: "Message not found" }, 404);
    // Identity check from SESSION — not from client body
    if (String(msg.sender_id) !== String(session.user_id))
      return json({ ok: false, error: "You can only delete your own messages" }, 403);
    await env.DB.prepare(`DELETE FROM messages WHERE id=?`).bind(msg_id).run();
    return json({ ok: true });
  } catch(e) { return json({ ok: false, error: "Database error" }, 500); }
}

async function handleGetFile(req, env) {
  const guard = await requireAuth(req, env);
  if (guard) return guard;

  const file_id = new URL(req.url).searchParams.get("file_id");
  if (!file_id) return json({ ok: false, error: "file_id required" }, 400);

  const TG_API = `https://api.telegram.org/bot${env.BOT_TOKEN}`;
  try {
    const res  = await fetch(`${TG_API}/getFile?file_id=${file_id}`);
    const data = await res.json();
    if (!data.ok) return json({ ok: false, error: data.description }, 500);
    return json({ ok: true, url: `https://api.telegram.org/file/bot${env.BOT_TOKEN}/${data.result.file_path}` });
  } catch (e) { return json({ ok: false, error: "Could not fetch file" }, 500); }
}

// ═══════════════════════════════════════════════════════════
//  NOTES
// ═══════════════════════════════════════════════════════════
async function handleNotesUpload(req, env) {
  let form;
  try { form = await req.formData(); } catch { return json({ ok: false, error: "Invalid form data" }, 400); }
  if (form.get("admin_key") !== env.ADMIN_KEY) return json({ ok: false, error: "Unauthorized" }, 401);

  const TG_API     = `https://api.telegram.org/bot${env.BOT_TOKEN}`;
  const chapter_id = form.get("chapter_id");
  const subject    = form.get("subject") || "General";
  const title      = form.get("title");
  const note_type  = form.get("note_type") || "pdf";
  const pages      = parseInt(form.get("pages") || "0");
  const status     = form.get("status") || "free";
  const file       = form.get("file");

  if (!chapter_id || !title || !file) return json({ ok: false, error: "chapter_id, title and file are required" }, 400);
  if (file.size > 20 * 1024 * 1024)  return json({ ok: false, error: "File cannot exceed 20MB" }, 400);

  const tgForm = new FormData();
  tgForm.append("chat_id", env.STORAGE_CHANNEL_ID);
  tgForm.append("document", file, file.name || title + ".pdf");
  tgForm.append("caption", `[NEXIIT_NOTE]\n📚 ${title}\n📖 ${subject} | ${chapter_id}`);

  let file_id;
  try {
    const tgRes  = await fetch(`${TG_API}/sendDocument`, { method: "POST", body: tgForm });
    const tgData = await tgRes.json();
    if (!tgData.ok) return json({ ok: false, error: "Telegram: " + tgData.description }, 500);
    file_id = tgData.result.document.file_id;
  } catch(e) { return json({ ok: false, error: "Upload failed" }, 500); }

  const now = Math.floor(Date.now() / 1000);
  try {
    const result = await env.DB.prepare(
      `INSERT INTO notes (chapter_id, subject, title, note_type, pages, status, file_id, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(chapter_id, subject, title, note_type, pages, status, file_id, now).run();
    return json({ ok: true, id: result.meta?.last_row_id, file_id });
  } catch(e) { return json({ ok: false, error: "Database error" }, 500); }
}

async function handleNotesUploadHtml(req, env) {
  let chapter_id, subject, title, pages, status, html_content, adminKey;
  const ct = req.headers.get("content-type") || "";

  if (ct.includes("application/json")) {
    let body;
    try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400); }
    ({ admin_key: adminKey, chapter_id, subject, title, pages, status, html_content } = body);
    subject = subject || "General"; status = status || "free";
  } else {
    let form;
    try { form = await req.formData(); } catch { return json({ ok: false, error: "Invalid form" }, 400); }
    adminKey     = form.get("admin_key");
    chapter_id   = form.get("chapter_id");
    subject      = form.get("subject") || "General";
    title        = form.get("title");
    pages        = form.get("pages");
    status       = form.get("status") || "free";
    const file   = form.get("file");
    html_content = file ? await file.text() : form.get("html_content");
  }

  if (adminKey !== env.ADMIN_KEY)         return json({ ok: false, error: "Unauthorized" }, 401);
  if (!chapter_id || !title || !html_content) return json({ ok: false, error: "chapter_id, title and html_content are required" }, 400);
  if (html_content.length > 4500000)      return json({ ok: false, error: "HTML content exceeds 4.5MB limit" }, 400);

  // Basic XSS check — reject script tags that load external resources
  if (/<script[^>]+src\s*=/i.test(html_content) && !html_content.includes("NexIIT"))
    return json({ ok: false, error: "HTML contains potentially unsafe external scripts" }, 400);

  const TG_API   = `https://api.telegram.org/bot${env.BOT_TOKEN}`;
  const htmlBlob = new Blob([html_content], { type: "text/html" });
  const safeTitle = (title || "note").replace(/[^a-zA-Z0-9_\-]/g, "_").substring(0, 50);

  const tgForm = new FormData();
  tgForm.append("chat_id", env.STORAGE_CHANNEL_ID);
  tgForm.append("document", htmlBlob, safeTitle + ".html");
  tgForm.append("caption", `[NEXIIT_NOTE_HTML]\n📚 ${title}\n📖 ${subject} | ${chapter_id}`);

  let file_id;
  try {
    const tgRes  = await fetch(`${TG_API}/sendDocument`, { method: "POST", body: tgForm });
    const tgData = await tgRes.json();
    if (!tgData.ok) return json({ ok: false, error: "Telegram: " + tgData.description }, 500);
    file_id = tgData.result.document.file_id;
  } catch(e) { return json({ ok: false, error: "Upload failed" }, 500); }

  const now = Math.floor(Date.now() / 1000);
  try {
    const result = await env.DB.prepare(
      `INSERT INTO notes (chapter_id, subject, title, note_type, pages, status, file_id, created_at)
       VALUES (?, ?, ?, 'html', ?, ?, ?, ?)`
    ).bind(chapter_id, subject, title, parseInt(pages) || 0, status, file_id, now).run();
    return json({ ok: true, id: result.meta?.last_row_id, file_id });
  } catch(e) { return json({ ok: false, error: "Database error" }, 500); }
}

async function handleNotesList(req, env) {
  const guard = await requireAuth(req, env);
  if (guard) return guard;
  const chapter_id = new URL(req.url).searchParams.get("chapter_id");
  if (!chapter_id) return json({ ok: false, error: "chapter_id required" }, 400);
  try {
    const rows = await env.DB.prepare(`SELECT * FROM notes WHERE chapter_id=? ORDER BY created_at DESC`).bind(chapter_id).all();
    return json({ ok: true, notes: rows.results || [] });
  } catch(e) { return json({ ok: false, error: "Database error" }, 500); }
}

async function handleNotesGet(req, env) {
  const guard = await requireAuth(req, env);
  if (guard) return guard;
  const id = new URL(req.url).searchParams.get("id");
  if (!id) return json({ ok: false, error: "id required" }, 400);
  const TG_API = `https://api.telegram.org/bot${env.BOT_TOKEN}`;
  try {
    const note   = await env.DB.prepare(`SELECT * FROM notes WHERE id=?`).bind(id).first();
    if (!note)   return json({ ok: false, error: "Note not found" }, 404);
    const tgRes  = await fetch(`${TG_API}/getFile?file_id=${note.file_id}`);
    const tgData = await tgRes.json();
    if (!tgData.ok) return json({ ok: false, error: "Could not fetch from Telegram" }, 500);
    const fileUrl = `https://api.telegram.org/file/bot${env.BOT_TOKEN}/${tgData.result.file_path}`;
    if (note.note_type === "html") {
      const html_content = await (await fetch(fileUrl)).text();
      return json({ ok: true, note: { ...note, html_content, file_url: fileUrl } });
    }
    return json({ ok: true, note: { ...note, file_url: fileUrl } });
  } catch(e) { return json({ ok: false, error: "Server error" }, 500); }
}

async function handleNotesDelete(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400); }
  if (body.admin_key !== env.ADMIN_KEY) return json({ ok: false, error: "Unauthorized" }, 401);
  if (!body.id) return json({ ok: false, error: "id required" }, 400);
  try {
    await env.DB.prepare(`DELETE FROM notes WHERE id=?`).bind(body.id).run();
    return json({ ok: true });
  } catch(e) { return json({ ok: false, error: "Database error" }, 500); }
}

// ═══════════════════════════════════════════════════════════
//  MUSIC
// ═══════════════════════════════════════════════════════════
const DEFAULT_TRACKS = [
  { id: "rain",       name: "Rain Sounds",   emoji: "🌧️", mood: "Calm focus"     },
  { id: "lofi",       name: "Lo-fi Beats",   emoji: "🎵", mood: "Creative"       },
  { id: "whitenoise", name: "White Noise",   emoji: "⬜", mood: "Deep focus"     },
  { id: "brownnoise", name: "Brown Noise",   emoji: "🟫", mood: "Ultra deep"     },
  { id: "cafe",       name: "Cafe Ambience", emoji: "☕", mood: "Light focus"    },
  { id: "ocean",      name: "Ocean Waves",   emoji: "🌊", mood: "Relaxed"        },
  { id: "forest",     name: "Forest Sounds", emoji: "🌿", mood: "Nature focus"   },
  { id: "piano",      name: "Piano Study",   emoji: "🎹", mood: "Concentration"  },
];

async function handleMusicList(req, env) {
  const session = await verifySession(req, env);
  const isGuest = !session || session.user_type === "guest";
  try {
    const rows  = await env.DB.prepare(`SELECT * FROM music_tracks ORDER BY sort_order ASC`).all();
    const d1Map = {};
    (rows.results || []).forEach(r => { d1Map[r.id] = r; });
    const tracks = DEFAULT_TRACKS.map(dt => {
      const d1 = d1Map[dt.id];
      return { id: dt.id, name: d1?.name || dt.name, emoji: d1?.emoji || dt.emoji, mood: d1?.mood || dt.mood, ready: !!(d1?.file_id), locked: isGuest };
    });
    return json({ ok: true, tracks });
  } catch(e) {
    return json({ ok: true, tracks: DEFAULT_TRACKS.map(dt => ({ ...dt, ready: false, locked: isGuest })) });
  }
}

async function handleMusicPlay(req, env) {
  const guard = await requireAuth(req, env);
  if (guard) return guard;
  const id = new URL(req.url).searchParams.get("id");
  if (!id) return json({ ok: false, error: "id required" }, 400);
  const TG_API = `https://api.telegram.org/bot${env.BOT_TOKEN}`;
  try {
    const track = await env.DB.prepare(`SELECT * FROM music_tracks WHERE id=?`).bind(id).first();
    if (!track || !track.file_id) return json({ ok: false, error: "Track not found" }, 404);
    const res  = await fetch(`${TG_API}/getFile?file_id=${track.file_id}`);
    const data = await res.json();
    if (!data.ok) return json({ ok: false, error: data.description }, 500);
    return json({ ok: true, url: `https://api.telegram.org/file/bot${env.BOT_TOKEN}/${data.result.file_path}`, track });
  } catch(e) { return json({ ok: false, error: "Server error" }, 500); }
}

async function handleMusicUpload(req, env) {
  let form;
  try { form = await req.formData(); } catch { return json({ ok: false, error: "Invalid form" }, 400); }
  if (form.get("admin_key") !== env.ADMIN_KEY) return json({ ok: false, error: "Unauthorized" }, 401);

  const TG_API = `https://api.telegram.org/bot${env.BOT_TOKEN}`;
  const id     = form.get("id");
  const name   = form.get("name");
  const emoji  = form.get("emoji") || "🎵";
  const mood   = form.get("mood")  || "";
  const file   = form.get("file");

  if (!id || !file)                  return json({ ok: false, error: "id and file are required" }, 400);
  if (file.size > 20 * 1024 * 1024) return json({ ok: false, error: "File cannot exceed 20MB" }, 400);

  const tgForm = new FormData();
  tgForm.append("chat_id", env.STORAGE_CHANNEL_ID);
  tgForm.append("audio",   file, file.name || id + ".mp3");
  tgForm.append("caption", `[NEXIIT_MUSIC] ${id} — ${name || id}`);

  let file_id;
  try {
    const tgRes  = await fetch(`${TG_API}/sendAudio`, { method: "POST", body: tgForm });
    const tgData = await tgRes.json();
    if (!tgData.ok) return json({ ok: false, error: tgData.description }, 500);
    file_id = tgData.result.audio.file_id;
  } catch(e) { return json({ ok: false, error: "Upload failed" }, 500); }

  try {
    await env.DB.prepare(
      `INSERT INTO music_tracks (id, name, emoji, mood, file_id, sort_order) VALUES (?, ?, ?, ?, ?, 0)
       ON CONFLICT(id) DO UPDATE SET name=excluded.name, emoji=excluded.emoji, mood=excluded.mood, file_id=excluded.file_id`
    ).bind(id, name || id, emoji, mood, file_id).run();
  } catch(e) { return json({ ok: false, error: "Database error" }, 500); }

  return json({ ok: true, track_id: id, file_id });
}

async function handleMusicDelete(req, env) {
  let body;
  try { body = await req.json(); } catch { return json({ ok: false, error: "Invalid JSON" }, 400); }
  if (body.admin_key !== env.ADMIN_KEY) return json({ ok: false, error: "Unauthorized" }, 401);
  if (!body.id) return json({ ok: false, error: "id required" }, 400);
  try {
    await env.DB.prepare(`DELETE FROM music_tracks WHERE id=?`).bind(body.id).run();
    return json({ ok: true });
  } catch(e) { return json({ ok: false, error: "Database error" }, 500); }
}

// ═══════════════════════════════════════════════════════════
//  HEALTH
// ═══════════════════════════════════════════════════════════
async function handleHealth(env) {
  try {
    const [msgs, users] = await Promise.all([
      env.DB.prepare(`SELECT COUNT(*) as c FROM messages`).first(),
      env.DB.prepare(`SELECT COUNT(*) as c FROM users`).first(),
    ]);
    return json({
      ok:       true,
      service:  "NexIIT Worker",
      version:  "7.0",
      messages: msgs?.c  || 0,
      users:    users?.c || 0,
    });
  } catch (e) {
    return json({ ok: false, error: e.message }, 500);
  }
}

// ═══════════════════════════════════════════════════════════
//  MAIN ROUTER
// ═══════════════════════════════════════════════════════════
export default {
  async fetch(req, env) {
    const CORS = getCors(req);

    if (req.method === "OPTIONS") return new Response(null, { headers: CORS });

    const path = new URL(req.url).pathname;

    // Wrap json to always include dynamic CORS
    const r = (data, status = 200) => json(data, status, CORS);

    // ── PUBLIC ──────────────────────────────────────────
    if (path === "/")       return r({ ok: true, service: "NexIIT Worker", version: "7.0" });
    if (path === "/health") return handleHealth(env).then(res => {
      const clone = res.clone();
      return new Response(clone.body, { status: clone.status, headers: { ...Object.fromEntries(clone.headers), ...CORS } });
    });

    // ── AUTH ─────────────────────────────────────────────
    if (path === "/api/auth/sms/send"     && req.method === "POST") return addCors(await handleSendSmsOtp(req, env),    CORS);
    if (path === "/api/auth/sms/verify"   && req.method === "POST") return addCors(await handleVerifySmsOtp(req, env),  CORS);
    if (path === "/api/auth/email/send"   && req.method === "POST") return addCors(await handleSendEmailOtp(req, env),  CORS);
    if (path === "/api/auth/email/verify" && req.method === "POST") return addCors(await handleVerifyEmailOtp(req, env),CORS);
    if (path === "/api/auth/telegram"     && req.method === "POST") return addCors(await handleTelegramAuth(req, env),  CORS);
    if (path === "/api/auth/verify"       && req.method === "GET")  return addCors(await handleVerifyToken(req, env),   CORS);
    if (path === "/api/auth/logout"       && req.method === "POST") return addCors(await handleLogout(req, env),        CORS);

    // ── USER ─────────────────────────────────────────────
    if (path === "/api/user/update"       && req.method === "POST") return addCors(await handleUpdateProfile(req, env), CORS);
    if (path === "/api/user/xp"           && req.method === "POST") return addCors(await handleAddXp(req, env),         CORS);

    // ── SEMI-PUBLIC (guest allowed to view) ─────────────
    if (path === "/api/chapters"          && req.method === "GET")  return addCors(await handleChaptersList(req, env),  CORS);
    if (path === "/api/leaderboard"       && req.method === "GET")  return addCors(await handleLeaderboard(req, env),   CORS);
    if (path === "/api/music/list"        && req.method === "GET")  return addCors(await handleMusicList(req, env),     CORS);

    // ── PROTECTED (login required, no guest) ─────────────
    if (path === "/api/room/send"         && req.method === "POST") return addCors(await handleSend(req, env),          CORS);
    if (path === "/api/room/upload"       && req.method === "POST") return addCors(await handleUpload(req, env),        CORS);
    if (path === "/api/room/messages"     && req.method === "GET")  return addCors(await handleMessages(req, env),      CORS);
    if (path === "/api/room/delete"       && req.method === "POST") return addCors(await handleDelete(req, env),        CORS);
    if (path === "/api/file"              && req.method === "GET")  return addCors(await handleGetFile(req, env),       CORS);
    if (path === "/api/music/play"        && req.method === "GET")  return addCors(await handleMusicPlay(req, env),     CORS);
    if (path === "/api/notes"             && req.method === "GET")  return addCors(await handleNotesList(req, env),     CORS);
    if (path === "/api/notes/get"         && req.method === "GET")  return addCors(await handleNotesGet(req, env),      CORS);

    // ── ADMIN (admin_key required) ────────────────────────
    if (path === "/api/chapters/add"      && req.method === "POST") return addCors(await handleChaptersAdd(req, env),    CORS);
    if (path === "/api/chapters/delete"   && req.method === "POST") return addCors(await handleChaptersDelete(req, env), CORS);
    if (path === "/api/music/upload"      && req.method === "POST") return addCors(await handleMusicUpload(req, env),    CORS);
    if (path === "/api/music/delete"      && req.method === "POST") return addCors(await handleMusicDelete(req, env),    CORS);
    if (path === "/api/notes/upload"      && req.method === "POST") return addCors(await handleNotesUpload(req, env),    CORS);
    if (path === "/api/notes/upload-html" && req.method === "POST") return addCors(await handleNotesUploadHtml(req, env),CORS);
    if (path === "/api/notes/delete"      && req.method === "POST") return addCors(await handleNotesDelete(req, env),    CORS);

    return json({ ok: false, error: "Not found" }, 404, CORS);
  },
};

// Helper — attach CORS to any response
function addCors(res, cors) {
  const newHeaders = new Headers(res.headers);
  Object.entries(cors).forEach(([k, v]) => newHeaders.set(k, v));
  return new Response(res.body, { status: res.status, headers: newHeaders });
}
