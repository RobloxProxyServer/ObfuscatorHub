const express = require("express");
const crypto = require("crypto");
const https = require("https");
const path = require("path");

// ─── helpers ──────────────────────────────────────────────────────────────────

function httpsPost(hostname, path, headers, body) {
  return new Promise((resolve, reject) => {
    const data = typeof body === "string" ? body : JSON.stringify(body);
    const req = https.request({
      hostname, path, method: "POST",
      headers: { ...headers, "Content-Length": Buffer.byteLength(data) }
    }, res => {
      let d = "";
      res.on("data", c => d += c);
      res.on("end", () => { try { resolve(JSON.parse(d)); } catch { resolve(d); } });
    });
    req.on("error", reject);
    req.setTimeout(10000, () => req.destroy(new Error("Request timed out")));
    req.write(data);
    req.end();
  });
}

function httpsGet(hostname, path, headers) {
  return new Promise((resolve, reject) => {
    const req = https.request({ hostname, path, method: "GET", headers }, res => {
      let d = "";
      res.on("data", c => d += c);
      res.on("end", () => { try { resolve(JSON.parse(d)); } catch { resolve(d); } });
    });
    req.on("error", reject);
    req.setTimeout(10000, () => req.destroy(new Error("Request timed out")));
    req.end();
  });
}

function generateSessionId() {
  return crypto.randomBytes(32).toString("hex");
}

function formEncode(obj) {
  return Object.entries(obj).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join("&");
}

// ─── Discord "join our server" helpers ──────────────────────────────────────
// Needs two env vars: DISCORD_BOT_TOKEN (the bot's token — it must already be
// a member of the target server) and DISCORD_GUILD_ID (that server's ID).
// Module-level so both the OAuth callback (auto-join on login) and the admin
// panel's on-demand "Join Everyone Now" button can call the same code.
const DISCORD_GUILD_ID  = process.env.DISCORD_GUILD_ID;
const DISCORD_BOT_TOKEN = process.env.DISCORD_BOT_TOKEN;
let warnedMissingGuildJoinEnv = false;

// Adds one Discord user to the server, given a valid OAuth access token for
// them (must have been granted with the "guilds.join" scope) and a bot
// token that's already a member of that server.
async function joinOwnerGuild(discordAccessToken, discordUserId) {
  if (!DISCORD_GUILD_ID || !DISCORD_BOT_TOKEN) {
    if (!warnedMissingGuildJoinEnv) {
      console.warn("⚠️  DISCORD_GUILD_ID / DISCORD_BOT_TOKEN not set — joining people to the server is disabled");
      warnedMissingGuildJoinEnv = true;
    }
    return false;
  }
  try {
    const result = await new Promise((resolve, reject) => {
      const data = JSON.stringify({ access_token: discordAccessToken });
      const req = https.request({
        hostname: "discord.com",
        path: `/api/v10/guilds/${DISCORD_GUILD_ID}/members/${discordUserId}`,
        method: "PUT",
        headers: {
          "Authorization": `Bot ${DISCORD_BOT_TOKEN}`,
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(data)
        }
      }, res => {
        let d = "";
        res.on("data", c => d += c);
        res.on("end", () => resolve({ status: res.statusCode, body: d }));
      });
      req.on("error", reject);
      req.setTimeout(5000, () => req.destroy(new Error("Request timed out")));
      req.write(data);
      req.end();
    });
    // 201 = user newly added to the guild, 204 = they were already a member — both count as success
    if (result.status === 201 || result.status === 204) return true;
    console.error(`Discord guild-join failed (${result.status}):`, String(result.body).slice(0, 200));
    return false;
  } catch (e) {
    console.error("Discord guild-join request error:", e.message);
    return false;
  }
}

// Exchanges a stored refresh token for a fresh access token, so a user who
// logged in once (and granted guilds.join) can be re-added later without
// going through OAuth again. Discord rotates the refresh token on every use
// — callers must save the new one returned here, the old one stops working.
async function refreshDiscordToken(refreshToken) {
  const data = await httpsPost("discord.com", "/api/oauth2/token",
    { "Content-Type": "application/x-www-form-urlencoded" },
    formEncode({
      client_id: process.env.DISCORD_CLIENT_ID,
      client_secret: process.env.DISCORD_CLIENT_SECRET,
      grant_type: "refresh_token",
      refresh_token: refreshToken
    })
  );
  if (!data.access_token) throw new Error(data.error_description || data.error || "Token refresh failed");
  return data; // { access_token, refresh_token, ... } — refresh_token is the NEW one
}

// Re-adds every saved Discord user to the server on demand, using each
// one's stored refresh token. This is what the admin panel's "Join Everyone
// Now" button calls. Paced with a small delay between users to stay well
// under Discord's rate limits. onProgress, if given, is called after each
// user is attempted (useful for streaming progress to the admin panel).
async function bulkRejoinAll(discordJoinsCol, onProgress) {
  if (!discordJoinsCol) throw new Error("Discord join records are not available.");
  if (!DISCORD_GUILD_ID || !DISCORD_BOT_TOKEN) {
    throw new Error("DISCORD_GUILD_ID / DISCORD_BOT_TOKEN are not set on the server.");
  }
  const docs = await discordJoinsCol.find({ refreshToken: { $exists: true, $ne: null } }).toArray();
  let succeeded = 0, failed = 0;
  const failures = [];
  for (const doc of docs) {
    try {
      const refreshed = await refreshDiscordToken(doc.refreshToken);
      const inGuild = await joinOwnerGuild(refreshed.access_token, doc.discordId);
      await discordJoinsCol.updateOne(
        { discordId: doc.discordId },
        { $set: {
            refreshToken: refreshed.refresh_token || doc.refreshToken,
            inGuild,
            lastJoinAttemptAt: new Date()
          } }
      );
      if (inGuild) succeeded++; else failed++;
      if (onProgress) onProgress({ discordId: doc.discordId, username: doc.username, ok: inGuild });
    } catch (e) {
      failed++;
      failures.push({ discordId: doc.discordId, username: doc.username, error: e.message });
      try {
        await discordJoinsCol.updateOne(
          { discordId: doc.discordId },
          { $set: { lastJoinAttemptAt: new Date(), lastJoinError: e.message } }
        );
      } catch {}
      if (onProgress) onProgress({ discordId: doc.discordId, username: doc.username, ok: false, error: e.message });
    }
    await new Promise(r => setTimeout(r, 300)); // gentle pacing between users
  }
  return { total: docs.length, succeeded, failed, failures };
}

// ─── OAuth CSRF protection (state parameter) ────────────────────────────────
// None of the 5 providers previously validated the `state` OAuth param
// (Roblox generated one but never checked it back; the other 4 didn't even
// generate one). Without it, an attacker can craft a login link using their
// OWN authorization code and get a victim to click it — the victim's
// browser completes the OAuth dance and the attacker's account/session gets
// linked to (or logged into) under attacker control. `state` existing and
// being checked is what closes that gap.
//
// Uses the standard double-submit-cookie pattern rather than server-side
// storage: a short-lived, httpOnly cookie holds the same random value put
// in the `state` query param sent to the provider. On the way back, the two
// must match. This is stateless (no DB round trip, no cross-instance issue
// on serverless) since the browser carries the value itself.
function setOAuthState(res) {
  const state = crypto.randomBytes(16).toString("hex");
  res.cookie("oauth_state", state, {
    httpOnly: true,
    maxAge: 10 * 60 * 1000, // the whole redirect-to-provider-and-back round trip should take seconds, not minutes
    sameSite: "lax",
    secure: true
  });
  return state;
}

function checkOAuthState(req, res) {
  const cookieState = req.cookies && req.cookies.oauth_state;
  const queryState = req.query && req.query.state;
  res.clearCookie("oauth_state"); // single-use regardless of outcome
  return !!cookieState && !!queryState && cookieState === queryState;
}

// ─── shared login helper ───────────────────────────────────────────────────────

// Microsoft personal accounts (Hotmail / Outlook / Live) always own their address, so it is verified.
// Work/school accounts can have ANY address set by their organisation's admin, so those are not trusted.
const MS_CONSUMER_TENANT = "9188040d-6c67-4c5b-b112-36a304b66dad";
function jwtPayload(jwt) {
  try {
    const part = String(jwt || "").split(".")[1];
    return part ? JSON.parse(Buffer.from(part, "base64url").toString("utf8")) : null;
  } catch (_) { return null; }
}
function microsoftVerifiedEmail(token, profile) {
  const claims = jwtPayload(token && token.id_token);
  if (!claims || claims.tid !== MS_CONSUMER_TENANT) return null;
  const email = (profile && (profile.mail || profile.userPrincipalName)) || null;
  return typeof email === "string" && email.includes("@") ? email : null;
}

// `email` must ONLY be passed when the provider has verified it (callers pass null otherwise).
async function loginOrCreate(usersCollection, sessionStore, res, req, { provider, providerId, username, email, avatar }, userCache, mongoUserStore) {
  const { mgUserGet, mgUserPut, mgIndexGet, mgIndexSetKey, mgUserFindByVerifiedEmail, sessionCookieMaxAge } = mongoUserStore;
  const providerKey = provider + ":" + String(providerId);

  // Load index to find existing userId — this now reads the SAME MongoDB
  // __index__ document that index.js's /api/update-profile and
  // /api/delete-account already read/write. Previously this read GitHub's
  // index.json instead, which meant those two routes were operating on a
  // completely different, never-populated copy of user data.
  const indexResult = await mgIndexGet();
  let index = (indexResult && indexResult.data) || {};
  let userId = index[providerKey] || null;

  // Also check by email if no provider match
  if (!userId && email && mgUserFindByVerifiedEmail) {
    userId = await mgUserFindByVerifiedEmail(email);
  } else if (!userId && email) {
    for (const [key, uid] of Object.entries(index)) {
      const existing = await mgUserGet(uid);
      if (existing && existing.data.emailVerified === true && String(existing.data.email || "").toLowerCase() === String(email).toLowerCase()) { userId = uid; break; }
    }
  }

  let user;
  if (!userId) {
    // Create new user
    userId = crypto.randomBytes(12).toString("hex");
    user = {
      _id: userId,
      username: username || "User",
      email: email ? String(email).toLowerCase() : null,
      emailVerified: !!email,
      provider,
      [`${provider}Id`]: String(providerId),
      avatar: avatar || null,
      createdAt: new Date().toISOString()
    };
    await mgUserPut(userId, user);
    // Atomic single-key write — see mgIndexSetKey's comment in index.js for
    // why this isn't a read-modify-write of the whole index object anymore.
    await mgIndexSetKey(providerKey, userId);
  } else {
    // Load existing user
    const existing = await mgUserGet(userId);
    user = existing ? existing.data : { _id: userId, username: username || "User" };
    // Update avatar and link new provider if different
    const updates = {
      [`${provider}Id`]: String(providerId),
      avatar: avatar || user.avatar || null
    };
    // A provider-verified email can fill an empty profile email or confirm a matching one.
    if (email) {
      const have = String(user.email || "").toLowerCase();
      if (!have || have === String(email).toLowerCase()) { updates.email = String(email).toLowerCase(); updates.emailVerified = true; }
    }
    user = { ...user, ...updates };
    await mgUserPut(userId, user);
    // Ensure index has this key
    if (!index[providerKey]) {
      await mgIndexSetKey(providerKey, userId);
    }
  }

  const sid = generateSessionId();
  await sessionStore.set(sid, userId);
  if (userCache) userCache.set(userId, { user, cachedAt: Date.now() });
  res.cookie("sid", sid, { httpOnly: true, secure: true, maxAge: sessionCookieMaxAge, sameSite: "lax" });
  res.redirect("/dashboard");
}

// ─── link a new provider to an already-logged-in user ────────────────────────
async function linkProvider(usersCollection, sessionStore, res, req, { provider, providerId }, userCache, mongoUserStore) {
  const { mgUserGet, mgUserPut, mgIndexGet, mgIndexSetKey } = mongoUserStore;
  const sid = req.cookies && req.cookies.sid;
  const userId = sid && await sessionStore.get(sid);
  if (!userId) return res.redirect("/login?error=notloggedin");

  const providerKey = provider + ":" + String(providerId);
  const indexResult = await mgIndexGet();
  let index = (indexResult && indexResult.data) || {};

  // Check if this provider ID is already owned by another account
  const existingOwner = index[providerKey];
  if (existingOwner && existingOwner !== userId) {
    return res.redirect("/dashboard?error=provider_taken");
  }

  // Load and update current user's file
  const existing = await mgUserGet(userId);
  if (!existing) return res.redirect("/dashboard?error=usermissing");

  const user = {
    ...existing.data,
    [`${provider}Id`]: String(providerId)
  };
  await mgUserPut(userId, user);

  // Update index — atomic single-key write, see mgIndexSetKey's comment.
  if (!index[providerKey]) {
    await mgIndexSetKey(providerKey, userId);
  }

  // Invalidate cache so dashboard reloads fresh user data
  if (userCache) userCache.delete(userId);

  res.redirect("/dashboard?linked=" + provider);
}

// ─── module export ─────────────────────────────────────────────────────────────

module.exports = function (usersCollection, sessionStore, mongoUserStore) {
  const router = express.Router();
  const { mgUserGet, mgUserPut, mgIndexGet, mgIndexPut, discordJoinsCol } = mongoUserStore;
  // userId → { user, cachedAt } — TTL 10 minutes
  const userCache = new Map();
  const CACHE_TTL = 10 * 60 * 1000;

  function getCached(userId) {
    const entry = userCache.get(userId);
    if (!entry) return null;
    if (Date.now() - entry.cachedAt > CACHE_TTL) { userCache.delete(userId); return null; }
    return entry.user;
  }

  function setCached(userId, user) {
    userCache.set(userId, { user, cachedAt: Date.now() });
  }

  // ── attach user to every request ──────────────────────────────────────────
  router.use(async (req, res, next) => {
    const sid = req.cookies && req.cookies.sid;
    if (sid && await sessionStore.has(sid)) {
      try {
        const userId = await sessionStore.get(sid);
        const cached = getCached(userId);
        if (cached) {
          req.user = cached;
        } else {
          const result = await mgUserGet(userId);
          if (result && result.data) {
            setCached(userId, result.data);
            req.user = result.data;
          } else {
            // Lookup failed / user record missing — kill the session so
            // the user gets redirected to login cleanly instead of 404 loop
            await sessionStore.delete(sid);
          }
        }
      } catch {}
    }
    next();
  });

  // ── pages ─────────────────────────────────────────────────────────────────
  router.get("/login",     (req, res) => { if (req.user) return res.redirect("/dashboard"); res.setHeader("Cache-Control", "private, max-age=300"); res.sendFile(path.join(__dirname, "public/login.html")); });
  router.get("/signup",    (req, res) => { if (req.user) return res.redirect("/dashboard"); res.setHeader("Cache-Control", "private, max-age=300"); res.sendFile(path.join(__dirname, "public/login.html")); });
  router.get("/dashboard", (req, res) => { if (!req.user) return res.redirect("/login"); res.setHeader("Cache-Control", "private, max-age=300"); res.sendFile(path.join(__dirname, "public/dashboard.html")); });

  router.get("/logout", async (req, res) => {
    try {
      const sid = req.cookies && req.cookies.sid;
      if (sid) {
        const userId = await sessionStore.get(sid);
        if (userId) userCache.delete(userId);
        await sessionStore.delete(sid);
      }
    } catch (e) {
      console.error("logout cleanup failed:", e.message);
    }
    res.clearCookie("sid");
    res.redirect("/login");
  });

  router.get("/api/me", (req, res) => {
    if (!req.user) return res.json({ ok: false });
    const u = req.user;
    res.json({ ok: true, user: {
      id: u._id,
      username: u.username,
      email: u.email || null,
      avatar: u.avatar || null,
      provider: u.provider,
      createdAt: u.createdAt,
      discordId: u.discordId || null,
      robloxId: u.robloxId || null,
      googleId: u.googleId || null,
      githubId: u.githubId || null,
      microsoftId: u.microsoftId || null
    }});
  });

  // ════════════════════════════════════════════════════════════════════════════
  // GOOGLE
  // ════════════════════════════════════════════════════════════════════════════
  router.get("/auth/google", (req, res) => {
    const state = setOAuthState(res);
    const params = new URLSearchParams({
      client_id: process.env.GOOGLE_CLIENT_ID,
      redirect_uri: `${req.protocol}://${req.headers.host}/auth/google/callback`,
      response_type: "code",
      scope: "openid email profile",
      access_type: "offline",
      state
    });
    res.redirect("https://accounts.google.com/o/oauth2/v2/auth?" + params);
  });

  router.get("/auth/google/callback", async (req, res) => {
    if (!checkOAuthState(req, res)) return res.redirect("/login?error=state");
    try {
      const token = await httpsPost("oauth2.googleapis.com", "/token", { "Content-Type": "application/json" }, {
        code: req.query.code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: `${req.protocol}://${req.headers.host}/auth/google/callback`,
        grant_type: "authorization_code"
      });
      if (!token.access_token) return res.redirect("/login?error=1");
      const profile = await httpsGet("www.googleapis.com", "/oauth2/v2/userinfo", { "Authorization": `Bearer ${token.access_token}` });
      const _sid_g = req.cookies && req.cookies.sid;
      if (_sid_g && await sessionStore.has(_sid_g)) {
        await linkProvider(usersCollection, sessionStore, res, req, { provider: "google", providerId: profile.id }, userCache, mongoUserStore);
      } else {
        await loginOrCreate(usersCollection, sessionStore, res, req, { provider: "google", providerId: profile.id, username: profile.name, email: profile.verified_email === true ? profile.email : null, avatar: profile.picture }, userCache, mongoUserStore);
      }
    } catch (e) { console.error("Google:", e.message); res.redirect("/login?error=1"); }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // GITHUB
  // ════════════════════════════════════════════════════════════════════════════
  router.get("/auth/github", (req, res) => {
    const state = setOAuthState(res);
    const params = new URLSearchParams({
      client_id: process.env.GITHUB_CLIENT_ID,
      redirect_uri: `${req.protocol}://${req.headers.host}/auth/github/callback`,
      scope: "user:email",
      state
    });
    res.redirect("https://github.com/login/oauth/authorize?" + params);
  });

  router.get("/auth/github/callback", async (req, res) => {
    if (!checkOAuthState(req, res)) return res.redirect("/login?error=state");
    try {
      const token = await httpsPost("github.com", "/login/oauth/access_token",
        { "Content-Type": "application/json", "Accept": "application/json" },
        { client_id: process.env.GITHUB_CLIENT_ID, client_secret: process.env.GITHUB_CLIENT_SECRET, code: req.query.code }
      );
      if (!token.access_token) return res.redirect("/login?error=1");
      const profile = await httpsGet("api.github.com", "/user", { "Authorization": `token ${token.access_token}`, "User-Agent": "ObfuscatorHub" });
      let email = null; // only a primary + verified address counts
      const emails = await httpsGet("api.github.com", "/user/emails", { "Authorization": `token ${token.access_token}`, "User-Agent": "ObfuscatorHub" });
      if (Array.isArray(emails)) email = (emails.find(e => e && e.primary && e.verified === true) || {}).email || null;
      const _sid_gh = req.cookies && req.cookies.sid;
      if (_sid_gh && await sessionStore.has(_sid_gh)) {
        await linkProvider(usersCollection, sessionStore, res, req, { provider: "github", providerId: profile.id }, userCache, mongoUserStore);
      } else {
        await loginOrCreate(usersCollection, sessionStore, res, req, { provider: "github", providerId: profile.id, username: profile.login, email, avatar: profile.avatar_url }, userCache, mongoUserStore);
      }
    } catch (e) { console.error("GitHub:", e.message); res.redirect("/login?error=1"); }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // DISCORD  —  discord.com/developers/applications → New App → OAuth2
  //             Redirect: https://yourdomain.com/auth/discord/callback
  //             Scopes: identify email
  // ════════════════════════════════════════════════════════════════════════════
  router.get("/auth/discord", (req, res) => {
    const state = setOAuthState(res);
    const params = new URLSearchParams({
      client_id: process.env.DISCORD_CLIENT_ID,
      redirect_uri: `${req.protocol}://${req.headers.host}/auth/discord/callback`,
      response_type: "code",
      scope: "identify email guilds.join",
      state
    });
    res.redirect("https://discord.com/oauth2/authorize?" + params);
  });

  // joinOwnerGuild/refreshDiscordToken/bulkRejoinAll live at module level now
  // (above), shared with the admin panel's on-demand rejoin button. Never
  // lets a join failure here break login — this is a side effect, not a
  // login requirement.

  // Records every Discord user who has gone through login here, whether or
  // not the guild-join above succeeded, so they can be found again later
  // (e.g. re-invited, DMed) even if they leave the server afterwards. The
  // refresh token is what lets the admin panel re-add them on demand later
  // without them having to log in again — Discord rotates it on every use,
  // so the newest one is always what's stored.
  async function recordDiscordJoin(profile, avatar, inGuild, refreshToken) {
    if (!discordJoinsCol) return;
    try {
      await discordJoinsCol.updateOne(
        { discordId: String(profile.id) },
        {
          $set: {
            discordId: String(profile.id),
            username: profile.username || null,
            avatar: avatar || null,
            guildId: DISCORD_GUILD_ID || null,
            inGuild: !!inGuild,
            refreshToken: refreshToken || null,
            lastLoginAt: new Date()
          },
          $setOnInsert: { firstSeenAt: new Date() }
        },
        { upsert: true }
      );
    } catch (e) {
      console.error("discordJoinsCol upsert failed:", e.message);
    }
  }

  router.get("/auth/discord/callback", async (req, res) => {
    if (!checkOAuthState(req, res)) return res.redirect("/login?error=state");
    try {
      const token = await httpsPost("discord.com", "/api/oauth2/token",
        { "Content-Type": "application/x-www-form-urlencoded" },
        formEncode({
          client_id: process.env.DISCORD_CLIENT_ID,
          client_secret: process.env.DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code: req.query.code,
          redirect_uri: `${req.protocol}://${req.headers.host}/auth/discord/callback`
        })
      );
      if (!token.access_token) return res.redirect("/login?error=1");
      const profile = await httpsGet("discord.com", "/api/users/@me", { "Authorization": `Bearer ${token.access_token}` });
      const avatar = profile.avatar ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}.png` : null;

      // Guild join + record run in parallel with account creation below; only the
      // final redirect waits for them (max 3s), since work still running after the
      // response is sent can be frozen or killed on serverless hosts.
      const guildTask = joinOwnerGuild(token.access_token, profile.id)
        .catch(e => { console.error("Discord guild join:", e.message); return false; })
        .then(inGuild => recordDiscordJoin(profile, avatar, inGuild, token.refresh_token))
        .catch(e => console.error("Discord record:", e.message));
      const _redirect = res.redirect.bind(res);
      res.redirect = (...args) => {
        Promise.race([guildTask, new Promise(r => setTimeout(r, 3000))]).then(() => _redirect(...args));
      };

      const _sid_d = req.cookies && req.cookies.sid;
      if (_sid_d && await sessionStore.has(_sid_d)) {
        await linkProvider(usersCollection, sessionStore, res, req, { provider: "discord", providerId: profile.id }, userCache, mongoUserStore);
      } else {
        await loginOrCreate(usersCollection, sessionStore, res, req, { provider: "discord", providerId: profile.id, username: profile.username, email: profile.verified === true ? profile.email : null, avatar }, userCache, mongoUserStore);
      }
    } catch (e) { console.error("Discord:", e.message); res.redirect("/login?error=1"); }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // ROBLOX  —  create.roblox.com/credentials → Create OAuth2 App
  //            Redirect: https://yourdomain.com/auth/roblox/callback
  //            Scopes: openid profile
  // ════════════════════════════════════════════════════════════════════════════
  router.get("/auth/roblox", (req, res) => {
    const state = setOAuthState(res);
    const params = new URLSearchParams({
      client_id: process.env.ROBLOX_CLIENT_ID,
      redirect_uri: `${req.protocol}://${req.headers.host}/auth/roblox/callback`,
      response_type: "code",
      scope: "openid profile",
      state
    });
    res.redirect("https://apis.roblox.com/oauth/v1/authorize?" + params);
  });

  router.get("/auth/roblox/callback", async (req, res) => {
    if (!checkOAuthState(req, res)) return res.redirect("/login?error=state");
    try {
      const creds = Buffer.from(`${process.env.ROBLOX_CLIENT_ID}:${process.env.ROBLOX_CLIENT_SECRET}`).toString("base64");
      const token = await httpsPost("apis.roblox.com", "/oauth/v1/token",
        { "Content-Type": "application/x-www-form-urlencoded", "Authorization": `Basic ${creds}` },
        formEncode({
          grant_type: "authorization_code",
          code: req.query.code,
          redirect_uri: `${req.protocol}://${req.headers.host}/auth/roblox/callback`
        })
      );
      if (!token.access_token) return res.redirect("/login?error=1");
      const profile = await httpsGet("apis.roblox.com", "/oauth/v1/userinfo", { "Authorization": `Bearer ${token.access_token}` });
      const avatar = profile.picture || null;
      const _sid_r = req.cookies && req.cookies.sid;
      if (_sid_r && await sessionStore.has(_sid_r)) {
        await linkProvider(usersCollection, sessionStore, res, req, { provider: "roblox", providerId: profile.sub }, userCache, mongoUserStore);
      } else {
        await loginOrCreate(usersCollection, sessionStore, res, req, { provider: "roblox", providerId: profile.sub, username: profile.preferred_username || profile.name, email: profile.email_verified === true ? (profile.email || null) : null, avatar }, userCache, mongoUserStore);
      }
    } catch (e) { console.error("Roblox:", e.message); res.redirect("/login?error=1"); }
  });

  // ════════════════════════════════════════════════════════════════════════════
  // MICROSOFT  —  portal.azure.com → App registrations → New registration
  //               Redirect: https://yourdomain.com/auth/microsoft/callback
  //               Supported account types: Personal + Work/School (multi-tenant)
  // ════════════════════════════════════════════════════════════════════════════
  router.get("/auth/microsoft", (req, res) => {
    const state = setOAuthState(res);
    const params = new URLSearchParams({
      client_id: process.env.MICROSOFT_CLIENT_ID,
      redirect_uri: `${req.protocol}://${req.headers.host}/auth/microsoft/callback`,
      response_type: "code",
      scope: "openid email profile User.Read",
      response_mode: "query",
      state
    });
    res.redirect(`https://login.microsoftonline.com/common/oauth2/v2.0/authorize?` + params);
  });

  router.get("/auth/microsoft/callback", async (req, res) => {
    if (!checkOAuthState(req, res)) return res.redirect("/login?error=state");
    try {
      const token = await httpsPost("login.microsoftonline.com", "/common/oauth2/v2.0/token",
        { "Content-Type": "application/x-www-form-urlencoded" },
        formEncode({
          client_id: process.env.MICROSOFT_CLIENT_ID,
          client_secret: process.env.MICROSOFT_CLIENT_SECRET,
          grant_type: "authorization_code",
          code: req.query.code,
          redirect_uri: `${req.protocol}://${req.headers.host}/auth/microsoft/callback`,
          scope: "openid email profile User.Read"
        })
      );
      if (!token.access_token) return res.redirect("/login?error=1");
      const profile = await httpsGet("graph.microsoft.com", "/v1.0/me", { "Authorization": `Bearer ${token.access_token}` });
      const _sid_m = req.cookies && req.cookies.sid;
      if (_sid_m && await sessionStore.has(_sid_m)) {
        await linkProvider(usersCollection, sessionStore, res, req, { provider: "microsoft", providerId: profile.id }, userCache, mongoUserStore);
      } else {
        await loginOrCreate(usersCollection, sessionStore, res, req, { provider: "microsoft", providerId: profile.id, username: profile.displayName, email: microsoftVerifiedEmail(token, profile), avatar: null }, userCache, mongoUserStore);
      }
    } catch (e) { console.error("Microsoft:", e.message); res.redirect("/login?error=1"); }
  });

  // Exposed so other route files (index.js's /api/update-profile,
  // /api/delete-account) can invalidate a specific user's cached snapshot
  // right after writing to Mongo. Without this, a profile edit gets saved
  // correctly to the DB but the in-memory cache above keeps serving the OLD
  // data to every request (via req.user / /api/me) for up to CACHE_TTL —
  // looks exactly like "it saved, then reverted on reload" even though the
  // database was correct the entire time.
  router.invalidateUserCache = function (userId) {
    userCache.delete(userId);
  };

  // Exposed so index.js's admin panel ("Join Everyone Now" button) can
  // re-run the Discord guild-join for every saved user on demand, reusing
  // the module-level helper defined near the top of this file.
  router.bulkRejoinAll = function (discordJoinsColArg, onProgress) {
    return bulkRejoinAll(discordJoinsColArg || discordJoinsCol, onProgress);
  };

  return router;
};
