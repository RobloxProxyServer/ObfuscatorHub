const express = require("express");
const compression = require("compression");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const https = require("https");
const axios = require("axios");
const cookieParser = require("cookie-parser");

const { MongoClient } = require("mongodb");

const MONGO_POOL_OPTS = {
    maxPoolSize: 5,        // cap per-instance pool — small on purpose; serverless
    minPoolSize: 0,        // don't hold connections open on an idle/frozen instance
    maxIdleTimeMS: 10000,  // close unused connections after 10s instead of
    serverSelectionTimeoutMS: 5000, // fail fast instead of hanging if Atlas is
};

const uri  = process.env.MONGO_URI;
const client = new MongoClient(uri, MONGO_POOL_OPTS);

const uri2 = process.env.MONGO_URI_2;
const client2 = new MongoClient(uri2, MONGO_POOL_OPTS);

console.log("MONGO_URI:",  uri  ? "Loaded ✅" : "Missing ❌");
console.log("MONGO_URI_2:", uri2 ? "Loaded ✅" : "Missing ❌");
console.log("API_KEY:", process.env.API_KEY ? "Loaded ✅" : "⚠️  API_KEY not set — /api/create will reject all requests");
console.log("HCAPTCHA_SECRET:", process.env.HCAPTCHA_SECRET ? "Loaded ✅" : "⚠️  HCAPTCHA_SECRET not set — captcha will fail");

let scriptsCollection;
let tempCollection;
let blockedPathsCol;
let watchSourcesCol;
let usersCollection;
let keysCollection;
let integrationsCol;
let checkpointsCol;
let userdataCollection;
let oldScriptsCollection; // old primary-DB scripts still with fileName (pre-migration)
let sessionsCol; // MongoDB-backed sessions — see sessionStore below
let collaboratorsCol; // scriptId+email → permissions[] — see /api/scripts/:id/collaborators
let collabAuditCol;   // append-only history of collaborator grant/claim/removal events
let mountedAuthRouter; // set once auth.js is mounted below — needed so
let executionsCol; // MongoDB-backed activeExecutions — see execStore below
let hcaptchaCol; // one-time /api/hcaptcha → /verify/:hash link records — see below

const SESSION_TTL_MS = 90 * 24 * 60 * 60 * 1000; // 90 days from login
const SESSION_COOKIE_MAX_AGE_MS = SESSION_TTL_MS; // keep cookie and Mongo doc in sync — a 30-day
const sessionStore = {
    async get(sid) {
        if (!sid || typeof sid !== "string") return undefined;
        const doc = await sessionsCol.findOne({ sid });
        return doc ? doc.userId : undefined;
    },
    async has(sid) {
        if (!sid || typeof sid !== "string") return false;
        const doc = await sessionsCol.findOne({ sid }, { projection: { _id: 1 } });
        return !!doc;
    },
    async set(sid, userId) {
        await sessionsCol.updateOne(
            { sid },
            { $set: { sid, userId, expiresAt: new Date(Date.now() + SESSION_TTL_MS) } },
            { upsert: true }
        );
        return sessionStore;
    },
    async delete(sid) {
        if (!sid || typeof sid !== "string") return;
        await sessionsCol.deleteOne({ sid });
    }
};

const execStore = {
    async set(execId, data, ttlMs) {
        await executionsCol.updateOne(
            { execId },
            { $set: { execId, ...data, expiresAt: new Date(Date.now() + ttlMs) } },
            { upsert: true }
        );
    },
    async get(execId) {
        if (!execId) return undefined;
        const doc = await executionsCol.findOne({ execId });
        if (!doc) return undefined;
        if (doc.expiresAt && new Date(doc.expiresAt).getTime() < Date.now()) return undefined;
        const { _id, execId: _e, expiresAt, ...rest } = doc;
        return rest;
    },
    async delete(execId) {
        if (!execId) return;
        await executionsCol.deleteOne({ execId });
    },
    async touch(execId, ttlMs) {
        if (!execId) return;
        await executionsCol.updateOne({ execId }, { $set: { expiresAt: new Date(Date.now() + ttlMs) } });
    }
};

const ADMIN_COOKIE_TTL_MS = 12 * 60 * 60 * 1000; // 12 hours

function signAdminCookie(expiresAt) {
    const payload = String(expiresAt);
    const sig = crypto.createHmac("sha256", process.env.ADMIN_KEY).update(payload).digest("hex");
    return payload + "." + sig;
}

function verifyAdminCookie(cookieVal) {
    if (!cookieVal || typeof cookieVal !== "string") return false;
    const dot = cookieVal.lastIndexOf(".");
    if (dot < 1) return false;
    const payload = cookieVal.slice(0, dot);
    const sig = cookieVal.slice(dot + 1);
    const expected = crypto.createHmac("sha256", process.env.ADMIN_KEY).update(payload).digest("hex");
    const sigBuf = Buffer.from(sig, "hex");
    const expectedBuf = Buffer.from(expected, "hex");
    if (sigBuf.length !== expectedBuf.length) return false;
    if (!crypto.timingSafeEqual(sigBuf, expectedBuf)) return false; // timing-safe: a plain !== leaks how many
    const expiresAt = parseInt(payload, 10);
    if (isNaN(expiresAt) || Date.now() > expiresAt) return false;
    return true;
}

function requireAdmin(req, res, next) {
    if (!verifyAdminCookie(req.cookies && req.cookies.admin_session)) {
        return res.status(403).json({ ok: false, error: "Not authenticated" });
    }
    next();
}

let migrationRunning = false;

let dbReady = false;
let dbReadyPromise = null; // lazily set on first request by dbReadyGuard below

async function initDB() {
    try {
        await client.connect();
        const db = client.db("scriptsDB");

        tempCollection       = db.collection("scriptsave");   // temp holding area
        try {
            await tempCollection.createIndex({ id: 1 }, { unique: true });
        } catch (e) {
            console.error("temp id index creation failed:", e.message);
        }
        usersCollection      = db.collection("users");
        keysCollection       = db.collection("keys");
        integrationsCol      = db.collection("integrations");
        checkpointsCol       = db.collection("checkpoints");
        userdataCollection   = db.collection("userdata");     // replaces GitHub USERDATA repo
        oldScriptsCollection = db.collection("scripts");      // old scripts (fileName format) still in primary DB
        sessionsCol          = db.collection("sessions");     // replaces in-memory sessions Map
        executionsCol        = db.collection("executions");   // replaces in-memory activeExecutions Map
        collaboratorsCol     = db.collection("collaborators"); // scriptId+email → permissions[]
        collabAuditCol       = db.collection("collab_audit");  // history of grant/claim/removal events
        hcaptchaCol          = db.collection("hcaptcha_verifications"); // /api/hcaptcha → /verify/:hash
        discordJoinsCol      = db.collection("discord_guild_joins"); // one row per Discord user who has gone through /auth/discord
        try {
            await discordJoinsCol.createIndex({ discordId: 1 }, { unique: true });
        } catch (e) {
            console.error("discord_guild_joins index creation failed:", e.message);
        }

        try {
            await collaboratorsCol.createIndex({ scriptId: 1, email: 1 }, { unique: true });
            await collaboratorsCol.createIndex({ userId: 1 });
        } catch (e) {
            console.error("collaborators index creation failed:", e.message);
        }
        try {
            await collabAuditCol.createIndex({ scriptId: 1, at: -1 });
            await collabAuditCol.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        } catch (e) {
            console.error("collab_audit index creation failed:", e.message);
        }

        await client2.connect();
        const db2 = client2.db("scriptsDB");
        scriptsCollection    = db2.collection("scripts");
        try {
            await scriptsCollection.createIndex({ id: 1 }, { unique: true });
        } catch (e) {
            console.error("scripts id index creation failed:", e.message);
        }
        blockedPathsCol = db2.collection("blocked_paths");
        watchSourcesCol = db2.collection("watch_sources");
        try {
            await blockedPathsCol.createIndex({ path: 1 }, { unique: true });
            await watchSourcesCol.createIndex({ url: 1 }, { unique: true });
        } catch (e) {
            console.error("watch index creation failed:", e.message);
        }

        try {
            await checkpointsCol.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        } catch (e) {
            console.error("checkpoints TTL index creation failed:", e.message);
        }
        try {
            await sessionsCol.createIndex({ sid: 1 }, { unique: true });
            await sessionsCol.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        } catch (e) {
            console.error("sessions index creation failed:", e.message);
        }
        try {
            await keysCollection.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        } catch (e) {
            console.error("keys TTL index creation failed:", e.message);
        }
        try {
            await executionsCol.createIndex({ execId: 1 }, { unique: true });
            await executionsCol.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        } catch (e) {
            console.error("executions index creation failed:", e.message);
        }
        try {
            await hcaptchaCol.createIndex({ hash: 1 }, { unique: true });
            await hcaptchaCol.createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 });
        } catch (e) {
            console.error("hcaptcha_verifications index creation failed:", e.message);
        }

        dbReady = true;
        console.log("MongoDB Ready ✅");
    } catch (err) {
        dbReady = false;
        console.error("FATAL: MongoDB connection failed —", err.message);
    }
}

function dbReadyGuard(req, res, next) {
    if (dbReady) return next();
    if (!dbReadyPromise) {
        dbReadyPromise = initDB().catch(e => {
            console.error("initDB failed:", e.message);
            dbReadyPromise = null; // allow the next request to retry
            throw e; // propagate so the .catch below actually 503s
        });
    }
    dbReadyPromise
        .then(() => next())
        .catch(() => res.status(503).json({ error: "Database not ready, try again shortly" }));
}

const zlib = require("zlib");

function fetch(url, options = {}, _redirectCount = 0) {
    return new Promise((resolve, reject) => {
        const bodyData = options.body ? options.body : null;
        const timeoutMs = options.timeout || 15000; // fail closed instead of hanging forever
        const req = https.request(url, {
            method: options.method || "GET",
            headers: {
                "Accept-Encoding": "gzip, deflate, br",
                ...(options.headers || {}),
                ...(bodyData && { "Content-Length": Buffer.byteLength(bodyData) })
            }
        }, res => {
            if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
                res.resume(); // discard body, we're not using this response
                if (_redirectCount >= 5) {
                    reject(new Error("Too many redirects: " + url));
                    return;
                }
                const nextUrl = new URL(res.headers.location, url).toString();
                const preserveMethod = res.statusCode === 307 || res.statusCode === 308;
                fetch(nextUrl, preserveMethod ? options : { ...options, method: "GET", body: undefined }, _redirectCount + 1)
                    .then(resolve, reject);
                return;
            }

            const chunks = [];
            res.on("data", chunk => chunks.push(chunk));
            res.on("end", () => {
                const raw = Buffer.concat(chunks);
                const encoding = (res.headers["content-encoding"] || "").toLowerCase();

                let decodeErr = null;
                let buf = raw;
                try {
                    if (encoding === "gzip") buf = zlib.gunzipSync(raw);
                    else if (encoding === "br") buf = zlib.brotliDecompressSync(raw);
                    else if (encoding === "deflate") buf = zlib.inflateSync(raw);
                } catch (e) {
                    decodeErr = e;
                }

                if (decodeErr) { reject(decodeErr); return; }
                const data = buf.toString("utf8");

                resolve({
                    status: res.statusCode,
                    ok: res.statusCode >= 200 && res.statusCode < 300,
                    text: () => Promise.resolve(data),
                    json: () => Promise.resolve(JSON.parse(data))
                });
            });
        });
        req.on("error", reject);
        req.setTimeout(timeoutMs, () => {
            req.destroy(new Error(`Request timed out after ${timeoutMs}ms: ` + url));
        });
        if (bodyData) req.write(bodyData);
        req.end();
    });
}

const RUBIS_MAX_SCRIPT_BYTES = 3000000; // Rubis rejects anything above exactly 3,000,000 bytes
function scriptTooLargeForRubis(code) {
    return typeof code === "string" && Buffer.byteLength(code, "utf8") > RUBIS_MAX_SCRIPT_BYTES;
}


// ─── Oversized scripts (> Rubis limit): source lives on GitHub, Rubis holds a tiny loadstring ───
let githubBranchCache = null;
function githubRepo() { return process.env.GITHUB_BIG_REPO || "ObfuscaterHub/Lua_scripts"; } // big scripts only; the old GITHUB_SCRIPT_REPO stays for legacy reads
function githubApiHeaders(accept, json) {
    return {
        "Authorization": `token ${process.env.GITHUB_TOKEN}`,
        "Accept": accept || "application/vnd.github+json",
        "User-Agent": "script-save-app",
        ...(json ? { "Content-Type": "application/json" } : {})
    };
}
function githubContentsUrl(filePath) {
    return `https://api.github.com/repos/${githubRepo()}/contents/${filePath.split("/").map(encodeURIComponent).join("/")}`;
}
async function githubBranch() {
    if (process.env.GITHUB_BIG_BRANCH) return process.env.GITHUB_BIG_BRANCH;
    if (githubBranchCache) return githubBranchCache;
    const res = await fetch(`https://api.github.com/repos/${githubRepo()}`, { headers: githubApiHeaders() });
    if (!res.ok) throw new Error(`GitHub repo lookup failed: HTTP ${res.status}`);
    const data = await res.json();
    githubBranchCache = data.default_branch || "main";
    return githubBranchCache;
}
async function githubFileSha(filePath) {
    const branch = await githubBranch();
    const res = await fetch(`${githubContentsUrl(filePath)}?ref=${encodeURIComponent(branch)}`, { headers: githubApiHeaders() });
    if (res.status === 404) return null;
    if (!res.ok) throw new Error(`GitHub lookup failed: HTTP ${res.status}`);
    const data = await res.json();
    return data.sha || null;
}
async function githubPutFile(filePath, content, sha) {
    const branch = await githubBranch();
    const body = JSON.stringify({
        message: sha ? "update script" : "add script",
        content: Buffer.from(content, "utf8").toString("base64"),
        branch,
        ...(sha ? { sha } : {})
    });
    const res = await fetch(githubContentsUrl(filePath), { method: "PUT", headers: githubApiHeaders(null, true), body, timeout: 120000 });
    if (!res.ok) {
        let msg = "";
        try { msg = (await res.json()).message || ""; } catch (_) {}
        throw new Error(`GitHub upload failed: HTTP ${res.status} ${msg}`.trim());
    }
}
async function githubGetRawFile(filePath) {
    try {
        const branch = await githubBranch();
        const res = await fetch(`${githubContentsUrl(filePath)}?ref=${encodeURIComponent(branch)}`, {
            headers: githubApiHeaders("application/vnd.github.raw+json"), timeout: 60000
        });
        if (!res.ok) { console.error(`githubGetRawFile: HTTP ${res.status} for ${filePath}`); return null; }
        return await res.text();
    } catch (e) { console.error("githubGetRawFile failed:", e.message); return null; }
}
async function githubDeleteFile(filePath) {
    const sha = await githubFileSha(filePath);
    if (!sha) return;
    const branch = await githubBranch();
    const res = await fetch(githubContentsUrl(filePath), {
        method: "DELETE", headers: githubApiHeaders(null, true),
        body: JSON.stringify({ message: "delete script", sha, branch })
    });
    if (!res.ok) throw new Error(`GitHub delete failed: HTTP ${res.status}`);
}
async function githubLoadstringStub(filePath) {
    const branch = await githubBranch();
    const rawUrl = `https://raw.githubusercontent.com/${githubRepo()}/${encodeURIComponent(branch)}/${filePath.split("/").map(encodeURIComponent).join("/")}`;
    return `loadstring(game:HttpGet("${rawUrl}"))()`;
}

// Decides where the code lives. Small: Rubis holds it. Big: GitHub holds it, Rubis holds a loadstring to it.
async function prepareScriptStorage(sid, code) {
    if (!scriptTooLargeForRubis(code)) return { rubisCode: code, githubPath: null };
    if (!process.env.GITHUB_TOKEN) throw new Error("GITHUB_TOKEN is not set (needed for scripts over 3,000,000 bytes)");
    const githubPath = `big/${sid}-${crypto.randomBytes(12).toString("hex")}.lua`;
    await githubPutFile(githubPath, code, null);
    return { rubisCode: await githubLoadstringStub(githubPath), githubPath };
}

// Where to read a script's real source from (view / edit / unlock).
async function readScriptCode(s) {
    if (s.githubPath) return await githubGetRawFile(s.githubPath); // never fall back to the tiny stub
    let code = null;
    if (s.scrapID) code = await rubisGet(s.scrapID);
    else if (s.fileName) code = await legacyGetGitHubFile(s.fileName);
    if (!code && s.code) code = s.code;
    return code;
}

// Saving an edit: keeps the right storage (Rubis <-> GitHub) as the size crosses the limit.
async function applyScriptCodeUpdate(s, id, code) {
    const big = scriptTooLargeForRubis(code);
    const wasGithub = !!s.githubPath;
    if (!big && !wasGithub) {
        await rubisUpdate(s.scrapID, s.scrapOwnerKey, code);
    } else if (big && wasGithub) {
        await githubPutFile(s.githubPath, code, await githubFileSha(s.githubPath)); // same URL, so the Rubis stub stays valid
    } else if (big && !wasGithub) {
        const prepared = await prepareScriptStorage(id, code);
        try {
            await rubisUpdate(s.scrapID, s.scrapOwnerKey, prepared.rubisCode);
        } catch (e) {
            try { await githubDeleteFile(prepared.githubPath); } catch (_) {}
            throw e;
        }
        await scriptsCollection.updateOne({ id }, { $set: { githubPath: prepared.githubPath } });
    } else {
        await rubisUpdate(s.scrapID, s.scrapOwnerKey, code);
        await scriptsCollection.updateOne({ id }, { $unset: { githubPath: "" } });
        try { await githubDeleteFile(s.githubPath); } catch (e) { console.error("GitHub cleanup failed:", e.message); }
    }
}

async function rubisUpload(code) {
    const ownerKey = crypto.randomBytes(16).toString("hex");
    const res = await fetch(
        `https://api.rubis.app/v2/scrap?public=true&ownerKey=${ownerKey}`,
        { method: "POST", headers: { "Content-Type": "text/plain" }, body: code }
    );
    const data = await res.json();
    if (!data.success) throw new Error("Rubis upload failed: " + JSON.stringify(data));
    return { scrapID: data.scrapID, ownerKey };
}

async function rubisGet(scrapID) {
    try {
        const res = await fetch(`https://api.rubis.app/v2/scrap/${scrapID}/raw`);
        if (!res.ok) {
            console.error(`rubisGet: Rubis returned HTTP ${res.status} for scrap ${scrapID}`);
            return null;
        }
        return res.text();
    } catch { return null; }
}

function rubisLoadstringStub(scrapID) {
    return `local function _kgSpyGuardKG2()
  local _ishookKG2 = isfunctionhooked or ishooked
  local _targetsKG2 = {game.HttpGet, game.HttpPost}
  pcall(function() if syn and syn.request then table.insert(_targetsKG2, syn.request) end end)
  pcall(function() if request then table.insert(_targetsKG2, request) end end)
  if _ishookKG2 then
    for _, fnKG2 in next, _targetsKG2 do
      local okKG2, hookedKG2 = pcall(_ishookKG2, fnKG2)
      if okKG2 and hookedKG2 then return true end
    end
  end
  local okCoreKG2, coreKG2 = pcall(function() return game:GetService("CoreGui") end)
  if okCoreKG2 and coreKG2 then
    local okKidsKG2, kidsKG2 = pcall(function() return coreKG2:GetChildren() end)
    if okKidsKG2 and kidsKG2 then
      for _, childKG2 in next, kidsKG2 do
        local okGuiKG2, isGuiKG2 = pcall(function() return childKG2:IsA("ScreenGui") end)
        if okGuiKG2 and isGuiKG2 then
          local nmKG2 = tostring(childKG2.Name):lower()
          if nmKG2:find("httpspy", 1, true) or nmKG2:find("http spy", 1, true) or nmKG2:find("reqspy", 1, true) then
            return true
          end
        end
      end
    end
  end
  return false
end
if _kgSpyGuardKG2() then
  task.spawn(function() while true do task.wait(0) end end)
  pcall(function() game:GetService("Players").LocalPlayer:Kick("Anti-cheat: HTTP spy/hook detected.") end)
  return
end
local _rubisUrl = "https://api.rubis.app/v2/scrap/${scrapID}/raw"
local _rubisFn, _rubisErr
for _attempt = 1, 3 do
  local _okG, _body = pcall(game.HttpGet, game, _rubisUrl)
  if _okG and type(_body) == "string" and _body ~= "" then
    local _f, _e = loadstring(_body)
    if _f then
      _rubisFn = _f
      break
    end
    _rubisErr = "compile error: " .. tostring(_e)
  else
    _rubisErr = "fetch failed: " .. tostring(_body)
  end
  task.wait(1.5)
end
if not _rubisFn then
  error("[ObfuscatorHub] could not load script from storage (" .. tostring(_rubisErr) .. ")")
end
return _rubisFn()`;
}

async function rubisUpdate(scrapID, ownerKey, code) {
    const res = await fetch(
        `https://api.rubis.app/v2/scrap/${encodeURIComponent(scrapID)}?ownerKey=${encodeURIComponent(ownerKey)}`,
        { method: "PUT", headers: { "Content-Type": "text/plain" }, body: code }
    );
    if (!res.ok) throw new Error(`Rubis update failed: HTTP ${res.status}`);
    const data = await res.json();
    if (data && data.success === false) throw new Error("Rubis update failed: " + JSON.stringify(data));
    return data;
}

async function rubisDelete(scrapID, ownerKey) {
    const res = await fetch(
        `https://api.rubis.app/v2/scrap/${encodeURIComponent(scrapID)}?ownerKey=${encodeURIComponent(ownerKey)}`,
        { method: "DELETE" }
    );
    if (!res.ok) throw new Error(`Rubis delete failed: HTTP ${res.status}`);
    const data = await res.json();
    if (data && data.success === false) throw new Error("Rubis delete failed: " + JSON.stringify(data));
    return data;
}

const rubisQueue = [];
let rubisProcessing = false;

async function queueRubisUpload(code, onSuccess, onFail, _attempt) {
    rubisQueue.push({ code, onSuccess, onFail, attempt: _attempt || 1 });
    if (!rubisProcessing) processRubisQueue();
}

const RUBIS_MAX_ATTEMPTS = 3;

async function processRubisQueue() {
    if (rubisQueue.length === 0) { rubisProcessing = false; return; }
    rubisProcessing = true;
    const { code, onSuccess, onFail, attempt } = rubisQueue.shift();

    let result, uploadFailed = false, uploadErr = null;
    try {
        result = await rubisUpload(code);
    } catch (e) {
        uploadFailed = true;
        uploadErr = e;
    }

    if (uploadFailed) {
        console.error(`Rubis queue upload error (attempt ${attempt}/${RUBIS_MAX_ATTEMPTS}):`, uploadErr.message);
        if (attempt < RUBIS_MAX_ATTEMPTS) {
            setTimeout(() => queueRubisUpload(code, onSuccess, onFail, attempt + 1), 1000 * attempt);
        } else if (onFail) {
            try { await onFail(uploadErr); } catch (e2) { console.error("onFail handler itself threw:", e2.message); }
        }
    } else {
        try {
            await onSuccess(result);
        } catch (e) {
            console.error("Rubis queue onSuccess handler crashed (upload itself succeeded, scrapID:", result?.scrapID, "):", e.message);
        }
    }

    setTimeout(processRubisQueue, 200); // 200 ms gap (~5/s, well under 10/s limit)
}

async function mgUserGet(userId) {
    const doc = await userdataCollection.findOne({ userId });
    return doc ? { data: doc.data } : null;
}

async function mgUserPut(userId, data) {
    await userdataCollection.updateOne(
        { userId },
        { $set: { userId, data, updatedAt: new Date() } },
        { upsert: true }
    );
}

async function mgIndexGet() {
    const doc = await userdataCollection.findOne({ userId: "__index__" });
    return doc ? { data: doc.data } : null;
}

async function mgIndexPut(data) {
    await userdataCollection.updateOne(
        { userId: "__index__" },
        { $set: { userId: "__index__", data, updatedAt: new Date() } },
        { upsert: true }
    );
}

async function mgIndexSetKey(key, value) {
    await userdataCollection.updateOne(
        { userId: "__index__" },
        { $set: { userId: "__index__", [`data.${key}`]: value, updatedAt: new Date() } },
        { upsert: true }
    );
}

async function legacyGetGitHubFile(filename) {
    if (!process.env.GITHUB_TOKEN) return null;
    const headers = {
        "Authorization": `token ${process.env.GITHUB_TOKEN}`,
        "Accept": "application/vnd.github+json",
        "User-Agent": "script-save-app"
    };
    try {
        const metaRes = await fetch(
            `https://api.github.com/repos/${process.env.GITHUB_SCRIPT_REPO || "Thebestscripteryt/Script-save"}/contents/${filename}`,
            { headers }
        );
        const data = await metaRes.json();

        if (data.content) {
            return Buffer.from(data.content.replace(/\n/g, ""), "base64").toString();
        }

        if (data.download_url) {
            const rawRes = await fetch(data.download_url, {
                headers: { "Authorization": `token ${process.env.GITHUB_TOKEN}`, "User-Agent": "script-save-app" }
            });
            return rawRes.text();
        }

        if (data.sha) {
            const blobRes = await fetch(
                `https://api.github.com/repos/${process.env.GITHUB_SCRIPT_REPO || "Thebestscripteryt/Script-save"}/git/blobs/${data.sha}`,
                { headers }
            );
            const blob = await blobRes.json();
            if (blob.content) {
                return Buffer.from(blob.content.replace(/\n/g, ""), "base64").toString();
            }
        }

        return null; // truly not found
    } catch { return null; }
}

async function legacyListGitHubDir(repoPath) {
    if (!process.env.GITHUB_TOKEN) return [];
    try {
        const res = await fetch(
            `https://api.github.com/repos/Thebestscripteryt/USERDATA/contents/${repoPath}`,
            { headers: { "Authorization": `token ${process.env.GITHUB_TOKEN}`, "Accept": "application/vnd.github+json", "User-Agent": "script-save-app" } }
        );
        const data = await res.json();
        return Array.isArray(data) ? data : [];
    } catch { return []; }
}

async function legacyGetUserFileJSON(filePath) {
    if (!process.env.GITHUB_TOKEN) return null;
    try {
        const res = await fetch(
            `https://api.github.com/repos/Thebestscripteryt/USERDATA/contents/${filePath}`,
            { headers: { "Authorization": `token ${process.env.GITHUB_TOKEN}`, "Accept": "application/vnd.github+json", "User-Agent": "script-save-app" } }
        );
        const data = await res.json();
        if (!data.content) return null;
        return JSON.parse(Buffer.from(data.content, "base64").toString("utf8"));
    } catch { return null; }
}

// ─── Abuse watcher: find our own URLs inside flood scripts and silence those paths ───
const WATCH_UA = "Roblox/WinInet";
const WATCH_MAX_BYTES = 2 * 1024 * 1024;
const WATCH_MAX_NEW_PER_SCAN = 20;
const WATCH_MAX_TOTAL_BLOCKS = 200;
const OWN_DOMAIN = (process.env.OWN_DOMAIN || "obfuscatorhub.lol").toLowerCase();
const WATCH_SYSTEM_PREFIXES = new Set(["raw", "raw2", "getkey", "checkpoint", "verify", "auth", "unlock"]);

let blockedSet = new Set();
let blockedLoadedAt = 0;
let blockedLoading = null;

function normalizeSitePath(raw) {
    if (typeof raw !== "string") return null;
    let p = raw.split("?")[0].split("#")[0] || "/";
    try { p = decodeURIComponent(p); } catch (_) { return null; }
    p = p.toLowerCase().replace(/\/+/g, "/");
    if (p.length > 1) p = p.replace(/\/+$/, "");
    if (p.length > 100 || !/^\/[a-z0-9_\-\/.]*$/.test(p)) return null;
    return p;
}

function isBlockedPath(p) {
    const n = normalizeSitePath(p);
    return !!n && blockedSet.has(n);
}

async function refreshBlocked(force) {
    if (!blockedPathsCol) return;
    if (!force && Date.now() - blockedLoadedAt < 60 * 1000) return;
    if (blockedLoading) return blockedLoading;
    blockedLoading = (async () => {
        try {
            const docs = await blockedPathsCol.find({ status: "blocked" }, { projection: { path: 1 } }).limit(1000).toArray();
            blockedSet = new Set(docs.map(d => d.path));
            blockedLoadedAt = Date.now();
        } catch (e) {
            console.error("[watch] refreshBlocked failed:", e.message);
        } finally {
            blockedLoading = null;
        }
    })();
    return blockedLoading;
}

// Silent drop: no body, no error page. On a self-hosted server the socket is
// destroyed (client sees "can't connect"); on Vercel a connection can't be dropped,
// so an empty 204 is the quietest possible answer.
async function blockedPathMiddleware(req, res, next) {
    try {
        if (!blockedLoadedAt) await refreshBlocked(true);
        else if (Date.now() - blockedLoadedAt > 60 * 1000) refreshBlocked();
    } catch (_) {}
    if (blockedSet.size && isBlockedPath(req.path)) {
        if (!process.env.VERCEL && req.socket) { req.socket.destroy(); return; }
        res.status(204).end();
        return;
    }
    next();
}

function isSafeWatchUrl(u) {
    try {
        const url = new URL(u);
        if (url.protocol !== "https:") return false;
        if (url.username || url.password) return false;
        if (url.port && url.port !== "443") return false;
        const h = url.hostname.toLowerCase();
        if (!h.includes(".") || h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) return false;
        if (/^[0-9.]+$/.test(h) || h.includes(":")) return false; // no IP literals
        return true;
    } catch (_) { return false; }
}

function watchFetch(url, redirects = 0) {
    return new Promise((resolve, reject) => {
        if (!isSafeWatchUrl(url)) return reject(new Error("unsafe or invalid source URL"));
        const u = new URL(url);
        const req = https.request(u, {
            method: "GET",
            headers: { "User-Agent": WATCH_UA, "Accept": "*/*", "Accept-Encoding": "identity" }
        }, res => {
            if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
                res.resume();
                if (redirects >= 3) return reject(new Error("too many redirects"));
                return watchFetch(new URL(res.headers.location, u).toString(), redirects + 1).then(resolve, reject);
            }
            const chunks = [];
            let size = 0;
            res.on("data", c => {
                size += c.length;
                if (size > WATCH_MAX_BYTES) { req.destroy(new Error("response too large")); return; }
                chunks.push(c);
            });
            res.on("end", () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString("utf8") }));
            res.on("error", reject);
        });
        req.on("error", reject);
        req.setTimeout(8000, () => req.destroy(new Error("timeout")));
        req.end();
    });
}

function extractOwnPaths(body) {
    const escaped = OWN_DOMAIN.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const re = new RegExp("https?:\\/\\/(?:www\\.)?" + escaped + "(\\/[^\\s\"'<>\\)\\]\\\\]*)?", "gi");
    const found = new Set();
    let m;
    while ((m = re.exec(body)) !== null) {
        const n = normalizeSitePath(m[1] || "/");
        if (n) found.add(n);
    }
    return [...found];
}

async function classifyOwnPath(p) {
    const segs = p.split("/").filter(Boolean);
    if (!segs.length) return { action: "skip", reason: "root path" };
    const first = segs[0];
    if (WATCH_SYSTEM_PREFIXES.has(first)) return { action: "skip", reason: "system route" };
    let id;
    if (first === "api") {
        if (segs.length === 1) return { action: "skip", reason: "system route" };
        if (segs.length !== 2) return { action: "review", reason: "unusual api path" };
        id = segs[1];
    } else if (segs.length === 1) {
        id = first;
    } else {
        return { action: "review", reason: "multi-segment path" };
    }
    if (!/^[a-z0-9_-]{1,40}$/.test(id)) return { action: "skip", reason: "not a plain name (file or odd characters)" };
    if (RESERVED_PATHS.has(id)) return { action: "skip", reason: "system route" };
    const opts = { projection: { _id: 1 }, collation: { locale: "en", strength: 2 } };
    const exists = await scriptsCollection.findOne({ id }, opts) || await tempCollection.findOne({ id }, opts);
    if (exists) return { action: "review", reason: "matches a real script on this site" };
    return { action: "block", reason: "path does not exist on this site" };
}

async function getWatchSources() {
    const list = new Set((process.env.WATCH_SOURCES || "").split(",").map(x => x.trim()).filter(Boolean));
    try {
        const docs = await watchSourcesCol.find({}, { projection: { url: 1 } }).limit(50).toArray();
        docs.forEach(d => list.add(d.url));
    } catch (e) { console.error("[watch] reading sources failed:", e.message); }
    return [...list].filter(isSafeWatchUrl).slice(0, 10);
}

async function runWatchScan() {
    const sources = await getWatchSources();
    const report = { scanned: [], blocked: [], review: [], skipped: [], capped: [] };
    const hits = new Map(); // path -> Set(source urls)

    await Promise.all(sources.map(async url => {
        const entry = { url, status: null, found: [], error: null };
        try {
            const r = await watchFetch(url);
            entry.status = r.status;
            entry.found = extractOwnPaths(r.body);
            for (const p of entry.found) {
                if (!hits.has(p)) hits.set(p, new Set());
                hits.get(p).add(url);
            }
        } catch (e) { entry.error = e.message; }
        report.scanned.push(entry);
    }));

    let totalBlocked = await blockedPathsCol.countDocuments({ status: "blocked" });
    let newBlocks = 0;
    for (const [p, srcSet] of hits) {
        const sourcesArr = [...srcSet];
        const existing = await blockedPathsCol.findOne({ path: p });
        if (existing && existing.status === "allowed") { report.skipped.push({ path: p, reason: "allowed by admin" }); continue; }
        if (existing && existing.status === "blocked") { report.blocked.push({ path: p, reason: "already blocked" }); continue; }
        const c = await classifyOwnPath(p);
        if (c.action === "skip") { report.skipped.push({ path: p, reason: c.reason }); continue; }
        if (c.action === "block" && (newBlocks >= WATCH_MAX_NEW_PER_SCAN || totalBlocked >= WATCH_MAX_TOTAL_BLOCKS)) {
            await blockedPathsCol.updateOne({ path: p }, { $set: { status: "review", reason: "block limit reached", sources: sourcesArr, updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
            report.capped.push({ path: p });
            continue;
        }
        const status = c.action === "block" ? "blocked" : "review";
        await blockedPathsCol.updateOne({ path: p }, { $set: { status, reason: c.reason, sources: sourcesArr, updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
        if (status === "blocked") { newBlocks++; totalBlocked++; report.blocked.push({ path: p, reason: c.reason }); }
        else report.review.push({ path: p, reason: c.reason });
    }
    await refreshBlocked(true);
    return report;
}

process.on("unhandledRejection", (reason) => {
    console.error("[unhandledRejection]", (reason && reason.stack) || reason);
});

const app = express();
app.set("query parser", "simple"); // default "extended" (qs) turns ?t[$ne]=x into an object -> NoSQL operator injection

// Express 4 never catches a rejected promise from an async handler: the request hangs or the
// process crashes. Forward those errors to the error handler instead.
function wrapAsyncHandler(fn) {
    if (fn.length === 4) return fn; // error-handling middleware stays as is
    return function (req, res, next) {
        try {
            const r = fn.call(this, req, res, next);
            if (r && typeof r.catch === "function") r.catch(next);
        } catch (e) { next(e); }
    };
}
for (const m of ["get", "post", "put", "delete", "all"]) {
    const orig = app[m].bind(app);
    app[m] = (...args) => {
        if (m === "get" && args.length === 1) return orig(...args); // app.get("setting")
        return orig(...args.map(a => (typeof a === "function" ? wrapAsyncHandler(a) : a)));
    };
}
app.use(compression({
    filter: (req, res) => {
        if (req.path.startsWith("/api/") || req.path.startsWith("/raw/") || req.path.startsWith("/raw2/")) {
            return false;
        }
        return compression.filter(req, res);
    }
}));
const rateLimitMap = new Map();

function isRateLimited(ip) {
    const now = Date.now();
    const last = rateLimitMap.get(ip) || 0;
    if (now - last < 1500) return true;
    rateLimitMap.set(ip, now);
    return false;
}

const unlockAttempts = new Map(); // key: "ip" or "script:id" → { count, windowStart }

const UNLOCK_MAX_IP     = 10;  // max 10 wrong attempts per IP per 15 min
const UNLOCK_MAX_SCRIPT = 5;   // max 5 wrong attempts per script ID per 15 min
const UNLOCK_WINDOW     = 15 * 60 * 1000; // 15 minutes
const UNLOCK_BLOCK      = 30 * 60 * 1000; // block 30 min after limit

function checkUnlockLimit(key, max) {
    const now = Date.now();
    let entry = unlockAttempts.get(key);
    if (!entry || now - entry.windowStart > UNLOCK_WINDOW) {
        entry = { count: 0, windowStart: now, blocked: false };
    }
    if (entry.blocked && now - entry.blockedAt < UNLOCK_BLOCK) {
        return false; // still blocked
    }
    if (entry.blocked && now - entry.blockedAt >= UNLOCK_BLOCK) {
        entry = { count: 0, windowStart: now, blocked: false }; // reset after block expires
    }
    entry.count++;
    if (entry.count > max) {
        entry.blocked = true;
        entry.blockedAt = now;
        unlockAttempts.set(key, entry);
        return false;
    }
    unlockAttempts.set(key, entry);
    return true;
}

function resetUnlockLimit(key) {
    unlockAttempts.delete(key); // clear on success
}

setInterval(() => {
    const now = Date.now();
    for (const [key, entry] of unlockAttempts.entries()) {
        if (now - entry.windowStart > UNLOCK_BLOCK * 2) unlockAttempts.delete(key);
    }
}, 60 * 60 * 1000);

const webFormMap = new Map(); // ip → { count, windowStart, blocked }

const WEB_FORM_MAX     = 5;              // max submissions
const WEB_FORM_WINDOW  = 10 * 60 * 1000; // per 10 minutes
const WEB_FORM_BLOCK   = 60 * 60 * 1000; // block for 1 hour after limit hit

function checkWebForm(ip) {
    const now = Date.now();
    let entry = webFormMap.get(ip);

    if (entry && entry.blocked && now - entry.blockedAt < WEB_FORM_BLOCK) {
        return { allowed: false, reason: "blocked" };
    }

    if (!entry || now - entry.windowStart > WEB_FORM_WINDOW) {
        entry = { count: 0, windowStart: now, blocked: false };
    }

    entry.count++;
    if (entry.count > WEB_FORM_MAX) {
        entry.blocked  = true;
        entry.blockedAt = now;
        webFormMap.set(ip, entry);
        console.warn("Web form abuse blocked:", ip);
        return { allowed: false, reason: "ratelimit" };
    }

    webFormMap.set(ip, entry);
    return { allowed: true };
}

function isLikelyBot(req) {
    const ua = req.headers["user-agent"] || "";
    const accept = req.headers["accept"] || "";
    const acceptLang = req.headers["accept-language"] || "";

    if (!ua) return true;

    const botPatterns = /^(curl|python|wget|go-http|axios|node-fetch|aiohttp|java|libwww|okhttp|httpx)/i;
    if (botPatterns.test(ua)) return true;

    if (!acceptLang) return true;

    if (!accept.includes("text/html") && !accept.includes("*/*")) return true;

    return false;
}

setInterval(() => {
    const now = Date.now();
    for (const [ip, entry] of webFormMap.entries()) {
        if (now - entry.windowStart > WEB_FORM_BLOCK * 2) webFormMap.delete(ip);
    }
    for (const [ip, ts] of rateLimitMap.entries()) {
        if (now - ts > 60000) rateLimitMap.delete(ip);
    }
}, 2 * 60 * 60 * 1000);

app.set("trust proxy", 1);
app.disable("strict routing");

const faviconPath = path.join(__dirname, "favicon");
app.use(express.static(faviconPath, { maxAge: "1d" }));
app.use(cookieParser());
app.use(express.json({ limit: "25mb" })); // scripts are text; even a huge one is nowhere near this — 500mb was pure DoS surface
app.use(express.urlencoded({ limit: "25mb", extended: true }));

function stripMongoOperators(v, depth) {
    depth = depth || 0;
    if (depth > 30) return null;
    if (Array.isArray(v)) return v.map(x => stripMongoOperators(x, depth + 1));
    if (v && typeof v === "object") {
        const out = {};
        for (const k of Object.keys(v)) {
            if (k.startsWith("$")) continue; // never legitimate in user input, always an operator-injection attempt
            out[k] = stripMongoOperators(v[k], depth + 1);
        }
        return out;
    }
    return v;
}
app.use((req, res, next) => {
    if (req.cookies && typeof req.cookies === "object") {
        for (const k of Object.keys(req.cookies)) if (typeof req.cookies[k] !== "string") delete req.cookies[k];
    }
    if (req.body && typeof req.body === "object") req.body = stripMongoOperators(req.body);
    next();
});

app.use(dbReadyGuard);
app.use(blockedPathMiddleware);

app.use((req, res, next) => {
    if (!usersCollection) return next(); // DB not ready yet, skip
    req._usersCollection = usersCollection;
    req._sessions = sessionStore;
    next();
});

app.get("/about", (req, res) => {
    res.setHeader("Cache-Control", "public, max-age=3600");
    sendHtmlWithSiteUrl(req, res, path.join(__dirname, "public/about.html"));
});

function generateToken() {
    return crypto.randomBytes(16)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}

function id() {
    return crypto.randomBytes(6).toString("base64url");
}

function getSiteUrl(req) {
    return `${req.protocol}://${req.get("host")}`;
}

const _htmlTemplateCache = new Map();
function sendHtmlWithSiteUrl(req, res, filePath) {
    let template = _htmlTemplateCache.get(filePath);
    if (!template) {
        template = fs.readFileSync(filePath, "utf8");
        _htmlTemplateCache.set(filePath, template);
    }
    const html = template.split("{{SITE_URL}}").join(getSiteUrl(req));
    res.type("html").send(html);
}

function sendVerifyHtml(req, res) {
    const filePath = path.join(__dirname, "public/verify.html");
    let template = _htmlTemplateCache.get(filePath);
    if (!template) {
        template = fs.readFileSync(filePath, "utf8");
        _htmlTemplateCache.set(filePath, template);
    }
    const sitekey = process.env.HCAPTCHA_SITEKEY || "25bc146c-b7d0-4d3a-b18c-18c42124e022";
    const html = template.split("{{HCAPTCHA_SITEKEY}}").join(sitekey);
    res.type("html").send(html);
}

function escapeHtml(str) {
    return String(str ?? "").replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
}

app.get("/", (req, res) => {
    res.setHeader("Cache-Control", "public, max-age=300");
    sendHtmlWithSiteUrl(req, res, path.join(__dirname, "public/index.html"));
});

app.get("/server-ping", (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.send("<html><body><h1>Server On</h1></body></html>");
});

app.get("/lua-highlight.js", (req, res) => {
    res.setHeader("Cache-Control", "public, max-age=604800, immutable");
    res.sendFile(path.join(__dirname, "public/lua-highlight.js"));
});

app.post(["/create", "/create/"], async (req, res) => {
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();

    const hToken = req.body["h-captcha-response"];
    if (!hToken) return res.status(403).send("Captcha required.");
    try {
        const hVerify = await fetch("https://api.hcaptcha.com/siteverify", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `secret=${process.env.HCAPTCHA_SECRET}&response=${hToken}&remoteip=${ip}`
        });
        const hData = await hVerify.json();
        if (!hData.success) {
            return res.status(403).send("Captcha verification failed. Please try again.");
        }
    } catch(e) {
        console.error("hCaptcha error:", e.message);
        return res.status(500).send("Captcha check failed. Try again.");
    }

    if (isLikelyBot(req)) {
        console.warn("Bot blocked from /create:", ip, req.headers["user-agent"]);
        return res.status(403).sendFile(path.join(__dirname, "public/404.html"));
    }

    const check = checkWebForm(ip);
    if (!check.allowed) {
        return res.status(429).send(`<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Slow down – ObfuscatorHub</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>:root{--cyan:#00f5ff;--pink:#ff2d78;--red:#ff4455;}*{margin:0;padding:0;box-sizing:border-box;}body{background:#050508;color:#e0e8ff;font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center;}
.card{background:#0d0d14;border:1px solid rgba(255,68,85,0.3);border-radius:20px;padding:40px 32px;max-width:420px;}
h1{font-family:'Orbitron',sans-serif;font-size:22px;color:var(--red);margin-bottom:12px;}
p{color:rgba(255,255,255,0.45);font-size:13px;line-height:1.8;margin-bottom:20px;}
a{display:inline-block;padding:12px 28px;background:linear-gradient(135deg,var(--cyan),var(--pink));border-radius:10px;color:#fff;text-decoration:none;font-family:'Orbitron',sans-serif;font-size:12px;font-weight:700;letter-spacing:2px;}
</style></head>
<body><div class="card"><h1>⚠️ Slow Down</h1>
<p>You've submitted too many scripts in a short time.<br>Please wait a few minutes before trying again.</p>
<a href="/">← Go Home</a></div></body></html>`);
    }

    const { code, password } = req.body;
    if (typeof code !== "string") return res.status(400).send("Missing");
    if (!code || !password) return res.send("Missing");
    { const pwErr = validatePassword(password); if (pwErr) return res.status(400).send(pwErr); }
    const sid = id();
    const tokens = [generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken()];

    let prepared;
    try {
        prepared = await prepareScriptStorage(sid, code);
    } catch (e) {
        console.error("Large-script storage failed:", e.message);
        return res.status(502).send("Could not store the large script right now. Try again.");
    }

    try {
        await tempCollection.insertOne({
            id: sid,
            password,
            code: prepared.rubisCode,
            ...(prepared.githubPath ? { githubPath: prepared.githubPath } : {}),
            tokens,
            owner: await sessionStore.get(req.cookies?.sid) || null,
            createdAt: new Date()
        });
    } catch (e) {
        console.error("tempCollection insert failed in /create:", e.message);
        return res.status(500).send("Something went wrong saving your script. Please try again.");
    }

    const loaderCode = `loadstring(game:HttpGet("https://${req.headers.host}/api/${sid}"))()`;

    res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Script Ready – ObfuscatorHub</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=JetBrains+Mono:wght@300;400;600&display=swap" rel="stylesheet">
<style>
  :root { --cyan:#00f5ff;--pink:#ff2d78;--purple:#7c3aed;--green:#00ff88;--bg:#050508;--card:#0d0d14;--border:rgba(0,245,255,0.15); }
  *{margin:0;padding:0;box-sizing:border-box;}
  body{background:var(--bg);color:#e0e8ff;font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;overflow-x:hidden;}
  body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,245,255,0.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,245,255,0.025) 1px,transparent 1px);background-size:40px 40px;animation:gridMove 20s linear infinite;pointer-events:none;z-index:0;}
  @keyframes gridMove{to{transform:translateY(40px);}}
  .orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:0.12;pointer-events:none;z-index:0;animation:orbFloat 8s ease-in-out infinite;}
  .orb1{width:350px;height:350px;background:var(--green);top:-80px;left:-80px;}
  .orb2{width:250px;height:250px;background:var(--cyan);bottom:-60px;right:-60px;animation-delay:-4s;}
  @keyframes orbFloat{0%,100%{transform:translate(0,0)}50%{transform:translate(15px,-15px)}}
  .container{position:relative;z-index:1;width:95%;max-width:540px;animation:fadeUp 0.6s ease forwards;}
  @keyframes fadeUp{from{opacity:0;transform:translateY(30px)}to{opacity:1;transform:translateY(0)}}
  .badge{display:flex;align-items:center;justify-content:center;gap:8px;margin-bottom:8px;font-size:11px;letter-spacing:3px;text-transform:uppercase;color:var(--green);opacity:0.7;}
  .badge::before,.badge::after{content:'';height:1px;width:40px;background:linear-gradient(90deg,transparent,var(--green));}
  .badge::after{transform:scaleX(-1);}
  .card{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:32px;position:relative;overflow:hidden;}
  .card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--green),var(--cyan),transparent);animation:scanLine 3s linear infinite;}
  @keyframes scanLine{0%,100%{opacity:0.4}50%{opacity:1}}
  .card-corner{position:absolute;width:16px;height:16px;border-color:var(--green);border-style:solid;opacity:0.4;}
  .card-corner.tl{top:12px;left:12px;border-width:2px 0 0 2px}.card-corner.tr{top:12px;right:12px;border-width:2px 2px 0 0}.card-corner.bl{bottom:12px;left:12px;border-width:0 0 2px 2px}.card-corner.br{bottom:12px;right:12px;border-width:0 2px 2px 0}
  .success-icon{text-align:center;font-size:48px;margin-bottom:14px;animation:successPop 0.5s cubic-bezier(0.175,0.885,0.32,1.275) forwards;}
  @keyframes successPop{from{transform:scale(0);opacity:0}to{transform:scale(1);opacity:1}}
  h1{font-family:'Orbitron',sans-serif;font-size:20px;font-weight:900;text-align:center;letter-spacing:2px;margin-bottom:6px;background:linear-gradient(135deg,var(--green),var(--cyan));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
  .subtitle{text-align:center;font-size:11px;color:rgba(255,255,255,0.35);letter-spacing:2px;text-transform:uppercase;margin-bottom:28px;}
  .info-row{display:flex;align-items:center;gap:8px;padding:10px 14px;margin-bottom:10px;background:rgba(0,255,136,0.05);border:1px solid rgba(0,255,136,0.12);border-radius:10px;font-size:12px;}
  .info-dot{width:6px;height:6px;border-radius:50%;flex-shrink:0;}
  .dot-green{background:var(--green);box-shadow:0 0 8px var(--green);}
  .info-label{color:rgba(255,255,255,0.35);min-width:70px;}
  .info-val{color:var(--green);word-break:break-all;}
  .field-label{font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--cyan);opacity:0.6;margin-bottom:8px;margin-top:20px;}
  textarea{width:100%;height:100px;background:rgba(0,0,0,0.6);border:1px solid rgba(0,255,136,0.2);border-radius:10px;color:var(--green);font-family:'JetBrains Mono',monospace;font-size:12px;padding:14px;resize:none;outline:none;line-height:1.6;}
  .btn-copy{width:100%;margin-top:14px;padding:15px;border:none;border-radius:12px;font-family:'Orbitron',sans-serif;font-size:13px;font-weight:900;letter-spacing:3px;cursor:pointer;background:linear-gradient(135deg,var(--green),var(--cyan),var(--purple));background-size:200% 200%;color:#000;transition:transform 0.2s,box-shadow 0.2s;animation:gradShift 4s ease infinite;}
  .btn-copy:hover{transform:translateY(-2px);box-shadow:0 8px 30px rgba(0,255,136,0.3);}
  @keyframes gradShift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
  .btn-home{display:block;width:100%;margin-top:10px;padding:13px;border:1px solid rgba(0,245,255,0.2);border-radius:12px;background:transparent;color:var(--cyan);font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:600;letter-spacing:1px;cursor:pointer;text-align:center;text-decoration:none;transition:all 0.25s;}
  .btn-home:hover{background:rgba(0,245,255,0.07);box-shadow:0 0 20px rgba(0,245,255,0.1);}
  .divider{height:1px;background:linear-gradient(90deg,transparent,var(--border),transparent);margin:20px 0;}
  .tip{font-size:11px;color:rgba(255,255,255,0.25);text-align:center;letter-spacing:0.5px;line-height:1.7;}
  .tip span{color:var(--cyan);opacity:0.7;}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>
<div class="container">
  <div class="badge">ObfuscatorHub</div>
  <div class="card">
    <div class="card-corner tl"></div><div class="card-corner tr"></div>
    <div class="card-corner bl"></div><div class="card-corner br"></div>
    <div class="success-icon">✅</div>
    <h1>Script Protected!</h1>
    <div class="subtitle">Your script is encrypted &amp; ready</div>
    <div class="info-row"><div class="info-dot dot-green"></div><span class="info-label">Script ID</span><span class="info-val">${sid}</span></div>
    <div class="info-row"><div class="info-dot dot-green"></div><span class="info-label">Status</span><span class="info-val">Protected &amp; Live</span></div>
    <div class="field-label">// Loadstring — Paste into your executor</div>
    <textarea id="loaderCode" readonly spellcheck="false">${loaderCode}</textarea>
    <button class="btn-copy" onclick="copyLoader(this)">⚡ COPY LOADSTRING</button>
    <a href="/" class="btn-home">← Protect Another Script</a>
    <div class="divider"></div>
    <div class="tip">Paste the loadstring into your Roblox executor.<br><span>View or edit your script at /${sid}</span></div>
  </div>
</div>
<script>
function copyLoader(btn){navigator.clipboard.writeText(document.getElementById('loaderCode').value).then(()=>{btn.textContent='✅ COPIED!';setTimeout(()=>{btn.textContent='⚡ COPY LOADSTRING';},2000);});}
document.getElementById('loaderCode').addEventListener('click',function(){this.select();});
</script>
</body>
</html>`);

    const cookieSid = req.cookies && req.cookies.sid;
    const ownerId = (cookieSid && await sessionStore.has(cookieSid)) ? await sessionStore.get(cookieSid) : null;
    console.log("create: sid=" + cookieSid + " owner=" + ownerId);

    queueRubisUpload(
        prepared.rubisCode,
        async ({ scrapID, ownerKey }) => {
            try {
                const exists = await scriptsCollection.findOne({ id: sid });
                if (exists) {
                    await tempCollection.deleteOne({ id: sid });
                    return;
                }
                const live = await tempCollection.findOne({ id: sid });
                if (!live) {
                    try { await rubisDelete(scrapID, ownerKey); } catch (_) {}
                    console.log("Script deleted before upload finished, discarded:", sid);
                    return;
                }
                await scriptsCollection.insertOne({
                    id: sid,
                    password: live.password,
                    scrapID,
                    scrapOwnerKey: ownerKey,
                    ...(prepared.githubPath ? { githubPath: prepared.githubPath } : {}),
                    tokens,
                    lastToken: tokens[0],
                    owner: ownerId,
                    createdAt: new Date()
                });
                await tempCollection.deleteOne({ id: sid });
                console.log("✅ Script saved:", sid, "owner:", ownerId, "scrapID:", scrapID);
            } catch(e) { console.error("MongoDB insert failed:", e.message); }
        },
        (err) => { console.error("Rubis upload failed, keeping in temp:", sid, err && err.message); }
    );
});

app.post(["/api/create", "/api/create/"], async (req, res) => {
    const apiKey = req.headers["x-api-key"];
    if (!apiKey || apiKey !== process.env.API_KEY) {
        return res.status(401).json({ ok: false, error: "Invalid or missing API key. Pass it as x-api-key header." });
    }
    const { code, password } = req.body;
    if (typeof code !== "string") return res.status(400).json({ ok: false, error: "Invalid code." });
    if (!code || !password) return res.status(400).json({ ok: false });
    { const pwErr = validatePassword(password); if (pwErr) return res.status(400).json({ ok: false, error: pwErr }); }
    let wantedPath = null;
    if (req.body.customPath !== undefined && req.body.customPath !== "") {
        const vp = validateCustomPath(req.body.customPath);
        if (!vp.ok) return res.status(400).json({ ok: false, error: vp.error });
        wantedPath = vp.name;
    }
    const sid = wantedPath || id();
    const tokens = [generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken()];
    const host = req.headers.host;
    if (wantedPath) {
        if (await scriptIdTaken(wantedPath)) {
            return res.status(409).json({ ok: false, error: "That custom path is already taken." });
        }
    }
    const apiLink = `https://${host}/api/${sid}`;

    let prepared;
    try {
        prepared = await prepareScriptStorage(sid, code);
    } catch (e) {
        console.error("Large-script storage failed:", e.message);
        return res.status(502).json({ ok: false, error: "Could not store the large script right now. Try again." });
    }

    try {
        await tempCollection.insertOne({
            id: sid, password, code: prepared.rubisCode, ...(prepared.githubPath ? { githubPath: prepared.githubPath } : {}), tokens,
            owner: null, createdAt: new Date()
        });
    } catch (e) {
        console.error("Bot temp insert failed:", e.message);
        return res.status(500).json({ ok: false, error: "Failed to save script. Try again." });
    }

    res.json({
        ok: true,
        id: sid,
        password,
        api: apiLink,
        edit: `https://${host}/${sid}`,
        loadstring: `loadstring(game:HttpGet("${apiLink}"))()`
    });

    queueRubisUpload(
        prepared.rubisCode,
        async ({ scrapID, ownerKey }) => {
            try {
                const live = await tempCollection.findOne({ id: sid });
                if (!live) {
                    try { await rubisDelete(scrapID, ownerKey); } catch (_) {}
                    console.log("Script deleted before upload finished, discarded:", sid);
                    return;
                }
                await scriptsCollection.insertOne({
                    id: sid, password: live.password,
                    scrapID, scrapOwnerKey: ownerKey,
                    ...(prepared.githubPath ? { githubPath: prepared.githubPath } : {}),
                    tokens, lastToken: tokens[0],
                    owner: null, createdAt: new Date()
                });
                await tempCollection.deleteOne({ id: sid });
                console.log("✅ Bot script saved:", sid, "scrapID:", scrapID);
            } catch(e) { console.error("Bot MongoDB insert failed:", e.message); }
        },
        (err) => { console.error("Rubis upload failed (bot), keeping in temp:", sid); }
    );
});

app.post("/api/dashboard-create", async (req, res, next) => { try {
    const sid_cookie = req.cookies && req.cookies.sid;
    if (!sid_cookie || !await sessionStore.has(sid_cookie)) {
        return res.status(401).json({ ok: false, error: "Not logged in." });
    }
    const ownerId = await sessionStore.get(sid_cookie);
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();

    const hToken = req.body["h-captcha-response"];
    if (!hToken) return res.status(403).json({ ok: false, error: "Captcha required." });
    try {
        const hVerify = await fetch("https://api.hcaptcha.com/siteverify", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `secret=${process.env.HCAPTCHA_SECRET}&response=${hToken}&remoteip=${ip}`
        });
        const hData = await hVerify.json();
        if (!hData.success) return res.status(403).json({ ok: false, error: "Captcha verification failed." });
    } catch(e) {
        console.error("hCaptcha error:", e.message);
        return res.status(500).json({ ok: false, error: "Captcha check failed." });
    }

    const check = checkWebForm(ip);
    if (!check.allowed) {
        return res.status(429).json({ ok: false, error: "Too many submissions — please wait a few minutes." });
    }

    const { code, password } = req.body;
    if (typeof code !== "string") return res.status(400).json({ ok: false, error: "Invalid code." });
    if (!code || !password) return res.status(400).json({ ok: false, error: "Missing code or password." });
    const pwErrD = validatePassword(password);
    if (pwErrD) return res.status(400).json({ ok: false, error: pwErrD });
    let wantedPath = null;
    if (req.body.customPath !== undefined && req.body.customPath !== "") {
        const vp = validateCustomPath(req.body.customPath);
        if (!vp.ok) return res.status(400).json({ ok: false, error: vp.error });
        wantedPath = vp.name;
    }
    const sid = wantedPath || id();
    const tokens = [generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken()];
    const host = req.headers.host;
    if (wantedPath) {
        if (await scriptIdTaken(wantedPath)) {
            return res.status(409).json({ ok: false, error: "That custom path is already taken." });
        }
    }
    const apiLink = `https://${host}/api/${sid}`;

    let prepared;
    try {
        prepared = await prepareScriptStorage(sid, code);
    } catch (e) {
        console.error("Large-script storage failed:", e.message);
        return res.status(502).json({ ok: false, error: "Could not store the large script right now. Try again." });
    }

    try {
        await tempCollection.insertOne({
            id: sid, password, code: prepared.rubisCode, ...(prepared.githubPath ? { githubPath: prepared.githubPath } : {}), tokens,
            owner: ownerId, createdAt: new Date()
        });
    } catch (e) {
        console.error("tempCollection insert failed in /api/dashboard-create:", e.message);
        if (e && e.code === 11000) return res.status(409).json({ ok: false, error: "That custom path is already taken." });
        return res.status(500).json({ ok: false, error: "Failed to save script. Try again." });
    }

    res.json({
        ok: true,
        id: sid,
        password,
        api: apiLink,
        edit: `https://${host}/${sid}`,
        loadstring: `loadstring(game:HttpGet("${apiLink}"))()`
    });

    queueRubisUpload(
        prepared.rubisCode,
        async ({ scrapID, ownerKey }) => {
            try {
                const live = await tempCollection.findOne({ id: sid });
                if (!live) {
                    try { await rubisDelete(scrapID, ownerKey); } catch (_) {}
                    console.log("Script deleted before upload finished, discarded:", sid);
                    return;
                }
                await scriptsCollection.insertOne({
                    id: sid, password: live.password,
                    scrapID, scrapOwnerKey: ownerKey,
                    ...(prepared.githubPath ? { githubPath: prepared.githubPath } : {}),
                    tokens, lastToken: tokens[0],
                    owner: ownerId, createdAt: new Date()
                });
                await tempCollection.deleteOne({ id: sid });
                console.log("✅ Dashboard script saved:", sid, "owner:", ownerId, "scrapID:", scrapID);
            } catch(e) { console.error("Dashboard MongoDB insert failed:", e.message); }
        },
        (err) => { console.error("Rubis upload failed (dashboard), keeping in temp:", sid); }
    );
} catch (e) {
    console.error("/api/dashboard-create crashed:", e.stack || e.message || e);
    if (!res.headersSent) res.status(500).json({ ok: false, error: "Server error while saving the script. Try again." });
}
});

app.post("/unlock", async (req, res) => {
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
    const { id, password } = req.body;

    if (!id || typeof id !== "string" || (password !== undefined && typeof password !== "string")) {
        return res.json({ ok: false });
    }

    let s = await scriptsCollection.findOne({ id });
    if (!s) s = await tempCollection.findOne({ id });
    if (!s) return res.json({ ok: false, gone: true });

    const ownerSid = req.cookies?.sid;
    const ownerUserId = ownerSid ? await sessionStore.get(ownerSid) : null;
    const isOwner = !!(ownerUserId && s.owner && ownerUserId === s.owner);

    let hasCollabAccess = false;
    if (!isOwner && ownerUserId) {
        const perms = await getCollaboratorPermissions(id, ownerUserId);
        hasCollabAccess = perms.includes("view_password") || perms.includes("view_script");
    }

    if (!isOwner && !hasCollabAccess) {
        if (!password) return res.json({ ok: false });

        const ipAllowed     = checkUnlockLimit("ip:" + ip, UNLOCK_MAX_IP);
        const scriptAllowed = checkUnlockLimit("script:" + id, UNLOCK_MAX_SCRIPT);

        if (!ipAllowed) {
            console.warn("Unlock brute-force blocked by IP:", ip);
            return res.status(429).json({ ok: false, error: "Too many attempts. Try again later." });
        }
        if (!scriptAllowed) {
            console.warn("Unlock brute-force blocked for script:", id, "from IP:", ip);
            return res.status(429).json({ ok: false, error: "Too many attempts on this script. Try again later." });
        }

        if (s.password !== password) {
            return res.json({ ok: false });
        }

        resetUnlockLimit("ip:" + ip);
        resetUnlockLimit("script:" + id);
    }

    const realCode = await readScriptCode(s);
    if (!realCode) return res.json({ ok: false });

    res.json({ ok: true, code: realCode });
});

app.post("/api/save", async (req, res) => {
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
    const { id, password, code } = req.body;
    if (!id || typeof id !== "string" || (password !== undefined && typeof password !== "string")) {
        return res.json({ ok: false });
    }
    if (typeof code !== "string" || !code.trim()) {
        return res.json({ ok: false, error: "Code cannot be empty" });
    }
    try {
        let s = await scriptsCollection.findOne({ id });
        let inTemp = false;
        if (!s) {
            s = await tempCollection.findOne({ id });
            inTemp = true;
        }
        if (!s) return res.json({ ok: false });

        const saveSid = req.cookies?.sid;
        const saveUserId = saveSid ? await sessionStore.get(saveSid) : null;
        const isOwner = !!(saveUserId && s.owner && saveUserId === s.owner);

        let hasEditAccess = false;
        if (!isOwner && saveUserId) {
            const perms = await getCollaboratorPermissions(id, saveUserId);
            hasEditAccess = perms.includes("edit");
        }

        if (!isOwner && !hasEditAccess) {
            if (!checkUnlockLimit("ip:" + ip, UNLOCK_MAX_IP)) {
                return res.status(429).json({ ok: false, error: "Too many attempts." });
            }
            if (!password || s.password !== password) return res.json({ ok: false });
            resetUnlockLimit("ip:" + ip);
        }

        if (inTemp) {
            if (scriptTooLargeForRubis(code) || s.githubPath) {
                return res.json({ ok: false, error: "The script is still uploading. Try again in a few seconds." });
            }
            await tempCollection.updateOne({ id }, { $set: { code } });
            return res.json({ ok: true });
        }

        if (!s.scrapID || !s.scrapOwnerKey) {
            return res.status(400).json({
                ok: false,
                error: "Script is missing Rubis configuration"
            });
        }
        await applyScriptCodeUpdate(s, id, code); // throws on failure — caught below
        res.json({ ok: true });
    } catch (err) {
        console.error("Save failed:", err.message);
        res.json({ ok: false, error: "Failed to save — the live script was not updated. Try again." });
    }
});

async function purgeScriptData(id, s) {
    const results = {};
    const run = async (name, fn) => {
        try { const r = await fn(); results[name] = r && r.deletedCount !== undefined ? r.deletedCount : 1; }
        catch (e) { results[name] = "error: " + e.message; console.error("[purge] " + name + " failed for " + id + ":", e.message); }
    };
    if (s && s.githubPath) await run("github", () => githubDeleteFile(s.githubPath));
    await run("script",        () => scriptsCollection.deleteMany({ id }));
    await run("temp",          () => tempCollection.deleteMany({ id }));
    await run("keys",          () => keysCollection.deleteMany({ scriptId: id }));
    await run("checkpoints",   () => checkpointsCol.deleteMany({ scriptId: id }));
    await run("collaborators", () => collaboratorsCol.deleteMany({ scriptId: id }));
    await run("collab_audit",  () => collabAuditCol.deleteMany({ scriptId: id }));
    console.log("[purge] " + id + " ->", JSON.stringify(results));
    return results;
}

app.post("/api/delete", async (req, res) => {
    try {
        const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
        const { id, password } = req.body;
        if (!id || typeof id !== "string" || (password !== undefined && typeof password !== "string")) {
            return res.json({ ok: false });
        }
        const s = await scriptsCollection.findOne({ id }) || await tempCollection.findOne({ id });
        if (!s) return res.json({ ok: false });

        const delSid = req.cookies?.sid;
        const delUserId = delSid ? await sessionStore.get(delSid) : null;
        const isOwner = !!(delUserId && s.owner && delUserId === s.owner);

        let hasDeleteAccess = false;
        if (!isOwner && delUserId) {
            const perms = await getCollaboratorPermissions(id, delUserId);
            hasDeleteAccess = perms.includes("delete");
        }

        if (!isOwner && !hasDeleteAccess) {
            if (!password) return res.json({ ok: false });
            if (!checkUnlockLimit("ip:" + ip, UNLOCK_MAX_IP)) {
                return res.status(429).json({ ok: false, error: "Too many attempts." });
            }
            if (s.password !== password) return res.json({ ok: false });
            resetUnlockLimit("ip:" + ip);
        }

        if (s.scrapID && s.scrapOwnerKey) {
            await rubisDelete(s.scrapID, s.scrapOwnerKey);
        }
        await purgeScriptData(id, s);
        return res.json({ ok: true });
    } catch (err) { console.error("Delete API crash:", err); return res.json({ ok: false }); }
});

app.post("/api/change-password", async (req, res) => {
    try {
        const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
        const { id, newPassword, password } = req.body || {};
        if (!id || typeof id !== "string" || typeof newPassword !== "string" || (password !== undefined && typeof password !== "string")) {
            return res.status(400).json({ ok: false, error: "Invalid request." });
        }
        const pwErr = validatePassword(newPassword);
        if (pwErr) return res.status(400).json({ ok: false, error: pwErr });

        let col = scriptsCollection;
        let s = await scriptsCollection.findOne({ id });
        if (!s) { col = tempCollection; s = await tempCollection.findOne({ id }); }
        if (!s) return res.status(404).json({ ok: false, error: "Script not found." });

        const sid = req.cookies?.sid;
        const userId = sid ? await sessionStore.get(sid) : null;
        const isOwner = !!(userId && s.owner && userId === s.owner);

        if (!isOwner) {
            if (!checkUnlockLimit("ip:" + ip, UNLOCK_MAX_IP)) {
                return res.status(429).json({ ok: false, error: "Too many attempts." });
            }
            if (!password || s.password !== password) {
                return res.status(401).json({ ok: false, error: "Wrong current password." });
            }
            resetUnlockLimit("ip:" + ip);
        }

        if (s.password === newPassword) {
            return res.status(400).json({ ok: false, error: "The new password is the same as the current one." });
        }
        await col.updateOne({ id }, { $set: { password: newPassword, passwordChangedAt: new Date() } });
        return res.json({ ok: true });
    } catch (err) {
        console.error("change-password failed:", err.stack || err.message);
        return res.status(500).json({ ok: false, error: "Server error. Try again." });
    }
});

function watchAuth(req, res) {
    const secret = process.env.WATCH_SECRET;
    if (!secret || secret.length < 16) {
        res.status(503).json({ ok: false, error: "WATCH_SECRET is not configured (use at least 16 characters)." });
        return false;
    }
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
    if (!checkUnlockLimit("watch:" + ip, UNLOCK_MAX_IP)) {
        res.status(429).json({ ok: false, error: "Too many attempts." });
        return false;
    }
    const given = String(req.headers["x-watch-key"] || req.query.key || "");
    const a = crypto.createHash("sha256").update(given).digest();
    const b = crypto.createHash("sha256").update(secret).digest();
    if (!crypto.timingSafeEqual(a, b)) {
        res.status(401).json({ ok: false, error: "Unauthorized." });
        return false;
    }
    resetUnlockLimit("watch:" + ip);
    return true;
}

app.all("/api/watch/run", async (req, res) => {
    if (!watchAuth(req, res)) return;
    try {
        const report = await runWatchScan();
        console.log("[watch] scan done:", JSON.stringify({ blocked: report.blocked.length, review: report.review.length, errors: report.scanned.filter(x => x.error).length }));
        res.json({ ok: true, ...report });
    } catch (e) {
        console.error("[watch] scan failed:", e.stack || e.message);
        res.status(500).json({ ok: false, error: "Scan failed." });
    }
});

app.get("/api/watch/status", async (req, res) => {
    if (!watchAuth(req, res)) return;
    try {
        const docs = await blockedPathsCol.find({}).sort({ updatedAt: -1 }).limit(200).toArray();
        res.json({
            ok: true,
            sources: await getWatchSources(),
            blocked: docs.filter(d => d.status === "blocked").map(d => ({ path: d.path, reason: d.reason, sources: d.sources })),
            review: docs.filter(d => d.status === "review").map(d => ({ path: d.path, reason: d.reason, sources: d.sources })),
            allowed: docs.filter(d => d.status === "allowed").map(d => d.path)
        });
    } catch (e) {
        res.status(500).json({ ok: false, error: "Could not read status." });
    }
});

app.post("/api/watch/source", async (req, res) => {
    if (!watchAuth(req, res)) return;
    try {
        const url = req.body && req.body.url;
        if (typeof url !== "string" || !isSafeWatchUrl(url)) return res.status(400).json({ ok: false, error: "Source must be a public https URL." });
        if (req.body.remove) await watchSourcesCol.deleteOne({ url });
        else await watchSourcesCol.updateOne({ url }, { $set: { url }, $setOnInsert: { addedAt: new Date() } }, { upsert: true });
        res.json({ ok: true, sources: await getWatchSources() });
    } catch (e) {
        res.status(500).json({ ok: false, error: "Could not update sources." });
    }
});

app.post("/api/watch/block", async (req, res) => {
    if (!watchAuth(req, res)) return;
    try {
        const p = normalizeSitePath(String((req.body && req.body.path) || ""));
        if (!p || p === "/" || p === "/api/watch" || p.startsWith("/api/watch/")) return res.status(400).json({ ok: false, error: "Invalid path." });
        await blockedPathsCol.updateOne({ path: p }, { $set: { status: "blocked", reason: "manual", updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
        await refreshBlocked(true);
        res.json({ ok: true, path: p });
    } catch (e) {
        res.status(500).json({ ok: false, error: "Could not block path." });
    }
});

app.post("/api/watch/unblock", async (req, res) => {
    if (!watchAuth(req, res)) return;
    try {
        const p = normalizeSitePath(String((req.body && req.body.path) || ""));
        if (!p) return res.status(400).json({ ok: false, error: "Invalid path." });
        await blockedPathsCol.updateOne({ path: p }, { $set: { status: "allowed", reason: "unblocked by admin", updatedAt: new Date() }, $setOnInsert: { createdAt: new Date() } }, { upsert: true });
        await refreshBlocked(true);
        res.json({ ok: true, path: p });
    } catch (e) {
        res.status(500).json({ ok: false, error: "Could not unblock path." });
    }
});

async function adminCleanup(req, res) {
    try {
        const result = await tempCollection.deleteMany({});
        res.json({ ok: true, deleted: result.deletedCount });
    } catch(e) { res.json({ ok: false, error: e.message }); }
}

async function adminCleanupKeys(req, res) {
    try {
        const REVOKED_GRACE_MS  = 90 * 24 * 60 * 60 * 1000; // keep revoked keys 90d for audit/dispute purposes
        const ABANDONED_GRACE_MS = 90 * 24 * 60 * 60 * 1000; // never redeemed within 90d = safe to assume abandoned
        const now = Date.now();

        const revokedResult = await keysCollection.deleteMany({
            revoked: true,
            revokedAt: { $lt: new Date(now - REVOKED_GRACE_MS) }
        });
        const abandonedResult = await keysCollection.deleteMany({
            firstUsedAt: null,
            expiresAt: null,
            revoked: false, // already covered by revokedResult above if also revoked
            createdAt: { $lt: new Date(now - ABANDONED_GRACE_MS) }
        });

        res.json({
            ok: true,
            deletedRevoked: revokedResult.deletedCount,
            deletedAbandoned: abandonedResult.deletedCount
        });
    } catch(e) { res.json({ ok: false, error: e.message }); }
}

async function adminLogoutAll(req, res) {
    try {
        const result = await sessionsCol.deleteMany({});
        res.json({ ok: true, deleted: result.deletedCount });
    } catch(e) { res.json({ ok: false, error: e.message }); }
}

async function adminViewScript(req, res) {
    try {
        const scriptId = req.body && req.body.scriptId;
        if (!scriptId || typeof scriptId !== "string") {
            return res.json({ ok: false, error: "Missing or invalid scriptId." });
        }

        let s = await scriptsCollection.findOne({ id: scriptId });
        let location = "permanent";
        if (!s) {
            s = await tempCollection.findOne({ id: scriptId });
            location = "temp";
        }
        if (!s) return res.json({ ok: false, error: "No script found with that ID." });

        const code = await readScriptCode(s);

        let owner = null;
        if (s.owner) {
            const u = await mgUserGet(s.owner);
            if (u && u.data) owner = { userId: s.owner, username: u.data.username || null, email: u.data.email || null };
            else owner = { userId: s.owner, username: null, email: null };
        }

        const collabRows = await collaboratorsCol.find({ scriptId }).sort({ addedAt: -1 }).toArray();
        const collaborators = collabRows.map(c => ({
            email: c.email,
            permissions: c.permissions || [],
            addedAt: c.addedAt || null,
            claimed: !!c.userId
        }));
        const auditRows = await collabAuditCol.find({ scriptId }).sort({ at: -1 }).limit(20).toArray();
        const collabAudit = auditRows.map(a => ({
            action: a.action,
            email: a.email,
            permissions: a.permissions || [],
            at: a.at
        }));

        res.json({
            ok: true,
            location,
            id: s.id,
            owner,
            password: s.password || null,
            createdAt: s.createdAt || null,
            scrapID: s.scrapID || null,
            code,
            collaborators,
            collabAudit
        });
    } catch(e) { res.json({ ok: false, error: e.message }); }
}

app.post("/api/update-profile", async (req, res) => {
    const sid = req.cookies && req.cookies.sid;
    if (!sid || !await sessionStore.has(sid)) return res.json({ ok: false });
    const userId = await sessionStore.get(sid);
    const update = {};
    const b = req.body || {};
    if (b.username !== undefined) {
        if (typeof b.username !== "string" || !b.username.trim() || b.username.trim().length > 40) return res.json({ ok: false, error: "Username must be 1-40 characters" });
        update.username = b.username.trim();
    }
    if (b.email !== undefined) {
        if (typeof b.email !== "string" || b.email.trim().length > 254 || !isValidEmail(b.email)) return res.json({ ok: false, error: "Invalid email address" });
        update.email = b.email.trim().toLowerCase();
    }
    if (b.avatar !== undefined) {
        if (typeof b.avatar !== "string" || b.avatar.length > 500 || !/^https:\/\//i.test(b.avatar)) return res.json({ ok: false, error: "Avatar must be an https URL" });
        update.avatar = b.avatar;
    }
    if (Object.keys(update).length === 0) return res.json({ ok: false, error: "Nothing to update" });
    try {
        const existing = await mgUserGet(userId);
        if (!existing) return res.json({ ok: false, error: "User not found" });
        const updated = { ...existing.data, ...update };
        if (update.email !== undefined && update.email !== String(existing.data.email || "").toLowerCase()) updated.emailVerified = false; // changed by hand => unverified
        await mgUserPut(userId, updated);
        if (mountedAuthRouter && mountedAuthRouter.invalidateUserCache) {
            mountedAuthRouter.invalidateUserCache(userId);
        }
        res.json({ ok: true });
    } catch (e) { res.json({ ok: false, error: e.message }); }
});

const PASSWORD_MIN = 5;
const PASSWORD_MAX = 20;
const CUSTOM_PATH_MIN = 3;
const CUSTOM_PATH_MAX = 20;
const RESERVED_PATHS = new Set([
    "api", "watch", "me", "create", "save", "delete", "scripts", "integrations", "analytics",
    "dashboard-create", "update-profile", "my-scripts", "my-collaborations", "verify-key",
    "check-hwid", "delete-account", "custom-path", "hcaptcha", "admin", "login", "logout",
    "dashboard", "auth", "raw", "raw2", "getkey", "checkpoint", "verify", "unlock", "about",
    "term", "policy", "migrate-page", "server-ping", "linkvertise", "lua-highlight", "static",
    "public", "favicon", "null", "undefined", "script", "scriptid", "test", "root", "support"
]);

function validatePassword(pw) {
    if (typeof pw !== "string") return "Password is required.";
    if (pw.length < PASSWORD_MIN || pw.length > PASSWORD_MAX || pw.trim().length < PASSWORD_MIN) {
        return "Password must be " + PASSWORD_MIN + "-" + PASSWORD_MAX + " characters.";
    }
    return null;
}

function validateCustomPath(raw) {
    if (typeof raw !== "string") return { ok: false, error: "Custom path must be text." };
    if (/[\s\u0000-\u001f\u007f\u0085\u00a0\u1680\u2000-\u200f\u2028-\u202f\u205f-\u2064\u3000\ufeff]/.test(raw)) {
        return { ok: false, error: "Custom path cannot contain spaces or line breaks." };
    }
    if (raw.length < CUSTOM_PATH_MIN || raw.length > CUSTOM_PATH_MAX) {
        return { ok: false, error: "Custom path must be " + CUSTOM_PATH_MIN + "-" + CUSTOM_PATH_MAX + " characters." };
    }
    if (!/^[A-Za-z0-9](?:[A-Za-z0-9_-]*[A-Za-z0-9])?$/.test(raw)) {
        return { ok: false, error: "Use only letters, numbers, - and _ (must start and end with a letter or number)." };
    }
    const name = raw.toLowerCase();
    if (RESERVED_PATHS.has(name)) return { ok: false, error: "That name is reserved. Pick another." };
    return { ok: true, name };
}

async function scriptIdTaken(name) {
    if (isBlockedPath("/" + name)) return true;
    const hit = await scriptsCollection.findOne({ id: name }, { projection: { _id: 1 } })
        || await tempCollection.findOne({ id: name }, { projection: { _id: 1 } });
    return !!hit;
}

app.get("/api/my-scripts", async (req, res) => {
    const sid = req.cookies && req.cookies.sid;
    if (!sid || !await sessionStore.has(sid)) return res.json({ ok: false, scripts: [] });
    const userId = await sessionStore.get(sid);
    try {
        const scripts = await scriptsCollection
            .find({ owner: userId })
            .sort({ createdAt: -1 })
            .toArray();
        console.log("my-scripts: userId=" + userId + " found=" + scripts.length);
        res.json({ ok: true, scripts: scripts.map(s => ({
            id: s.id,
            createdAt: s.createdAt,
            password: s.password,
            keySystem: s.keySystem || null,
            bgUrl: s.bgUrl || null
        })) });
    } catch(e) {
        console.error("my-scripts error:", e.message);
        res.json({ ok: true, scripts: [] });
    }
});

const PROVIDERS = {
  linkvertise: { name:"Linkvertise",          website:"https://linkvertise.com",    color:"#1de9b6" },
  lootlabs:    { name:"Lootlabs",             website:"https://lootlabs.gg",        color:"#f59e0b" },
  workink:     { name:"Work.ink",             website:"https://work.ink",           color:"#6366f1" },
  shrtfly:     { name:"Shrtfly",             website:"https://shrtfly.com",        color:"#ec4899" },
  shortjambo:  { name:"Short-jambo",          website:"https://short-jambo.com",    color:"#10b981" },
  shrinkearn:  { name:"Shrinkearn",           website:"https://shrinkearn.com",     color:"#f97316" },
  linkunlocker:{ name:"LinkUnlocker",         website:"https://linkunlocker.com",   color:"#8b5cf6" },
  rinku:       { name:"Rinku",               website:"https://rinku.me",           color:"#06b6d4" },
  custom:      { name:"Custom Provider",      website:"",                            color:"#94a3b8" }
};

const REQUIRED_INTEGRATION_FIELDS = {
  linkvertise:  ["anti_bypass_token", "target_link"],
  lootlabs:     ["api_key"],
  workink:      ["api_key"],
  shrtfly:      ["api_key"],
  shortjambo:   ["api_key"],
  shrinkearn:   ["api_key"],
  linkunlocker: ["api_token", "unlock_url"],
  rinku:        ["api_key", "salt"]
};

function findMissingIntegrationFields(provider, fields) {
  const required = REQUIRED_INTEGRATION_FIELDS[provider] || [];
  const f = fields || {};
  return required.filter(key => !f[key] || !String(f[key]).trim());
}

async function buildProviderLink(integration, callbackUrl) {
  const f = integration.fields || {};
  try {
    switch (integration.provider) {
      case "linkvertise":
        throw new Error("linkvertise must not go through buildProviderLink() — special-cased in /checkpoint");
      case "lootlabs":
        throw new Error("lootlabs must not go through buildProviderLink() — special-cased in /checkpoint");
      case "workink":
        throw new Error("workink must not go through buildProviderLink() — special-cased in /checkpoint");
      case "shrtfly": {
        const resp = await axios.get("https://shrtfly.com/api", {
          params: { api: f.api_key, url: callbackUrl, type: 1, format: "json" }
        });
        const url = resp.data?.result?.shorten_url;
        if (!url) throw new Error("Shrtfly response missing a link: " + JSON.stringify(resp.data));
        return url;
      }
      case "shortjambo": {
        const resp = await axios.get("https://short-jambo.com/api", {
          params: { api: f.api_key, url: callbackUrl, ...(f.alias ? { alias: f.alias } : {}) }
        });
        const url = resp.data?.shortenedUrl || resp.data?.url;
        if (!url) throw new Error("Short-Jambo response missing a link: " + JSON.stringify(resp.data));
        return url;
      }
      case "shrinkearn": {
        const resp = await axios.get("https://shrinkearn.com/api", {
          params: { api: f.api_key, url: callbackUrl, format: "json" }
        });
        const url = resp.data?.shortenedUrl || resp.data?.url;
        if (!url) throw new Error("ShrinkEarn response missing a link: " + JSON.stringify(resp.data));
        return url;
      }
      case "linkunlocker":
        throw new Error("linkunlocker must not go through buildProviderLink() — special-cased in /checkpoint");
      case "rinku": {
        const resp = await axios.get("https://rinku.me/api", {
          params: { api: f.api_key, url: callbackUrl }
        });
        const url = resp.data?.shortenedUrl || resp.data?.url;
        if (!url) throw new Error("Rinku response missing a link: " + JSON.stringify(resp.data));
        return url;
      }
      default:
        throw new Error("Unknown provider: " + integration.provider);
    }
  } catch (e) {
    console.error("buildProviderLink failed for", integration.provider, e.message);
    throw new Error("This script's provider link couldn't be generated right now. Please try again shortly.");
  }
}

async function buildLinkUnlockerLink(unlockUrl, apiToken, destinationUrl) {
  const resp = await axios.post(
    "https://linkunlocker.com/api/public/url_encryptor",
    { destination_url: destinationUrl, api_token: apiToken },
    { headers: { "Content-Type": "application/json" } }
  );
  const hash = resp.data?.hash || resp.data?.message;
  if (!hash) throw new Error("LinkUnlocker encryptor returned no hash");
  const sep = unlockUrl.includes("?") ? "&" : "?";
  return { url: `${unlockUrl}${sep}hash=${encodeURIComponent(hash)}`, hash };
}

async function verifyLinkUnlockerHash(hash, apiToken) {
  const resp = await axios.get("https://linkunlocker.com/api/public/hash/validate", {
    params: { hash, api_token: apiToken, deleteToken: 1 } // deleteToken: one-time use, per docs
  });
  return resp.data?.valid === true;
}

async function getOrCreateWorkinkBaseLink(integration, f, host) {
  if (integration.workinkBaseUrl) return integration.workinkBaseUrl;
  const resp = await axios.post(
    "https://dashboard.work.ink/_api/v1/link",
    { title: "ObfuscatorHub Key System", destination: `https://${host}/`, link_description: "Complete one quick step to unlock your ObfuscatorHub key instantly 🔑" }, // inert placeholder destination — always overridden per-visit via ?sr=
    { headers: { "X-Api-Key": f.api_key, "Content-Type": "application/json" }, timeout: 8000 }
  );
  if (resp.data?.error === true) throw new Error("Work.ink rejected the link creation: " + (resp.data?.message || JSON.stringify(resp.data)));
  const url = resp.data?.response?.url || resp.data?.url;
  if (!url) throw new Error("Work.ink link creation returned no url: " + JSON.stringify(resp.data));
  await integrationsCol.updateOne({ id: integration.id }, { $set: { workinkBaseUrl: url } });
  return url;
}

async function buildWorkinkLink(integration, f, callbackUrl, host) {
  const baseUrl = await getOrCreateWorkinkBaseLink(integration, f, host);
  const resp = await axios.get("https://work.ink/_api/v2/override", {
    params: { destination: callbackUrl },
    timeout: 8000
  });
  const sr = resp.data?.sr;
  if (!sr) throw new Error("Work.ink override returned no sr token");
  const sep = baseUrl.includes("?") ? "&" : "?";
  return `${baseUrl}${sep}sr=${encodeURIComponent(sr)}`;
}

async function verifyLinkvertiseHash(hash, apiToken) {
  const resp = await axios.post(
    "https://publisher.linkvertise.com/api/v1/anti_bypassing",
    null,
    { params: { token: apiToken, hash } }
  );
  console.log("[linkvertise] hash length:", hash?.length, "response:", JSON.stringify(resp.data));
  let value = resp.data;
  if (value && typeof value === "object" && "status" in value) value = value.status;
  if (typeof value === "string") value = value.trim().toUpperCase();
  return value === true || value === "TRUE";
}

async function getOrCreateLootlabsBaseLink(integration, f, host) {
  if (integration.lootlabsBaseUrl) return integration.lootlabsBaseUrl;
  const resp = await axios.post("https://creators.lootlabs.gg/api/public/content_locker", {
    title: (f.title || "Unlock").slice(0, 30),
    url: `https://${host}/`, // inert placeholder — always overridden per-visit via &data=
    tier_id: f.tier_id ? parseInt(f.tier_id) : 1,
    number_of_tasks: f.tasks ? parseInt(f.tasks) : 1,
    ...(f.theme ? { theme: parseInt(f.theme) } : {}),
    ...(f.thumbnail ? { thumbnail: f.thumbnail } : {})
  }, { headers: { Authorization: `Bearer ${f.api_key}` } });
  const lootUrl = resp.data?.message?.loot_url;
  if (!lootUrl) throw new Error("LootLabs content_locker returned no loot_url: " + JSON.stringify(resp.data));
  await integrationsCol.updateOne({ id: integration.id }, { $set: { lootlabsBaseUrl: lootUrl } });
  return lootUrl;
}

async function buildLootlabsLink(integration, f, callbackUrl, host) {
  const baseUrl = await getOrCreateLootlabsBaseLink(integration, f, host);
  const resp = await axios.post("https://creators.lootlabs.gg/api/public/url_encryptor", {
    destination_url: callbackUrl,
    api_token: f.api_key
  }, { headers: { "Content-Type": "application/json" } });
  const encrypted = resp.data?.message;
  if (!encrypted) throw new Error("LootLabs url_encryptor returned no encrypted value: " + JSON.stringify(resp.data));
  const sep = baseUrl.includes("?") ? "&" : "?";
  return `${baseUrl}${sep}data=${encrypted}`;
}

app.get("/api/integrations", async (req, res) => {
  const sid = req.cookies?.sid;
  if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, integrations:[] });
  const userId = await sessionStore.get(sid);
  try {
    const ints = await integrationsCol.find({ owner:userId }).sort({ createdAt:-1 }).toArray();
    res.json({ ok:true, integrations: ints.map(i=>({
      id:i.id, name:i.name, provider:i.provider, createdAt:i.createdAt,
      fields: Object.fromEntries(Object.entries(i.fields||{}).map(([k,v])=>[k, /token|key/i.test(k) && typeof v === "string" ? v.slice(0,4)+"••••" : v]))
    }))});
  } catch(e) { res.json({ ok:false, integrations:[], error:e.message }); }
});

app.post("/api/integrations/create", async (req, res) => {
  const sid = req.cookies?.sid;
  if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, error:"Not logged in" });
  const userId = await sessionStore.get(sid);
  const { name, provider, fields } = req.body;
  if (!provider || !PROVIDERS[provider]) return res.json({ ok:false, error:"Unknown provider" });
  if (!name || !name.trim()) return res.json({ ok:false, error:"Integration name is required" });
  const missing = findMissingIntegrationFields(provider, fields);
  if (missing.length) return res.json({ ok:false, error:`Missing required field(s): ${missing.join(", ")}` });
  try {
    const doc = {
      id: crypto.randomBytes(8).toString("hex"),
      owner: userId,
      name: name.trim(), // the author's custom name, e.g. "Main Shrinkearn" — was previously
      provider, fields: fields||{},
      createdAt: new Date()
    };
    await integrationsCol.insertOne(doc);
    res.json({ ok:true, integration:{ id:doc.id, name:doc.name, provider:doc.provider } });
  } catch(e) { res.json({ ok:false, error:e.message }); }
});

app.post("/api/integrations/delete", async (req, res) => {
  const sid = req.cookies?.sid;
  if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, error:"Not logged in" });
  const userId = await sessionStore.get(sid);
  const { id, force } = req.body;
  try {
    if (!force) {
      const dependents = await scriptsCollection
        .find({ owner: userId, "keySystem.integrationId": id }, { projection: { id: 1 } })
        .toArray();
      if (dependents.length) {
        return res.json({
          ok: false,
          error: `This integration is used by ${dependents.length} script(s). Delete anyway?`,
          inUseBy: dependents.map(s => s.id),
          requiresForce: true
        });
      }
    }
    await integrationsCol.deleteOne({ id, owner:userId });
    res.json({ ok:true });
  } catch(e) { res.json({ ok:false, error:e.message }); }
});

function cleanDiscordInvite(v) {
  // Paid-script server / group link: Discord, Telegram or any other https group link
  v = String(v || "").trim();
  if (!v) return null;
  return v.length <= 300 && /^https:\/\/[^\s"'()<>\\]+$/.test(v) ? v : false;
}
function cleanBgUrl(v) {
  v = String(v || "").trim();
  if (!v) return null;
  return v.length <= 500 && /^https:\/\/[^\s"'()<>\\]+$/.test(v) ? v : false;
}

app.post("/api/scripts/:id/background", async (req, res) => {
  const sid = req.cookies?.sid;
  if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, error:"Not logged in" });
  const userId = await sessionStore.get(sid);
  try {
    const bgUrl = cleanBgUrl(req.body.bgUrl);
    if (bgUrl === false) return res.json({ ok:false, error:"Invalid image URL. It must start with https:// and have no spaces or quotes." });
    const s = await getScriptForAccess(req.params.id, userId, "edit");
    if (!s) return res.json({ ok:false, error:"Script not found" });
    await scriptsCollection.updateOne({ id:req.params.id }, { $set:{ bgUrl } });
    res.json({ ok:true, bgUrl });
  } catch(e) { res.json({ ok:false, error:e.message }); }
});

app.get("/api/script-bg/:id", async (req, res) => {
  try {
    const s = await scriptsCollection.findOne({ id:req.params.id }, { projection:{ bgUrl:1 } });
    res.setHeader("Cache-Control", "no-store");
    res.json({ bgUrl: (s && s.bgUrl) || null });
  } catch(e) { res.json({ bgUrl:null }); }
});

app.get("/api/scripts/:id/keysystem", async (req, res) => {
  const sid = req.cookies?.sid;
  if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, error:"Not logged in" });
  const userId = await sessionStore.get(sid);
  try {
    const s = await getScriptForAccess(req.params.id, userId, "see_keys");
    if (!s) return res.json({ ok:false, error:"Script not found" });
    res.json({ ok:true, keySystem: s.keySystem || { enabled:false } });
  } catch(e) { res.json({ ok:false, error:e.message }); }
});

app.post("/api/scripts/:id/keysystem", async (req, res) => {
  const sid = req.cookies?.sid;
  if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, error:"Not logged in" });
  const userId = await sessionStore.get(sid);
  let { enabled, integrationId, customLink, expiryHours, maxDevices, discordInvite } = req.body;
  if (integrationId === "__custom__") integrationId = null;
  else customLink = ""; // only keep customLink when __custom__ was actually selected
  try {
    const s = await getScriptForAccess(req.params.id, userId, enabled ? "keysystem_on" : "keysystem_off");
    if (!s) return res.json({ ok:false, error:"Script not found" });

    if (integrationId) {
      const integration = await integrationsCol.findOne({ id: integrationId, owner: userId });
      if (!integration) {
        return res.json({ ok:false, error:"Integration not found or not owned by you" });
      }
    }

    let ksExpiryHours = parseInt(expiryHours, 10);
    if (isNaN(ksExpiryHours) || ksExpiryHours < 0) ksExpiryHours = 24;

    let ksDiscord = s.keySystem && s.keySystem.discordInvite ? s.keySystem.discordInvite : null;
    if (discordInvite !== undefined) {
      ksDiscord = cleanDiscordInvite(discordInvite);
      if (ksDiscord === false) return res.json({ ok:false, error:"Invalid link. It must start with https:// (Discord, Telegram or other group link) and have no spaces or quotes." });
    }

    const keySystem = {
      enabled: !!enabled,
      discordInvite: ksDiscord,
      integrationId: integrationId || null,
      customLink: (customLink || "").trim() || null,
      expiryHours: ksExpiryHours,
      maxDevices:  Math.max(1, parseInt(maxDevices)  || 1)
    };
    await scriptsCollection.updateOne({ id:req.params.id }, { $set:{ keySystem } });
    res.json({ ok:true, keySystem });
  } catch(e) { res.json({ ok:false, error:e.message }); }
});

function genKey(prefix) {
  const p = String(typeof prefix === "string" ? prefix : "OBFHUB").toUpperCase().replace(/[^A-Z0-9_-]/g, "").slice(0,10) || "OBFHUB";
  const h = () => crypto.randomBytes(2).toString("hex").toUpperCase();
  return `${p}-${h()}-${h()}-${h()}-${h()}`;
}

app.get("/api/scripts/:id/keys", async (req, res) => {
  const sid = req.cookies?.sid;
  if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, keys:[] });
  const userId = await sessionStore.get(sid);
  try {
    const s = await getScriptForAccess(req.params.id, userId, "see_keys");
    if (!s) return res.json({ ok:false, keys:[] });
    const now = new Date();
    const keys = await keysCollection.find({ scriptId:req.params.id }).sort({ createdAt:-1 }).toArray();
    res.json({ ok:true, keys: keys.map(k=>({
      key:k.key,
      hwids:     k.hwids     || [],
      executors: k.executors || [],
      maxDevices:k.maxDevices,
      uses:      k.uses      || 0,
      note:      k.note      || "",
      firstUsedAt: k.firstUsedAt || null,
      expiresAt:   k.expiresAt   || null,
      createdAt:   k.createdAt,
      createdBy:   k.note === "auto:checkpoint" ? "user (checkpoint)" : "author",
      status: k.revoked ? "revoked"
            : (k.expiresAt && now > new Date(k.expiresAt)) ? "expired"
            : k.firstUsedAt ? "active"
            : "unused"
    }))});
  } catch(e) { res.json({ ok:false, keys:[], error:e.message }); }
});

app.post("/api/scripts/:id/keys/generate", async (req, res) => {
  const sid = req.cookies?.sid;
  if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, error:"Not logged in" });
  const userId = await sessionStore.get(sid);
  const { prefix, expiryHours, note, maxDevices } = req.body;
  try {
    const s = await getScriptForAccess(req.params.id, userId, "generate_key");
    if (!s) return res.json({ ok:false, error:"Script not found" });
    const ks = s.keySystem || {};
    let reqHours = parseInt(expiryHours, 10);
    if (isNaN(reqHours)) reqHours = parseInt(ks.expiryHours, 10);
    if (isNaN(reqHours)) reqHours = 24;
    if (reqHours < 0) reqHours = 24;
    const doc = {
      key: genKey(prefix),
      scriptId: req.params.id,
      hwids: [], uses: 0, revoked: false,
      maxDevices: Math.max(1, parseInt(maxDevices)||ks.maxDevices||1),
      expiryHours: reqHours,
      expiresAt: null, firstUsedAt: null,
      note: typeof note === "string" ? note.slice(0, 100) : "",
      createdAt: new Date()
    };
    await keysCollection.insertOne(doc);
    res.json({ ok:true, key:doc.key });
  } catch(e) { res.json({ ok:false, error:e.message }); }
});

app.post("/api/scripts/:id/keys/revoke", async (req, res) => {
  const sid = req.cookies?.sid;
  if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, error:"Not logged in" });
  const userId = await sessionStore.get(sid);
  const { key } = req.body;
  try {
    const s = await getScriptForAccess(req.params.id, userId, "revoke_key");
    if (!s) return res.json({ ok:false, error:"Script not found" });
    const result = await keysCollection.updateOne({ key, scriptId:req.params.id }, { $set:{ revoked:true, revokedAt: new Date() } });
    if (result.matchedCount === 0) return res.json({ ok:false, error:"Key not found for this script." });
    res.json({ ok:true });
  } catch(e) { res.json({ ok:false, error:e.message }); }
});

app.post("/api/scripts/:id/keys/hwid-reset", async (req, res) => {
  const sid = req.cookies?.sid;
  if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, error:"Not logged in" });
  const userId = await sessionStore.get(sid);
  const { key } = req.body;
  try {
    const s = await getScriptForAccess(req.params.id, userId, "reset_hwid");
    if (!s) return res.json({ ok:false, error:"Script not found" });
    const result = await keysCollection.updateOne({ key, scriptId:req.params.id }, { $set:{ hwids:[] } });
    if (result.matchedCount === 0) return res.json({ ok:false, error:"Key not found for this script." });
    res.json({ ok:true });
  } catch(e) { res.json({ ok:false, error:e.message }); }
});

function isValidEmail(raw) {
    if (typeof raw !== "string") return false;
    const email = raw.trim().toLowerCase();
    if (email.length > 254 || /[\s<>"'`&\\]/.test(email)) return false; // emails are rendered into pages; no markup characters
    let atIndex = -1, dotIndex = -1;
    for (let i = 0; i < email.length; i++) {
        const c = email[i];
        if (c === "@" && atIndex === -1) atIndex = i;
        if (c === "." && atIndex !== -1 && i > atIndex) dotIndex = i;
    }
    const hasCharsBeforeAt = atIndex > 0;
    const hasCharsBetween  = atIndex !== -1 && dotIndex !== -1 && (dotIndex - atIndex) > 1;
    const hasCharsAfterDot = dotIndex !== -1 && dotIndex < email.length - 1;
    return hasCharsBeforeAt && hasCharsBetween && hasCharsAfterDot;
}

const COLLAB_PERMISSIONS = [
    "view_script", "view_password", "edit",
    "generate_key", "revoke_key", "reset_hwid", "see_keys",
    "keysystem_on", "keysystem_off",
    "delete"
];

async function logCollabAudit(scriptId, email, action, permissions, actorUserId, targetUserId) {
    try {
        await collabAuditCol.insertOne({
            scriptId, email, action, // "invited" | "updated" | "removed" | "claimed"
            permissions: permissions || [],
            actorUserId: actorUserId || null,   // who performed the action (owner), if applicable
            targetUserId: targetUserId || null, // which account claimed it, if applicable
            at: new Date(),
            expiresAt: new Date(Date.now() + 180 * 24 * 60 * 60 * 1000)
        });
    } catch (e) {
        console.error("collab audit log failed:", e.message);
    }
}

async function claimCollaboratorRow(scriptId, email, userId) {
    const claimed = await collaboratorsCol.findOneAndUpdate(
        { scriptId, email, userId: null },
        { $set: { userId, claimedAt: new Date() } },
        { returnDocument: "after" }
    );
    if (claimed) await logCollabAudit(scriptId, email, "claimed", claimed.permissions || [], null, userId);
    return claimed;
}

async function getCollaboratorPermissions(scriptId, userId) {
    if (!userId) return [];
    try {
        const bound = await collaboratorsCol.findOne({ scriptId, userId });
        if (bound) return bound.permissions || [];

        const ownerData = await mgUserGet(userId);
        const email = ownerData && ownerData.data && ownerData.data.email;
        // An email typed into the profile is not proof of ownership; only provider-verified ones may claim an invite.
        if (!email || typeof email !== "string" || ownerData.data.emailVerified !== true) return [];

        const claimed = await claimCollaboratorRow(scriptId, email.toLowerCase(), userId);
        return claimed ? (claimed.permissions || []) : [];
    } catch {
        return [];
    }
}

const MAX_COLLABORATORS_PER_SCRIPT = 25;

async function getScriptForAccess(scriptId, userId, permission) {
    const s = await scriptsCollection.findOne({ id: scriptId });
    if (!s) return null;
    if (s.owner === userId) return s;
    const perms = await getCollaboratorPermissions(scriptId, userId);
    return perms.includes(permission) ? s : null;
}

app.post("/api/scripts/:id/collaborators", async (req, res) => {
    const sid = req.cookies?.sid;
    if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, error:"Not logged in" });
    const userId = await sessionStore.get(sid);
    const { email, permissions } = req.body;

    if (!isValidEmail(email)) return res.json({ ok:false, error:"Enter a valid email" });
    if (!Array.isArray(permissions)) return res.json({ ok:false, error:"Invalid permissions" });
    const cleanPermissions = [...new Set(permissions.filter(p => COLLAB_PERMISSIONS.includes(p)))];
    if (cleanPermissions.length === 0) return res.json({ ok:false, error:"Select at least one permission" });

    try {
        const s = await scriptsCollection.findOne({ id:req.params.id, owner:userId });
        if (!s) return res.json({ ok:false, error:"Script not found" });

        const normalizedEmail = email.trim().toLowerCase();

        const ownerData = await mgUserGet(userId);
        if (ownerData && ownerData.data.email && ownerData.data.email.toLowerCase() === normalizedEmail) {
            return res.json({ ok:false, error:"You already own this script" });
        }

        const existing = await collaboratorsCol.findOne({ scriptId: req.params.id, email: normalizedEmail });
        if (!existing) {
            const count = await collaboratorsCol.countDocuments({ scriptId: req.params.id });
            if (count >= MAX_COLLABORATORS_PER_SCRIPT) {
                return res.json({ ok:false, error:`This script already has the maximum of ${MAX_COLLABORATORS_PER_SCRIPT} collaborators.` });
            }
        }

        const result = await collaboratorsCol.updateOne(
            { scriptId: req.params.id, email: normalizedEmail },
            { $set: { scriptId: req.params.id, email: normalizedEmail, permissions: cleanPermissions, ownerId: userId, updatedAt: new Date() }, $setOnInsert: { addedAt: new Date(), userId: null } },
            { upsert: true }
        );
        await logCollabAudit(req.params.id, normalizedEmail, result.upsertedCount ? "invited" : "updated", cleanPermissions, userId, null);
        res.json({ ok:true });
    } catch(e) { res.json({ ok:false, error:e.message }); }
});

app.get("/api/scripts/:id/collaborators", async (req, res) => {
    const sid = req.cookies?.sid;
    if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, collaborators:[] });
    const userId = await sessionStore.get(sid);
    try {
        const s = await scriptsCollection.findOne({ id:req.params.id, owner:userId });
        if (!s) return res.json({ ok:false, collaborators:[] });
        const list = await collaboratorsCol.find({ scriptId: req.params.id }).sort({ addedAt:-1 }).toArray();
        res.json({ ok:true, collaborators: list.map(c => ({
            email: c.email,
            permissions: c.permissions || [],
            addedAt: c.addedAt,
            claimed: !!c.userId // true once the invited email's account has logged in at least once
        })) });
    } catch(e) { res.json({ ok:false, collaborators:[], error:e.message }); }
});

app.post("/api/scripts/:id/collaborators/remove", async (req, res) => {
    const sid = req.cookies?.sid;
    if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, error:"Not logged in" });
    const userId = await sessionStore.get(sid);
    const { email } = req.body;
    if (!isValidEmail(email)) return res.json({ ok:false, error:"Invalid email" });
    try {
        const s = await scriptsCollection.findOne({ id:req.params.id, owner:userId });
        if (!s) return res.json({ ok:false, error:"Script not found" });
        const normalizedEmail = email.trim().toLowerCase();
        const result = await collaboratorsCol.deleteOne({ scriptId:req.params.id, email: normalizedEmail });
        if (result.deletedCount === 0) return res.json({ ok:false, error:"Collaborator not found" });
        await logCollabAudit(req.params.id, normalizedEmail, "removed", [], userId, null);
        res.json({ ok:true });
    } catch(e) { res.json({ ok:false, error:e.message }); }
});

app.get("/api/my-collaborations", async (req, res) => {
    const sid = req.cookies?.sid;
    if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, collaborations:[] });
    const userId = await sessionStore.get(sid);
    try {
        const me = await mgUserGet(userId);
        const email = me && me.data && me.data.email;
        if (email && typeof email === "string" && me.data.emailVerified === true) {
            const normalizedEmail = email.toLowerCase();
            const pending = await collaboratorsCol.find({ email: normalizedEmail, userId: null }).toArray();
            for (const row of pending) {
                await claimCollaboratorRow(row.scriptId, normalizedEmail, userId);
            }
        }

        const rows = await collaboratorsCol.find({ userId }).sort({ addedAt:-1 }).toArray();
        const out = [];
        for (const row of rows) {
            const s = await scriptsCollection.findOne({ id: row.scriptId }, { projection:{ id:1, owner:1 } });
            if (!s) continue; // script since deleted — orphaned grant, just skip it
            const owner = await mgUserGet(s.owner);
            out.push({
                scriptId: row.scriptId,
                permissions: row.permissions || [],
                ownerUsername: (owner && owner.data && owner.data.username) || null,
                addedAt: row.addedAt
            });
        }
        res.json({ ok:true, collaborations: out });
    } catch(e) { res.json({ ok:false, collaborations:[], error:e.message }); }
});

app.get("/api/analytics", async (req, res) => {
  const sid = req.cookies?.sid;
  if (!sid || !await sessionStore.has(sid)) return res.json({ ok:false, error:"Not logged in" });
  const userId = await sessionStore.get(sid);
  try {
    const scripts = await scriptsCollection.find({ owner:userId }).toArray();
    const scriptIds = scripts.map(s=>s.id);
    if (!scriptIds.length) return res.json({ ok:true, stats:{ total:0,active:0,expired:0,revoked:0,unused:0,uniqueDevices:0,redemptions:0 }, scriptBreakdown:[], executors:[] });

    const now = new Date();
    const keys = await keysCollection.find({ scriptId:{ $in:scriptIds } }).toArray();

    let total=0, active=0, expired=0, revoked=0, unused=0, redemptions=0;
    const allHwids = new Set();
    const scriptDeviceSets = {}; // scriptId → Set of unique hwids (per-script dedup, mirrors allHwids globally)
    const executorMap = {}; // executor name → count
    const scriptBreakdown = {};
    scriptIds.forEach(id=>{ scriptBreakdown[id]={ total:0,active:0,expired:0,revoked:0,unused:0,uniqueDevices:0 }; scriptDeviceSets[id]=new Set(); });

    for (const k of keys) {
      total++;
      const bd = scriptBreakdown[k.scriptId] || {};
      bd.total = (bd.total||0)+1;

      if (k.revoked) {
        revoked++; bd.revoked=(bd.revoked||0)+1;
      } else if (k.expiresAt && now>new Date(k.expiresAt)) {
        expired++; bd.expired=(bd.expired||0)+1;
      } else if (!k.firstUsedAt) {
        unused++; bd.unused=(bd.unused||0)+1;
      } else {
        active++; bd.active=(bd.active||0)+1;
      }

      redemptions += k.uses||0;

      (k.hwids||[]).forEach(h=>{
        allHwids.add(h);
        (scriptDeviceSets[k.scriptId] || (scriptDeviceSets[k.scriptId]=new Set())).add(h);
      });

      (k.executors||[]).forEach(name=>{
        executorMap[name] = (executorMap[name]||0)+1;
      });
    }

    for (const id of scriptIds) {
      scriptBreakdown[id].uniqueDevices = scriptDeviceSets[id] ? scriptDeviceSets[id].size : 0;
    }

    const executors = Object.entries(executorMap)
      .sort((a,b)=>b[1]-a[1]).slice(0,5)
      .map(([name,count])=>({ name, count, pct:total>0?Math.round(count/total*100):0 }));

    const breakdown = scripts.map(s=>({ scriptId:s.id, ...(scriptBreakdown[s.id]||{}) }));

    res.json({
      ok:true,
      stats:{ total,active,expired,revoked,unused,uniqueDevices:allHwids.size,redemptions },
      scriptBreakdown: breakdown,
      executors,
      executorsBasis: "percent_of_keys_used_with_executor" // % of keys, not executions/users
    });
  } catch(e) { res.json({ ok:false, error:e.message }); }
});

app.get("/getkey/:id", async (req, res) => {
    try {
        const s = await scriptsCollection.findOne({ id:req.params.id }, { projection:{ keySystem:1 } });
        if (s && s.keySystem && s.keySystem.enabled && s.keySystem.discordInvite) return res.redirect(s.keySystem.discordInvite);
    } catch (e) {}
    res.redirect(`/checkpoint/${req.params.id}`);
});

app.get("/checkpoint/:scriptId", async (req, res) => {
  try {
    const s = await scriptsCollection.findOne({ id:req.params.scriptId });
    if (!s || !s.keySystem || !s.keySystem.enabled)
      return res.status(400).send(renderCheckpointError("Key system not enabled for this script."));

    let providerLink = null;
    let providerName = "Provider";
    let isFree = false;
    let token = null;
    let extraFields = {}; // per-provider verification state (hash/token), merged into the checkpoint doc below
    let int = null; // hoisted so the Linkvertise cookie can be set after the checkpoint doc is inserted below

    if (s.keySystem.customLink) {
      providerLink = s.keySystem.customLink;
      providerName = "Custom Link";
      extraFields = { provider: "custom", sessionId: crypto.randomBytes(20).toString("hex") };
      token = crypto.randomBytes(20).toString("hex");
    } else if (s.keySystem.integrationId) {
      int = await integrationsCol.findOne({ id: s.keySystem.integrationId, owner: s.owner });
      if (!int) return res.status(400).send(renderCheckpointError("No integration configured."));
      providerName = int.name ? `${int.name} (${int.provider})` : (int.provider || "Provider");
      const candidateToken = crypto.randomBytes(20).toString("hex");
      const callbackUrl = `https://${req.headers.host}/checkpoint/${req.params.scriptId}/complete?t=${candidateToken}`;
      const f = int.fields || {};

      if (int.provider === "linkunlocker") {
        if (!f.unlock_url) return res.status(400).send(renderCheckpointError("LinkUnlocker integration is missing its unlock URL."));
        if (!f.api_token) return res.status(400).send(renderCheckpointError("LinkUnlocker integration is missing its Redirect API token."));
        try {
          const { url, hash } = await buildLinkUnlockerLink(f.unlock_url, f.api_token, callbackUrl);
          providerLink = url;
          extraFields = { luHash: hash, luApiToken: f.api_token };
        } catch (e) {
          console.error("LinkUnlocker encrypt failed:", e.message);
          return res.status(502).send(renderCheckpointError("Could not reach LinkUnlocker. Try again shortly."));
        }
      } else if (int.provider === "workink") {
        if (!f.api_key) return res.status(400).send(renderCheckpointError("Work.ink integration is missing its API Key."));
        try {
          providerLink = await buildWorkinkLink(int, f, callbackUrl, req.headers.host);
        } catch (e) {
          console.error(`Work.ink link build failed: ${e.message} | status: ${e.response?.status} | body: ${JSON.stringify(e.response?.data)}`);
          return res.status(502).send(renderCheckpointError("Could not reach Work.ink. Try again shortly."));
        }
      } else if (int.provider === "linkvertise") {
        if (!f.anti_bypass_token) return res.status(400).send(renderCheckpointError("Linkvertise integration is missing its Anti-Bypass token."));
        if (!f.target_link) return res.status(400).send(renderCheckpointError("Linkvertise integration is missing its Permanent Target-Link."));
        providerLink = f.target_link;
        extraFields = { provider: "linkvertise", integrationId: int.id, sessionId: crypto.randomBytes(20).toString("hex") };
      } else if (int.provider === "lootlabs") {
        if (!f.api_key) return res.status(400).send(renderCheckpointError("LootLabs integration is missing its API Token."));
        try {
          providerLink = await buildLootlabsLink(int, f, callbackUrl, req.headers.host);
        } catch (e) {
          console.error(`LootLabs link build failed: ${e.message} | status: ${e.response?.status} | body: ${JSON.stringify(e.response?.data)}`);
          return res.status(502).send(renderCheckpointError("Could not reach LootLabs. Try again shortly."));
        }
      } else {
        providerLink = await buildProviderLink(int, callbackUrl); // can throw/fail — nothing written to DB yet if it does
      }
      token = candidateToken;
    } else {
      isFree = true;
    }

    if (token) {
      await checkpointsCol.insertOne({
        token, scriptId:req.params.scriptId,
        completed: false,
        createdAt: new Date(),
        expiresAt: new Date(Date.now() + 30*60*1000), // uncompleted tokens expire after 30 min
        ...extraFields
      });
    }

    if (extraFields.sessionId && token) {
      res.cookie("OH_CHECKPOINT", extraFields.sessionId, {
        httpOnly: true,
        secure: true,
        sameSite: "lax",
        maxAge: 30 * 60 * 1000,
        path: "/"
      });
    }

    res.setHeader("Cache-Control", "no-store");
    res.send(renderCheckpointTask(req.params.scriptId, providerName, providerLink, isFree));
  } catch(e) { res.status(500).send(renderCheckpointError(e.message)); }
});

app.post("/checkpoint/:scriptId/free-generate", async (req, res) => {
  try {
    const { captcha } = req.body;
    if (!captcha) return res.json({ ok:false, error:"Captcha required" });
    const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
    const hv = await fetch("https://api.hcaptcha.com/siteverify", {
      method:"POST",
      headers:{"Content-Type":"application/x-www-form-urlencoded"},
      body:`secret=${process.env.HCAPTCHA_SECRET}&response=${captcha}&remoteip=${ip}`
    });
    const hd = await hv.json();
    if (!hd.success) return res.json({ ok:false, error:"Captcha failed" });

    const s = await scriptsCollection.findOne({ id:req.params.scriptId });
    if (!s || !s.keySystem || !s.keySystem.enabled)
      return res.json({ ok:false, error:"Key system not active" });

    if (s.keySystem.customLink || s.keySystem.integrationId) {
      return res.status(403).json({ ok:false, error:"This script requires completing the provider link — free generation is not enabled for it." });
    }

    const token = crypto.randomBytes(20).toString("hex");
    await checkpointsCol.insertOne({
      token, scriptId:req.params.scriptId,
      completed:false, createdAt:new Date(),
      expiresAt:new Date(Date.now()+5*60*1000) // 5 min to load the redirect
    });
    res.json({ ok:true, token });
  } catch(e) { res.json({ ok:false, error:e.message }); }
});

async function mintCheckpointKey(scriptId) {
  const s = await scriptsCollection.findOne({ id: scriptId });
  if (!s || !s.keySystem || !s.keySystem.enabled) return null;
  const ks = s.keySystem;
  const key = genKey();
  const safeMaxDevices  = Math.max(1, parseInt(ks.maxDevices, 10) || 1);
  let safeExpiryHours = parseInt(ks.expiryHours, 10);
  if (isNaN(safeExpiryHours) || safeExpiryHours < 0) safeExpiryHours = 24;
  await keysCollection.insertOne({
    key,
    scriptId,
    hwids: [], uses: 0, revoked: false,
    maxDevices: safeMaxDevices,
    expiryHours: safeExpiryHours, // 0 = never expire, preserved through parseInt/isNaN check above
    expiresAt: null, // set on first Roblox use
    firstUsedAt: null,
    note: "auto:checkpoint",
    createdAt: new Date()
  });
  return { key, expiryHours: safeExpiryHours };
}

app.get("/checkpoint/:scriptId/complete", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const token = req.query.t;
  try {
    if (!token || typeof token !== "string") return res.status(403).send(renderCheckpointError("No token provided. Complete the checkpoint link first."));

    const peek = await checkpointsCol.findOne({ token, scriptId:req.params.scriptId });
    if (!peek) return res.status(403).send(renderCheckpointError("Invalid, expired, or already-used token. Go back and complete the link again."));
    if (new Date() > new Date(peek.expiresAt)) {
      const createdMs  = new Date(peek.createdAt).getTime();
      const expiresMs  = new Date(peek.expiresAt).getTime();
      const limitMin   = Math.round((expiresMs - createdMs) / 60000) || 30;
      return res.status(403).send(renderCheckpointError(`Token expired (${limitMin} min limit). Please complete the link again.`));
    }

    if (peek.luHash && peek.luApiToken) {
      let valid = false;
      try { valid = await verifyLinkUnlockerHash(peek.luHash, peek.luApiToken); }
      catch (e) { console.error("LinkUnlocker validate failed:", e.message); }
      if (!valid) return res.status(403).send(renderCheckpointError("LinkUnlocker could not verify this checkpoint. Go back and complete the link again."));
    }

    const cp = await checkpointsCol.findOneAndDelete({ token, scriptId:req.params.scriptId });
    if (!cp) return res.status(403).send(renderCheckpointError("Invalid, expired, or already-used token. Go back and complete the link again."));

    const minted = await mintCheckpointKey(req.params.scriptId);
    if (!minted) return res.status(400).send(renderCheckpointError("This script no longer has an active key system."));

    res.send(renderCheckpointSuccess(req.params.scriptId, minted.key, minted.expiryHours));
  } catch(e) { res.status(500).send(renderCheckpointError(e.message)); }
});

app.get("/linkvertise/callback", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const sessionId = req.cookies?.OH_CHECKPOINT;
    const hash = req.query.hash;
    if (!sessionId) {
      console.log("[linkvertise/callback] missing OH_CHECKPOINT — raw Cookie header:", req.headers.cookie || "(none)", "| Host:", req.headers.host, "| Referer:", req.headers.referer || "(none)");
      return res.status(403).send(renderCheckpointError("No checkpoint session found. Go back and start the checkpoint again."));
    }
    if (!hash) return res.status(403).send(renderCheckpointError("No Linkvertise hash provided. Go back and complete the link again."));

    const cp = await checkpointsCol.findOne({ sessionId, provider: "linkvertise" });
    if (!cp) return res.status(403).send(renderCheckpointError("Invalid or already-used checkpoint session. Go back and complete the link again."));
    if (new Date() > new Date(cp.expiresAt)) {
      await checkpointsCol.deleteOne({ sessionId });
      res.clearCookie("OH_CHECKPOINT", { path: "/" });
      return res.status(403).send(renderCheckpointError("Checkpoint session expired (30 min limit). Please start again."));
    }

    const int = await integrationsCol.findOne({ id: cp.integrationId });
    if (!int || !int.fields?.anti_bypass_token) {
      return res.status(400).send(renderCheckpointError("This Linkvertise integration is no longer configured."));
    }

    let valid = false;
    try { valid = await verifyLinkvertiseHash(hash, int.fields.anti_bypass_token); }
    catch (e) { console.error("Linkvertise anti-bypass check failed:", e.message); }
    if (!valid) {
      return res.status(403).send(renderCheckpointError("Linkvertise could not verify this checkpoint. Go back and complete the link again."));
    }

    const claimed = await checkpointsCol.findOneAndDelete({ sessionId, provider: "linkvertise" });
    if (!claimed) return res.status(403).send(renderCheckpointError("This checkpoint was already completed. Go back and start again if you need another key."));

    const minted = await mintCheckpointKey(claimed.scriptId);
    res.clearCookie("OH_CHECKPOINT", { path: "/" });
    if (!minted) return res.status(400).send(renderCheckpointError("This script no longer has an active key system."));

    res.send(renderCheckpointSuccess(claimed.scriptId, minted.key, minted.expiryHours));
  } catch (e) {
    res.status(500).send(renderCheckpointError(e.message));
  }
});

app.get("/checkpoint/:scriptId/custom-complete", async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  try {
    const sessionId = req.cookies?.OH_CHECKPOINT;
    if (!sessionId) return res.status(403).send(renderCheckpointError("No checkpoint session found. Go back and start the checkpoint again."));

    const claimed = await checkpointsCol.findOneAndDelete({ sessionId, scriptId: req.params.scriptId, provider: "custom" });
    res.clearCookie("OH_CHECKPOINT", { path: "/" });
    if (!claimed) return res.status(403).send(renderCheckpointError("Invalid, expired, or already-used checkpoint session. Go back and complete the link again."));
    if (new Date() > new Date(claimed.expiresAt)) {
      return res.status(403).send(renderCheckpointError("Checkpoint session expired (30 min limit). Please start again."));
    }

    const minted = await mintCheckpointKey(claimed.scriptId);
    if (!minted) return res.status(400).send(renderCheckpointError("This script no longer has an active key system."));

    res.send(renderCheckpointSuccess(claimed.scriptId, minted.key, minted.expiryHours));
  } catch (e) {
    res.status(500).send(renderCheckpointError(e.message));
  }
});

const HCAPTCHA_LINK_TTL_MS = 5 * 60 * 1000; // 5 min — link dies at this point regardless of whether it was ever verified

function signHcaptchaResult(hash, verified) {
    const payload = `${hash}.${verified ? "1" : "0"}`;
    return crypto.createHmac("sha256", process.env.ADMIN_KEY).update(payload).digest("hex");
}

function hcaptchaRedirectUrl(doc) {
    const sig = signHcaptchaResult(doc.hash, true);
    const sep = doc.callback.includes("?") ? "&" : "?";
    return `${doc.callback}${sep}verified=1&hash=${doc.hash}&sig=${sig}`;
}

app.post(["/api/hcaptcha", "/api/hcaptcha/"], async (req, res) => {
    const adminKey = req.headers["x-admin-key"];
    if (!adminKey || typeof adminKey !== "string") {
        return res.status(401).json({ ok: false, error: "Missing admin key. Pass it as x-admin-key header." });
    }
    const keyBuf = Buffer.from(adminKey);
    const realBuf = Buffer.from(process.env.ADMIN_KEY || "");
    const validKey = keyBuf.length === realBuf.length && crypto.timingSafeEqual(keyBuf, realBuf);
    if (!validKey) return res.status(401).json({ ok: false, error: "Invalid admin key." });

    const { callback } = req.body || {};
    if (!callback || typeof callback !== "string") {
        return res.status(400).json({ ok: false, error: "Missing 'callback' — the URL to send the visitor back to once verified." });
    }
    let safeCallback;
    try {
        const url = new URL(callback);
        if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("bad protocol");
        safeCallback = url.href;
    } catch {
        return res.status(400).json({ ok: false, error: "Invalid callback URL." });
    }

    const hash = crypto.randomBytes(20).toString("hex");
    try {
        await hcaptchaCol.insertOne({
            hash, callback: safeCallback, verified: false,
            createdAt: new Date(), expiresAt: new Date(Date.now() + HCAPTCHA_LINK_TTL_MS)
        });
    } catch (e) {
        console.error("hcaptcha_verifications insert failed:", e.message);
        return res.status(500).json({ ok: false, error: "Failed to create verification link." });
    }

    const host = req.headers.host;
    res.json({
        ok: true,
        hash,
        verify: `https://${host}/verify/${hash}`,
        expiresInMinutes: HCAPTCHA_LINK_TTL_MS / 60000
    });
});

app.get("/verify/:hash", async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    try {
        const doc = await hcaptchaCol.findOne({ hash: req.params.hash });
        if (!doc) return res.status(404).send(renderCheckpointError("This verification link is invalid or has already expired."));
        if (new Date() > new Date(doc.expiresAt)) {
            await hcaptchaCol.deleteOne({ hash: req.params.hash });
            return res.status(410).send(renderCheckpointError("This verification link has expired. Ask for a new one."));
        }
        if (doc.verified) return res.redirect(hcaptchaRedirectUrl(doc));

        sendVerifyHtml(req, res);
    } catch (e) {
        res.status(500).send(renderCheckpointError(e.message));
    }
});

app.post("/verify/:hash", async (req, res) => {
    try {
        const doc = await hcaptchaCol.findOne({ hash: req.params.hash });
        if (!doc) return res.status(404).json({ ok: false, error: "Invalid or expired verification link." });
        if (new Date() > new Date(doc.expiresAt)) {
            await hcaptchaCol.deleteOne({ hash: req.params.hash });
            return res.status(410).json({ ok: false, error: "This verification link has expired." });
        }
        if (doc.verified) return res.json({ ok: true, redirect: hcaptchaRedirectUrl(doc) });

        const hToken = req.body && req.body["h-captcha-response"];
        if (!hToken) return res.status(400).json({ ok: false, error: "Captcha required." });

        const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
        const hVerify = await fetch("https://api.hcaptcha.com/siteverify", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: `secret=${process.env.HCAPTCHA_SECRET}&response=${hToken}&remoteip=${ip}`
        });
        const hData = await hVerify.json();
        if (!hData.success) return res.status(403).json({ ok: false, error: "Captcha verification failed. Try again." });

        await hcaptchaCol.updateOne(
            { hash: doc.hash },
            { $set: { verified: true, verifiedAt: new Date() } } // expiresAt untouched — always exactly
        );

        res.json({ ok: true, redirect: hcaptchaRedirectUrl({ ...doc, verified: true }) });
    } catch (e) {
        console.error("hcaptcha verify error:", e.message);
        res.status(500).json({ ok: false, error: "Verification failed. Try again." });
    }
});

app.post("/api/verify-key", async (req, res) => {
  const { scriptId, key, hwid, executor } = req.body;
  if (!scriptId || typeof scriptId !== "string" ||
      !key || typeof key !== "string" ||
      !hwid || typeof hwid !== "string" ||
      (executor !== undefined && (typeof executor !== "string" || executor.length > 64))) {
    return res.json({ valid:false, reason:"Missing parameters" });
  }
  try {
    let keyDoc = await keysCollection.findOne({ key, scriptId });
    if (!keyDoc) return res.json({ valid:false, reason:"Invalid key" });
    if (keyDoc.revoked) return res.json({ valid:false, reason:"Key has been revoked." });

    const now = new Date();

    if (!keyDoc.firstUsedAt) {
      const hours = keyDoc.expiryHours != null ? keyDoc.expiryHours
                  : keyDoc.expiryDays > 0 ? keyDoc.expiryDays * 24
                  : 0;
      const expiresAt = hours > 0 ? new Date(now.getTime() + hours*60*60*1000) : null;
      const claimed = await keysCollection.findOneAndUpdate(
        { key, scriptId, firstUsedAt: null },
        { $set: { firstUsedAt: now, expiresAt } },
        { returnDocument: "after" }
      );
      keyDoc = claimed || await keysCollection.findOne({ key, scriptId });
    }

    if (keyDoc.expiresAt && now > new Date(keyDoc.expiresAt)) {
      await keysCollection.deleteOne({ key, scriptId });
      return res.json({ valid:false, reason:"Key expired. Get a new key from the checkpoint." });
    }

    const hwids = keyDoc.hwids || [];
    const isReturning = hwids.includes(hwid);
    const maxDevices = keyDoc.maxDevices || 1;

    if (!isReturning && hwids.length >= maxDevices) {
      return res.json({
        valid: false,
        reason: `This key is locked to ${maxDevices === 1 ? "another device" : maxDevices + " other devices"}. Ask the script author to reset your HWID if you changed device.`
      });
    }

    let s = await scriptsCollection.findOne({ id: scriptId });
    if (!s) s = await tempCollection.findOne({ id: scriptId });
    if (!s) return res.json({ valid:false, reason:"Script not found." });

    let realCode = null;
    if (s.scrapID) realCode = rubisLoadstringStub(s.scrapID);
    else if (s.fileName) realCode = await legacyGetGitHubFile(s.fileName);
    if (!realCode && s.code) realCode = s.code;
    if (!realCode) return res.json({ valid:false, reason:"Script source unavailable." });

    if (isReturning) {
      if (executor && (keyDoc.executors || []).length < 10) await keysCollection.updateOne({ key, scriptId }, { $addToSet:{ executors:executor }, $inc:{ uses:1 } });
      else await keysCollection.updateOne({ key, scriptId }, { $inc:{ uses:1 } });
    } else {
      const claimed = await keysCollection.findOneAndUpdate(
        { key, scriptId, hwids: { $ne: hwid }, $expr: { $lt: [{ $size: "$hwids" }, "$maxDevices"] } },
        { $push: { hwids: hwid }, $inc: { uses: 1 }, $addToSet: { executors: executor||"unknown" } },
        { returnDocument: "after" }
      );
      if (!claimed) {
        const fresh = await keysCollection.findOne({ key, scriptId });
        if (fresh && (fresh.hwids||[]).includes(hwid)) {
          await keysCollection.updateOne({ key, scriptId }, { $inc:{ uses:1 } });
        } else {
          return res.json({
            valid: false,
            reason: `This key is locked to ${maxDevices === 1 ? "another device" : maxDevices + " other devices"}. Ask the script author to reset your HWID if you changed device.`
          });
        }
      }
    }

    const execId2 = crypto.randomBytes(8).toString("hex");
    const token2  = generateToken();
    await execStore.set(execId2, { code: realCode, ip: req.ip, token: token2 }, 15000);

    const shell = buildAntiHookShell(req.headers.host, scriptId, execId2, token2);

    const freshExecId = crypto.randomBytes(8).toString("hex");
    const freshToken   = generateToken();
    await execStore.set(freshExecId, { code: shell, ip: req.ip, token: freshToken }, 15000); // 15-second window for GUI shell retrieval

    res.json({ valid:true, reason:"OK", execId: freshExecId, token: freshToken });
  } catch(e) { res.json({ valid:false, reason:e.message }); }
});

app.post("/api/check-hwid", async (req, res) => {
  const { scriptId, hwid, executor } = req.body;
  if (!scriptId || typeof scriptId !== "string" ||
      !hwid || typeof hwid !== "string" ||
      (executor !== undefined && typeof executor !== "string")) {
    return res.json({ authorized:false, reason:"Missing parameters" });
  }
  try {
    const candidates = await keysCollection.find({ scriptId, hwids: hwid }).toArray();
    if (!candidates.length) return res.json({ authorized:false, reason:"No cached authorization for this device." });

    const now = new Date();
    const isValid = k => !k.revoked && (!k.expiresAt || now <= new Date(k.expiresAt));
    const keyDoc = candidates.find(isValid);

    if (!keyDoc) {
      for (const k of candidates) {
        if (!k.revoked && k.expiresAt && now > new Date(k.expiresAt)) {
          await keysCollection.deleteOne({ key: k.key, scriptId });
        }
      }
      const reason = candidates.every(k => k.revoked) ? "Key has been revoked." : "Key expired.";
      return res.json({ authorized:false, reason });
    }

    let s = await scriptsCollection.findOne({ id: scriptId });
    if (!s) s = await tempCollection.findOne({ id: scriptId });
    if (!s) return res.json({ authorized:false, reason:"Script not found." });
    if (!s.keySystem?.enabled) return res.json({ authorized:false, reason:"Key system is not enabled." });

    let realCode = null;
    if (s.scrapID) realCode = rubisLoadstringStub(s.scrapID);
    else if (s.fileName) realCode = await legacyGetGitHubFile(s.fileName);
    if (!realCode && s.code) realCode = s.code;
    if (!realCode) return res.json({ authorized:false, reason:"Script source unavailable." });

    const execId2 = crypto.randomBytes(8).toString("hex");
    const token2  = generateToken();
    await execStore.set(execId2, { code: realCode, ip: req.ip, token: token2 }, 15000);

    const shell = buildAntiHookShell(req.headers.host, scriptId, execId2, token2);

    const freshExecId = crypto.randomBytes(8).toString("hex");
    const freshToken   = generateToken();
    await execStore.set(freshExecId, { code: shell, ip: req.ip, token: freshToken }, 15000);

    if (executor) await keysCollection.updateOne({ key: keyDoc.key, scriptId }, { $addToSet:{ executors:executor }, $inc:{ uses:1 } });
    else await keysCollection.updateOne({ key: keyDoc.key, scriptId }, { $inc:{ uses:1 } });

    res.json({ authorized:true, execId: freshExecId, token: freshToken });
  } catch(e) { res.json({ authorized:false, reason:e.message }); }
});

function _cpBase(content, extraScripts) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ObfuscatorHub — Key Checkpoint</title>
<link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700;900&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
:root{--cyan:#00f5ff;--pink:#ff2d78;--purple:#7c3aed;--green:#00ff88;--red:#ff4455;--bg:#050508;--card:#0d0d14;--border:rgba(0,245,255,0.13);}
*{margin:0;padding:0;box-sizing:border-box;}
body{background:var(--bg);color:#e0e8ff;font-family:'JetBrains Mono',monospace;min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;overflow-x:hidden;padding:20px;}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(0,245,255,0.025) 1px,transparent 1px),linear-gradient(90deg,rgba(0,245,255,0.025) 1px,transparent 1px);background-size:40px 40px;animation:gridMove 20s linear infinite;pointer-events:none;z-index:0;}
@keyframes gridMove{to{transform:translateY(40px);}}
.orb{position:fixed;border-radius:50%;filter:blur(80px);opacity:0.1;pointer-events:none;z-index:0;animation:orbFloat 8s ease-in-out infinite;}
.orb1{width:400px;height:400px;background:var(--cyan);top:-100px;left:-80px;}
.orb2{width:300px;height:300px;background:var(--pink);bottom:-80px;right:-60px;animation-delay:-4s;}
@keyframes orbFloat{0%,100%{transform:translate(0,0)}50%{transform:translate(15px,-15px)}}
.wrap{position:relative;z-index:1;width:100%;max-width:460px;animation:fadeUp 0.5s ease;}
@keyframes fadeUp{from{opacity:0;transform:translateY(24px)}to{opacity:1;transform:translateY(0)}}
.brand{font-family:'Orbitron',sans-serif;font-size:12px;font-weight:900;letter-spacing:3px;background:linear-gradient(135deg,var(--cyan),var(--pink));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;text-align:center;margin-bottom:10px;}
.card{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:34px 28px;position:relative;overflow:hidden;text-align:center;}
.card::before{content:'';position:absolute;top:0;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--cyan),var(--pink),transparent);animation:scan 3s linear infinite;}
@keyframes scan{0%,100%{opacity:0.4}50%{opacity:1}}
.icon{font-size:44px;margin-bottom:12px;animation:pulse 2s ease-in-out infinite;}
@keyframes pulse{0%,100%{filter:drop-shadow(0 0 6px var(--cyan))}50%{filter:drop-shadow(0 0 18px var(--cyan))}}
.title{font-family:'Orbitron',sans-serif;font-size:19px;font-weight:900;letter-spacing:2px;margin-bottom:8px;}
.sub{font-size:12px;color:rgba(255,255,255,0.4);line-height:1.8;margin-bottom:22px;}
.task-btn{display:block;width:100%;padding:18px 24px;border:none;border-radius:14px;font-family:'Orbitron',sans-serif;font-size:14px;font-weight:900;letter-spacing:2px;cursor:pointer;background:linear-gradient(135deg,var(--cyan),var(--pink),var(--purple));background-size:200% 200%;color:#fff;animation:gradShift 3s ease infinite;transition:transform 0.2s,box-shadow 0.2s;text-decoration:none;margin-bottom:10px;}
.task-btn:hover{transform:translateY(-2px);box-shadow:0 10px 32px rgba(0,245,255,0.35);}
@keyframes gradShift{0%{background-position:0% 50%}50%{background-position:100% 50%}100%{background-position:0% 50%}}
.redirect-note{font-size:11px;color:rgba(255,255,255,0.25);margin-bottom:20px;display:flex;align-items:center;justify-content:center;gap:6px;}
.arrow{font-size:18px;animation:arrowPulse 1.5s ease-in-out infinite;}
@keyframes arrowPulse{0%,100%{opacity:0.3;transform:translateX(0)}50%{opacity:1;transform:translateX(4px)}}
.divider{height:1px;background:linear-gradient(90deg,transparent,var(--border),transparent);margin:20px 0;}
.key-box{background:rgba(0,255,136,0.06);border:1px solid rgba(0,255,136,0.25);border-radius:10px;padding:14px 16px;font-size:15px;color:var(--green);word-break:break-all;font-weight:700;cursor:pointer;margin-bottom:8px;transition:background 0.2s;text-align:left;}
.key-box:hover{background:rgba(0,255,136,0.12);}
.expiry{font-size:11px;color:rgba(255,255,255,0.3);margin-bottom:16px;}
.copy-btn{display:inline-flex;align-items:center;gap:8px;padding:12px 28px;border-radius:10px;font-family:'Orbitron',sans-serif;font-size:12px;font-weight:700;letter-spacing:1px;cursor:pointer;border:none;background:linear-gradient(135deg,var(--green),var(--cyan));color:#000;transition:transform 0.2s;}
.copy-btn:hover{transform:translateY(-1px);}
.err-title{font-family:'Orbitron',sans-serif;font-size:16px;color:var(--red);margin-bottom:10px;letter-spacing:2px;}
.back-btn{display:inline-flex;align-items:center;gap:8px;padding:12px 24px;border-radius:10px;font-family:'Orbitron',sans-serif;font-size:11px;font-weight:700;letter-spacing:1px;cursor:pointer;border:none;background:rgba(255,68,85,0.12);border:1px solid rgba(255,68,85,0.25);color:var(--red);text-decoration:none;margin-top:12px;}
.captcha-wrap{margin:14px 0;display:flex;justify-content:center;}
.gen-btn{display:inline-flex;align-items:center;gap:8px;padding:14px 28px;border-radius:12px;font-family:'Orbitron',sans-serif;font-size:12px;font-weight:700;letter-spacing:2px;cursor:pointer;border:none;background:linear-gradient(135deg,var(--green),var(--cyan));color:#000;margin-top:6px;transition:transform 0.2s;}
.gen-btn:hover{transform:translateY(-1px);}
.gen-btn:disabled{opacity:0.4;cursor:not-allowed;animation:none;}
.msg{font-size:12px;margin-top:10px;min-height:18px;}
</style>
</head>
<body>
<div class="orb orb1"></div><div class="orb orb2"></div>
<div class="wrap">
  <div class="brand">🛡️ ObfuscatorHub</div>
  <div class="card">${content}</div>
</div>
<script>
function copyKey(k){navigator.clipboard.writeText(k).then(()=>{const b=document.getElementById("copyBtn");if(b){b.textContent="✅ Copied!";setTimeout(()=>{b.textContent="📋 Copy Key";},1800);}});}
</script>
${extraScripts || ""}
</body></html>`;
}

function renderCheckpointError(msg) {
  return _cpBase(`
    <div class="icon" style="animation:none;filter:drop-shadow(0 0 8px var(--red));">⛔</div>
    <div class="err-title">Checkpoint Failed</div>
    <p class="sub">${escapeHtml(msg)}</p>
    <a href="javascript:history.back()" class="back-btn">← Go Back</a>
  `);
}

function renderCheckpointTask(scriptId, providerName, providerLink, isFree) {
  let safeProviderLink;
  if (!isFree) {
    try {
      const url = new URL(providerLink);
      if (url.protocol !== "https:") {
        throw new Error("Invalid provider URL");
      }
      safeProviderLink = url.href;
    } catch {
      throw new Error("Invalid provider URL");
    }
  }

  if (isFree) {
    const freeScripts = `<script src="https://js.hcaptcha.com/1/api.js" async defer></script>
      <script>
      let _captchaToken=null;
      function onCaptchaDone(t){_captchaToken=t;const b=document.getElementById('genBtn');if(b)b.disabled=false;}
      async function doGenerate(){
        const b=document.getElementById('genBtn'),m=document.getElementById('genMsg');
        if(!_captchaToken){m.style.color='var(--red)';m.textContent='Complete the captcha first.';return;}
        b.disabled=true;b.textContent='⏳ Generating...';
        try{
          const r=await fetch('/checkpoint/${scriptId}/free-generate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({captcha:_captchaToken})});
          const d=await r.json();
          if(d.ok){
            m.style.color='var(--green)';
            m.textContent='✅ Verified! Redirecting to your key...';
            window.location='/checkpoint/${scriptId}/complete?t='+d.token;
          }else{m.style.color='var(--red)';m.textContent='❌ '+(d.error||'Failed');b.disabled=false;b.textContent='🔑 Generate Key';}
        }catch(e){m.style.color='var(--red)';m.textContent='Network error.';b.disabled=false;b.textContent='🔑 Generate Key';}
      }
      </script>`;
    return _cpBase(`
      <div class="icon">🔑</div>
      <div class="title" style="background:linear-gradient(135deg,var(--cyan),var(--pink));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">Get Your Key</div>
      <p class="sub">Complete the quick captcha below and click Generate Key to get your free access key instantly.</p>
      <div class="captcha-wrap">
        <div class="h-captcha" data-sitekey="${process.env.HCAPTCHA_SITEKEY||"25bc146c-b7d0-4d3a-b18c-18c42124e022"}" data-theme="dark" data-callback="onCaptchaDone"></div>
      </div>
      <button id="genBtn" class="gen-btn" disabled onclick="doGenerate()">🔑 Generate Key</button>
      <div id="genMsg" class="msg"></div>
    `, freeScripts);
  }
  return _cpBase(`
    <div class="icon">🔑</div>
    <div class="title" style="background:linear-gradient(135deg,var(--cyan),var(--pink));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;">Key Required</div>
    <p class="sub">Complete the task below to unlock your unique access key. Everyone gets a different key — direct bypass = blocked.</p>
    <div class="redirect-note">
      <span>You'll be redirected through</span>
      <strong style="color:var(--cyan);">${escapeHtml(providerName)}</strong>
      <span class="arrow">→</span>
      <span>then get your key automatically</span>
    </div>
    <a href="${escapeHtml(safeProviderLink)}" class="task-btn">⚡ Complete Task — ${escapeHtml(providerName)}</a>
    <div class="redirect-note" style="font-size:10px;margin-bottom:0;">
      🔒 After completing the task you'll be redirected back here to receive your unique key
    </div>
  `);
}

function renderCheckpointSuccess(scriptId, key, expiryHours) {
  const expStr = expiryHours === 0 ? "Never" : (expiryHours >= 24 ? `${Math.floor(expiryHours/24)} day(s)` : `${expiryHours} hour(s)`);
  return _cpBase(`
    <div class="icon" style="animation:none;filter:drop-shadow(0 0 14px var(--green));">✅</div>
    <div class="title" style="color:var(--green);">Key Generated!</div>
    <p class="sub">Copy this key and paste it into the Roblox key prompt.<br>The timer starts when you first use it in Roblox — not now.</p>
    <div class="key-box" onclick="copyKey('${key}')" title="Click to copy">${key}</div>
    <div class="expiry">⏱ Expires <strong style="color:var(--cyan);">${expStr}</strong> after first use in Roblox &nbsp;·&nbsp; HWID-locked to your device on first use</div>
    <button id="copyBtn" class="copy-btn" onclick="copyKey('${key}')">📋 Copy Key</button>
    <div class="divider"></div>
    <p style="font-size:11px;color:rgba(255,255,255,0.2);">This key is unique to you. Sharing it will lock it to another HWID.</p>
  `);
}

app.post("/api/delete-account", async (req, res) => {
    const sid = req.cookies && req.cookies.sid;
    if (!sid || !await sessionStore.has(sid)) return res.json({ ok: false });
    const userId = await sessionStore.get(sid);
    try {
        await userdataCollection.deleteOne({ userId });

        try {
            const idxResult = await mgIndexGet();
            if (idxResult) {
                const index = idxResult.data || {};
                const newIndex = {};
                for (const [key, val] of Object.entries(index)) {
                    if (val !== userId) newIndex[key] = val;
                }
                await mgIndexPut(newIndex);
            }
        } catch(e) { console.error("index cleanup failed:", e.message); }

        let ownedScriptIds = [];
        try {
            ownedScriptIds = (await scriptsCollection.find({ owner: userId }, { projection: { id: 1 } }).toArray()).map(s => s.id);
            await scriptsCollection.updateMany(
                { owner: userId },
                { $set: { owner: null } }
            );
        } catch(e) { console.error("Script owner clear failed:", e.message); }

        try {
            if (ownedScriptIds.length) {
                await keysCollection.deleteMany({ scriptId: { $in: ownedScriptIds } });
            }
        } catch(e) { console.error("Key cleanup failed:", e.message); }
        try {
            await integrationsCol.deleteMany({ owner: userId });
        } catch(e) { console.error("Integration cleanup failed:", e.message); }

        await sessionStore.delete(sid);
        res.clearCookie("sid");
        if (mountedAuthRouter && mountedAuthRouter.invalidateUserCache) {
            mountedAuthRouter.invalidateUserCache(userId);
        }
        res.json({ ok: true });
    } catch(e) {
        console.error("delete-account error:", e.message);
        res.json({ ok: false });
    }
});

const OUTER_ANTI_TAMPER_PREFIX = `
if not game or not game.GetService or not (game.IsLoaded and game:IsLoaded()) then return end

local _origLoadstring = loadstring
local _origPcallKG     = pcall

local _kgProtectedFns = { [_origLoadstring] = true }
_kgProtectedFns[game.HttpGet] = true
_kgProtectedFns[game.HttpPost] = true
pcall(function() if syn and syn.request then _kgProtectedFns[syn.request] = true end end)
pcall(function() if request then _kgProtectedFns[request] = true end end)

if hookfunction then
  local _realHookfunctionKG = hookfunction
  hookfunction = function(fnToHook, replacement)
    if _kgProtectedFns[fnToHook] or fnToHook == loadstring then
      task.spawn(function() while true do task.wait(0) end end)
      _origPcallKG(function()
        game:GetService("Players").LocalPlayer:Kick("Anti-cheat: Do not attempt to hook loadstring.")
      end)
      return fnToHook
    end
    return _realHookfunctionKG(fnToHook, replacement)
  end
end

local function _kgCheckTamper()
  local ishookKG = isfunctionhooked or ishooked or nil
  if ishookKG then
    for fn, _ in next, _kgProtectedFns do
      local ok, hooked = _origPcallKG(ishookKG, fn)
      if ok and hooked then
        task.spawn(function() while true do task.wait(0) end end)
        _origPcallKG(function()
          game:GetService("Players").LocalPlayer:Kick("Anti-cheat: Do not attempt to hook protected functions.")
        end)
        return true
      end
    end
  end
  if restorefunction then
    task.spawn(function()
      while true do
        task.wait(0.5)
        for fn, _ in next, _kgProtectedFns do
          local ok2, hooked2 = _origPcallKG(function()
            return isfunctionhooked and isfunctionhooked(fn)
          end)
          if ok2 and hooked2 then while true do task.wait(0) end end
        end
      end
    end)
  end

  local okCoreSpy, coreSpy = pcall(function() return game:GetService("CoreGui") end)
  if okCoreSpy and coreSpy then
    local okKidsSpy, kidsSpy = pcall(function() return coreSpy:GetChildren() end)
    if okKidsSpy and kidsSpy then
      for _, childSpy in next, kidsSpy do
        local okGuiSpy, isGuiSpy = pcall(function() return childSpy:IsA("ScreenGui") end)
        if okGuiSpy and isGuiSpy then
          local nmSpy = tostring(childSpy.Name):lower()
          if nmSpy:find("httpspy", 1, true) or nmSpy:find("http spy", 1, true) or nmSpy:find("reqspy", 1, true) then
            task.spawn(function() while true do task.wait(0) end end)
            _origPcallKG(function()
              game:GetService("Players").LocalPlayer:Kick("Anti-cheat: HTTP spy GUI detected.")
            end)
            return true
          end
        end
      end
    end
  end
  return false
end

if _kgCheckTamper() then return end
`;

function isExecutorUA(ua) {
    return typeof ua === "string" && /roblox|delta|arceus|real|xeno|solora|madium|volt|thunder|wave|synapse|krnl|fluxus|codex|electron|hydrogen|seliware|velocity|swift|oxygen|valex|cryptic|ronix|potassium|bunni|argon|trigon|wininet/i.test(ua);
}
function luaNotice(msg) {
    return 'warn("' + String(msg).replace(/[\\"\r\n]/g, " ") + '")';
}

const FormData = require("form-data");

function assertUsableLua(code, who) {
    if (typeof code !== "string" || !code.trim()) throw new Error(who + " returned empty output");
    if (code.charCodeAt(0) === 27 || code.startsWith("\u001bLua")) throw new Error(who + " returned bytecode");
}

const LEAKD_API_URL = "https://leakd.up.railway.app/obfuscate";
const LEAKD_PRESET = "RobloxExecutor";

const FALLBACK_API_URL = "https://oofuscator-4war8nr8.manus.space/api/obfuscate";
const FALLBACK_SETTINGS = {
    encryptStrings: true,
    proxifyLocals: true,
    proxifyFunctions: true,
    antiTamper: true,
    antiHook: true,
    controlFlowFlattening: true,
    isLuauRuntime: true,
    loaderVMDepth: 4
};

async function obfuscateWithLeakD(source) {
    const form = new FormData();
    form.append("file", Buffer.from(source, "utf8"), {
        filename: "script.lua",
        contentType: "text/plain"
    });

    const resp = await axios.post(LEAKD_API_URL, form, {
        params: { preset: LEAKD_PRESET },
        headers: form.getHeaders(),
        timeout: 30000,
        maxBodyLength: Infinity,
        maxContentLength: Infinity
    });

    const data = resp.data;
    if (!data?.success || typeof data?.obfuscated_code !== "string" || !data.obfuscated_code) {
        throw new Error("LeakD returned non-success: " + JSON.stringify(data).slice(0, 200));
    }

    const lines = data.obfuscated_code.split("\n");
    let skip = 0;
    while (skip < 2 && skip < lines.length && /^\s*--/.test(lines[skip])) skip++;
    const out = lines.slice(skip).join("\n");
    assertUsableLua(out, "LeakD");
    return out;
}

async function obfuscateWithFallback(source) {
    const resp = await axios.post(
        FALLBACK_API_URL,
        { source, settings: FALLBACK_SETTINGS },
        { timeout: 30000 }
    );

    const data = resp.data;
    if (!data?.success || typeof data?.output !== "string" || !data.output) {
        throw new Error("Fallback API returned non-success: " + JSON.stringify(data).slice(0, 200));
    }

    assertUsableLua(data.output, "Fallback");
    return data.output;
}

const PROMETHEUS_SERVERS = [
    "https://proth-production-7b7e.up.railway.app/api/obfuscate",
    "https://proth-production-3b4c.up.railway.app/api/obfuscate",
    "https://proth-production.up.railway.app/api/obfuscate",
    "https://proth-production-b8b6.up.railway.app/api/obfuscate"
];
const PROMETHEUS_PRESET = "Ultra";
let prometheusIndex = 0; // rotates after each success so load is spread across the servers

// Picks a different starting server each call (round robin), so the 4 servers
// get roughly equal load over time. Instead of trying them one-by-one and
// waiting out each server's full timeout before moving on (which is what made
// this take 20+ seconds when the first pick was slow or down), it fires the
// starting server immediately and, if it hasn't answered within STAGGER_MS,
// fires the next one too — in parallel, not instead of it. Whichever answers
// first wins and the rest are aborted, so a slow/dead server costs at most
// one stagger window instead of its whole timeout.
async function obfuscateWithPrometheus(source) {
    const start = prometheusIndex;
    const order = PROMETHEUS_SERVERS.map((_, i) => (start + i) % PROMETHEUS_SERVERS.length);
    prometheusIndex = (start + 1) % PROMETHEUS_SERVERS.length; // next call starts on the next server either way

    const STAGGER_MS = 1500;     // how long one server gets to answer alone before the next is also fired
    const PER_TRY_TIMEOUT = 12000;

    const controllers = [];
    const timers = [];
    let settled = false;
    function cleanup() {
        settled = true;
        timers.forEach(t => clearTimeout(t));
        controllers.forEach(c => c.abort());
    }

    function attempt(idx) {
        const controller = new AbortController();
        controllers.push(controller);
        return axios.post(
            PROMETHEUS_SERVERS[idx],
            { code: source, preset: PROMETHEUS_PRESET },
            { timeout: PER_TRY_TIMEOUT, maxBodyLength: Infinity, maxContentLength: Infinity, signal: controller.signal }
        ).then(resp => {
            const d = resp.data || {};
            const out = d.code || d.result || d.obfuscated || d.output;
            if (typeof out !== "string" || !out) throw new Error("empty response");
            assertUsableLua(out, "Prometheus");
            return out;
        }).catch(err => {
            if (!settled) console.error(`Prometheus server ${idx} failed:`, err.message);
            throw err;
        });
    }

    const tries = order.map((idx, i) => {
        if (i === 0) return attempt(idx);
        return new Promise((resolve, reject) => {
            const t = setTimeout(() => attempt(idx).then(resolve, reject), i * STAGGER_MS);
            timers.push(t);
        });
    });

    try {
        const out = await Promise.any(tries);
        cleanup();
        return out;
    } catch (aggErr) {
        cleanup();
        const msg = aggErr && aggErr.errors ? aggErr.errors.map(e => e.message).join("; ") : (aggErr && aggErr.message);
        throw new Error("All Prometheus servers failed: " + msg);
    }
}

async function newObfuscate(source) {
    try {
        const out = await obfuscateWithPrometheus(source);
        console.log("Prometheus obfuscator succeeded.");
        return out;
    } catch (err) {
        console.error("Prometheus obfuscator failed, trying fallback:", err.message);
    }

    try {
        const out = await obfuscateWithFallback(source);
        console.log("Fallback obfuscator succeeded.");
        return out;
    } catch (err) {
        console.error("Fallback obfuscator also failed:", err.message);
        return null; // caller falls back to plain code
    }
}

function buildRawShell(host, execId, token) {
    return String.raw`if not game or not game.GetService or not(game.IsLoaded and game:IsLoaded())then return end;local a,b,c=game,pcall,loadstring;local d=(getgenv and getgenv())or _G;if d.__kg_lock then return end;d.__kg_lock=true;local e;local function f(c)if not e then e=true;print("detected: "..tostring(c))if not b(function()a:Shutdown()end)then b(function()a.Players.LocalPlayer:Kick("Anti-cheat: "..tostring(c))end)end end;return true end;local function g(a,...)a=tostring(a):lower()for b,b in ipairs({...})do if a:find(b,1,true)then return true end end end;local function h(a,...)local a,b=b(a,...)if a then return end;b=tostring(b)return b:find("%.lua:%d+")~=nil or b:find('%[string "')~=nil end;local function i()local a={}if listfiles then for c,c in ipairs({"","."})do local b,c=b(listfiles,c)if b and type(c)=="table"then for b,b in ipairs(c)do a[tostring(b):lower()]=true end end end end;return a end;local j=i()local function k()local a={}for b in next,i()do if not j[b]then a[#a+1]=b end end;return a end;local i={function()return loadstring end,function()return a.HttpGet end,function()return a.HttpGetAsync end,function()return a.HttpPost end,function()return a.HttpPostAsync end,function()return request end,function()return http_request end,function()return syn and syn.request end,function()return http and http.request end,function()return fluxus and fluxus.request end,function()return WebSocket and WebSocket.connect end}local j,l={},{}for a,c in ipairs(i)do local b,c=b(c)if b and type(c)=="function"then j[c]=true;l[a]=c end end;local function m(a)return function(b,c)if j[b]then f("hook attempt")return b end;return a(b,c)end end;local n={}if hookfunction then n.hookfunction=m(hookfunction)end;if replaceclosure then n.replaceclosure=m(replaceclosure)end;if hookmetamethod then local a=hookmetamethod;n.hookmetamethod=function(b,c,d)if typeof(b)=="Instance"and(c=="__namecall"or c=="__index")then f("metamethod hook")return function()end end;return a(b,c,d)end end;for a,c in pairs(n)do b(function()_G[a]=c;d[a]=c end)end;local g={function()if loadstring~=c or(iscclosure and not iscclosure(loadstring))or(islclosure and islclosure(loadstring))then return"loadstring"end;if debug and debug.info then local a,b=b(debug.info,loadstring,"s")if a and b and b~="[C]"then return"loadstring src"end end end,function()for a,b in pairs(n)do if d[a]~=b then return"guard replaced: "..a end end end,function()for a,c in ipairs(i)do if l[a]then local b,c=b(c)if b and c~=l[a]then return"fn replaced"end end end;local a=isfunctionhooked or ishooked;if a then for c in next,j do local a,b=b(a,c)if a and b then return"hooked fn"end end end end,function()local b,c,d=l[2],l[6],l[7];if(b and h(b,a,nil))or(c and h(c,nil))or(d and h(d,nil))then return"error leak"end end,function()if not getrawmetatable then return end;local a,c=b(getrawmetatable,a)if not a or type(c)~="table"then return end;local a=isexecutorclosure or checkclosure or is_synapse_function;for d,d in ipairs({"__namecall","__index"})do local c=c[d];if type(c)=="function"then if islclosure and islclosure(c)then return d end;if a then local a,b=b(a,c)if a and b then return d end end end end end,function()local a=d.Config;if type(a)=="table"then for b,b in ipairs({"FormatUrls","SetUrlsToClipboard","SaveOutputToFile","SkipDefaultHeaders","DefaultHeaders"})do if a[b]~=nil then return"spy config"end end end end,function()for a,a in ipairs(k())do if a:match("http_%x+%.log$")or a:match("loadstring%d+%.txt$")or g(a,"intercepted","payload","dumped","captured")then return"new file"end end end}local function h()for a,a in ipairs(g)do local a,b=b(a)if a and b then return f(b)end end;return e end;local e={("PTTH detpecretnI"):reverse(),("yps PTTH"):reverse(),("daolyap_detpecretni"):reverse(),("yllufsseccus devas edoc detcetorP"):reverse()}local function g()local a=(debug and debug.getconstants)or getconstants;if not getgc or not a then return end;local c,d=b(getgc,true)if not c or type(d)~="table"then return end;for c,d in ipairs(d)do if c%4000==0 then task.wait()end;local c=type(d)if c=="function"then if not(iscclosure and iscclosure(d))then local a,b=b(a,d)if a and type(b)=="table"then for a,a in pairs(b)do if type(a)=="string"then for b,b in ipairs(e)do if a:find(b,1,true)then return"memory"end end end end end end elseif c=="table"then if rawget(d,"SetUrlsToClipboard")~=nil or rawget(d,"SkipDefaultHeaders")~=nil then return"memory"end end end end;local function e(a)if not isfile then return end;local c=("_daolyap_detpecretni"):reverse()for a=a-2,a+20 do local a,d=b(os.date,"%Y%m%d_%H%M%S",a)if a then local a,b=b(isfile,c..d..".lua")if a and b then return true end end end end;local function i()local a="kg"..math.random(1e8,9e8)..math.random(1e8,9e8)local d=os.time()local a=c("local a='"..a.."' return a")if a then b(a)end;task.wait(.6)return e(d)and"decoy dump"or#k()>0 and"decoy file"end;local function e(a)if h()then return end;local e;local g={}for a,b in pairs(d)do if type(b)=="function"and b~=c then g[a]=b;d[a]=function(...)e=e or a;return b(...)end end end;local a,b,c=b(c,a)for a,b in pairs(g)do d[a]=b end;if e then f("loadstring side effect: "..e)return end;if not a then error(tostring(b))end;if not b then error(tostring(c))end;if h()then return end;return b end;local function c()if h()then return end;local c=g()if c then f(c)return end;local c=i()if c then f(c)return end;if h()then return end;local c="${token}";local a,b=b(a.HttpGet,a,"https://${host}/raw/${execId}?t="..c)if not a or type(b)~="string"or b==""then error("[raw] returned no valid code")end;local a=e(b)if a then return a()end end;local a,b=b(c)d.__kg_lock=nil;if not a then error(tostring(b))end;return b`;
}

function buildAntiHookShell(host, genvKey, execId2, token2) {
    return `
        if not game or not game.GetService or not (game.IsLoaded and game:IsLoaded()) then return end

        local _origLoadstring = loadstring

        if hookfunction then
            local _realHookfunction = hookfunction
            hookfunction = function(fnToHook, replacement)
                if fnToHook == _origLoadstring or fnToHook == loadstring then

                    task.spawn(function() while true do task.wait(0) end end)
                    pcall(function()
                        game:GetService("Players").LocalPlayer:Kick(
                            "Anti-cheat: Do not attempt to hook loadstring/HttpGet."
                        )
                    end)
                    return fnToHook
                end
                return _realHookfunction(fnToHook, replacement)
            end
        end

        local _origPrint        = print
        local _origWarn         = warn
        local _origRequire      = require
        local _origError        = error
        local _origPcall        = pcall
        local _origXpcall       = xpcall
        local _origTostring     = tostring
        local _origType         = type
        local _origRawget       = rawget
        local _origRawset       = rawset
        local _origSetmetatable = setmetatable
        local _origGetmetatable = getmetatable

        local _protectedFns = {}

        local function _registerProtected(fn)
            _protectedFns[fn] = true
        end

        _registerProtected(_origLoadstring)
        _registerProtected(game.HttpGet)
        _registerProtected(game.HttpPost)
        pcall(function() if syn and syn.request then _registerProtected(syn.request) end end)
        pcall(function() if request then _registerProtected(request) end end)

        local function _checkTamper()
            local ishook = isfunctionhooked or ishooked or nil
            if ishook then
                for fn, _ in next, _protectedFns do
                    local ok, hooked = _origPcall(ishook, fn)
                    if ok and hooked then

                        task.spawn(function()
                            while true do task.wait(0) end
                        end)
                        _origPcall(function()
                            game:GetService("Players").LocalPlayer:Kick(
                                "Anti-cheat: Do not attempt to hook protected functions."
                            )
                        end)
                        return true
                    end
                end
            end

            local restore = restorefunction or nil
            if restore then
                task.spawn(function()
                    while true do
                        task.wait(0.5)
                        for fn, _ in next, _protectedFns do
                            local ok2, hooked2 = _origPcall(function()
                                return isfunctionhooked and isfunctionhooked(fn)
                            end)
                            if ok2 and hooked2 then
                                while true do task.wait(0) end
                            end
                        end
                    end
                end)
            end

            local okCoreSpy, coreSpy = pcall(function() return game:GetService("CoreGui") end)
            if okCoreSpy and coreSpy then
                local okKidsSpy, kidsSpy = pcall(function() return coreSpy:GetChildren() end)
                if okKidsSpy and kidsSpy then
                    for _, childSpy in next, kidsSpy do
                        local okGuiSpy, isGuiSpy = pcall(function() return childSpy:IsA("ScreenGui") end)
                        if okGuiSpy and isGuiSpy then
                            local nmSpy = tostring(childSpy.Name):lower()
                            if nmSpy:find("httpspy", 1, true) or nmSpy:find("http spy", 1, true) or nmSpy:find("reqspy", 1, true) then
                                task.spawn(function() while true do task.wait(0) end end)
                                _origPcall(function()
                                    game:GetService("Players").LocalPlayer:Kick("Anti-cheat: HTTP spy GUI detected.")
                                end)
                                return true
                            end
                        end
                    end
                end
            end
            return false
        end

        local _origIpairs = ipairs
        local _printGuard = function(...)
            local args = {...}
            for _, v in _origIpairs(args) do
                if _origType(v) == "string" then
                    if string.find(v, "loadstring", 1, true) and string.find(v, "HttpGet", 1, true) then

                        task.spawn(function() while true do task.wait(0) end end)
                        _origPcall(function()
                            game:GetService("Players").LocalPlayer:Kick("Anti-cheat: loadstring dump detected.")
                        end)
                        return
                    end
                end
            end
            return _origPrint(...)
        end
        _registerProtected(_printGuard)

        print = _printGuard

        local _hasGenv, _genv = pcall(getgenv)
        if _hasGenv and _genv then
            _genv._OBFHUB_LOADED = _genv._OBFHUB_LOADED or {}
            local _runCount = (_genv._OBFHUB_LOADED["${genvKey}"] or 0) + 1
            if _runCount > 2 then
                warn("Script already running.")
                return
            end
            _genv._OBFHUB_LOADED["${genvKey}"] = _runCount
        end

        if _checkTamper() then return end

        local _url2 = "https://${host}/raw2/${execId2}?t=${token2}"
        local _fetchOk, _src2 = _origPcall(game.HttpGet, game, _url2)
        if not _fetchOk or not _src2 or _src2 == "" then
            error("Failed to load protected script body. Server returned: " .. tostring(_src2))
        end

        local _fn2, _err2 = loadstring(_src2)
        if not _fn2 then
            error("Script body load error: " .. tostring(_err2))
        end

        print        = _origPrint
        warn         = _origWarn
        require      = _origRequire
        error        = _origError
        pcall        = _origPcall
        xpcall       = _origXpcall
        tostring     = _origTostring
        type         = _origType
        rawget       = _origRawget
        rawset       = _origRawset
        setmetatable = _origSetmetatable
        getmetatable = _origGetmetatable

        _fn2()`;
}

app.get("/raw/:execId", async (req, res) => {
    const exec = await execStore.get(req.params.execId);
    if (!exec) return res.status(200).type("text/plain").send("-- expired: get a new key/link and try again");

    const queryToken = req.query.t;
    if (!queryToken || queryToken !== exec.token) return res.status(200).type("text/plain").send("-- invalid token");

    const ua = req.headers["user-agent"] || "";
    console.log(`[raw] execId=${req.params.execId} incoming User-Agent: "${ua}"`);
    if (!isExecutorUA(ua)) {
    return res.status(200).type("text/plain").send("-- Request denied (UA)");
    }

    await execStore.delete(req.params.execId);

    res.setHeader("Cache-Control", "no-store");
    res.type("text/plain").send(exec.code);
});

app.get("/raw2/:execId2", async (req, res) => {
    const exec = await execStore.get(req.params.execId2);
    if (!exec) return res.status(200).type("text/plain").send("-- expired: get a new key/link and try again");

    const queryToken = req.query.t;
    if (!queryToken || queryToken !== exec.token) return res.status(200).type("text/plain").send("-- invalid token");

    const ua = req.headers["user-agent"] || "";
    if (!isExecutorUA(ua)) {
    return res.status(200).type("text/plain").send("-- Request denied (UA)");
    }

    await execStore.delete(req.params.execId2);

    res.setHeader("Cache-Control", "no-store");
    res.type("text/plain").send(exec.code);
});

app.get("/term",        (req, res) => { res.setHeader("Cache-Control", "public, max-age=3600"); res.sendFile(path.join(__dirname, "public/term.html")); });
app.get("/policy",      (req, res) => { res.setHeader("Cache-Control", "public, max-age=3600"); res.sendFile(path.join(__dirname, "public/policy.html")); });
app.get("/migrate-page",(req, res) => { res.setHeader("Cache-Control", "public, max-age=3600"); res.sendFile(path.join(__dirname, "public/migrate.html")); });

async function adminMigrateTemp(req, res) {

    const original = await tempCollection.find().toArray();
    res.setHeader("Content-Type", "text/plain");
    res.setHeader("Transfer-Encoding", "chunked");
    res.write(`Starting migration of ${original.length} temp scripts to Rubis...\n`);

    let migrated = 0, skipped = 0, failed = 0;

    for (const s of original) {
        const existing = await scriptsCollection.findOne({ id: s.id });
        if (existing && (existing.scrapID || existing.fileName)) {
            skipped++;
            res.write(JSON.stringify({ id: s.id, status: "skipped" }) + "\n");
            continue;
        }
        if (!s.code) {
            failed++;
            res.write(JSON.stringify({ id: s.id, status: "failed", error: "no code" }) + "\n");
            continue;
        }
        if (scriptTooLargeForRubis(s.code)) {
            failed++;
            res.write(JSON.stringify({ id: s.id, status: "failed", error: "script exceeds Rubis 3MB limit" }) + "\n");
            continue;
        }
        try {
            const { scrapID, ownerKey } = await rubisUpload(s.code);
            await scriptsCollection.updateOne(
                { id: s.id },
                { $set: {
                    id: s.id,
                    password: s.password,
                    scrapID,
                    scrapOwnerKey: ownerKey,
                    tokens: s.tokens || [generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken()],
                    lastToken: s.lastToken || "",
                    owner: s.owner || null,
                    createdAt: s.createdAt || new Date()
                }},
                { upsert: true }
            );
            await tempCollection.deleteOne({ id: s.id });
            migrated++;
            res.write(JSON.stringify({ id: s.id, status: "migrated", scrapID }) + "\n");
            await new Promise(r => setTimeout(r, 250)); // stay well under Rubis 10 req/s
        } catch(e) {
            failed++;
            res.write(JSON.stringify({ id: s.id, status: "failed", error: e.message }) + "\n");
            await new Promise(r => setTimeout(r, 500));
        }
    }
    res.write(`\nDone. Migrated: ${migrated}, Skipped: ${skipped}, Failed: ${failed}\n`);
    res.end();
}

function buildKeyGateLua(host, scriptId, getKeyUrl) {
  return `
if not game or not game.GetService or not (game.IsLoaded and game:IsLoaded()) then return end

local _origLoadstring = loadstring
local _origPcallKG     = pcall

local _kgProtectedFns = { [_origLoadstring] = true }

if hookfunction then
  local _realHookfunctionKG = hookfunction
  hookfunction = function(fnToHook, replacement)
    if _kgProtectedFns[fnToHook] or fnToHook == loadstring then
      task.spawn(function() while true do task.wait(0) end end)
      _origPcallKG(function()
        game:GetService("Players").LocalPlayer:Kick("Anti-cheat: Do not attempt to hook loadstring.")
      end)
      return fnToHook
    end
    return _realHookfunctionKG(fnToHook, replacement)
  end
end

local function _kgCheckTamper()
  local ishookKG = isfunctionhooked or ishooked or nil
  if ishookKG then
    for fn, _ in next, _kgProtectedFns do
      local ok, hooked = _origPcallKG(ishookKG, fn)
      if ok and hooked then
        task.spawn(function() while true do task.wait(0) end end)
        _origPcallKG(function()
          game:GetService("Players").LocalPlayer:Kick("Anti-cheat: Do not attempt to hook protected functions.")
        end)
        return true
      end
    end
  end
  if restorefunction then
    task.spawn(function()
      while true do
        task.wait(0.5)
        for fn, _ in next, _kgProtectedFns do
          local ok2, hooked2 = _origPcallKG(function()
            return isfunctionhooked and isfunctionhooked(fn)
          end)
          if ok2 and hooked2 then while true do task.wait(0) end end
        end
      end
    end)
  end
  return false
end

if _kgCheckTamper() then return end

local HOST      = "https://${host}"
local SCRIPT_ID = "${scriptId}"
local KEY_LINK  = "${getKeyUrl}"
local EXEC_ID, TOKEN = nil, nil

local HttpService       = game:GetService("HttpService")
local Players           = game:GetService("Players")
local TweenService      = game:GetService("TweenService")
local UserInputService  = game:GetService("UserInputService")
local LocalPlayer       = Players.LocalPlayer

local ok, result = pcall(function()
  return game:GetService("RbxAnalyticsService"):GetClientId()
end)

if not ok or not result or result == "" then
  error("Unable to obtain device HWID")
end

local HWID = result

local AUTO_FN = nil
do
  pcall(function()
    local earlyExecutorName = (getexecutorname and getexecutorname()) or "Unknown"
    local checkBody = HttpService:JSONEncode({
      scriptId = SCRIPT_ID,
      hwid     = HWID,
      executor = earlyExecutorName
    })

    local reqOk, rawBody = false, nil

    if http and http.request then
      local ok, result = pcall(function()
        return http.request({
          Url = HOST .. "/api/check-hwid", Method = "POST",
          Headers = { ["Content-Type"] = "application/json" }, Body = checkBody,
        })
      end)
      if ok and result and result.Body then reqOk, rawBody = true, result.Body end
    end

    if not reqOk and request and type(request) == "function" then
      local ok, result = pcall(function()
        return request({
          Url = HOST .. "/api/check-hwid", Method = "POST",
          Headers = { ["Content-Type"] = "application/json" }, Body = checkBody,
        })
      end)
      if ok and result and result.Body then reqOk, rawBody = true, result.Body end
    end

    if not reqOk then
      local ok, result = pcall(function()
        return HttpService:RequestAsync({
          Url = HOST .. "/api/check-hwid", Method = "POST",
          Headers = { ["Content-Type"] = "application/json" }, Body = checkBody,
        })
      end)
      if ok and result and result.Body then reqOk, rawBody = true, result.Body end
    end

    if not reqOk then
      local ok, result = pcall(function()
        return HttpService:PostAsync(HOST .. "/api/check-hwid", checkBody, Enum.HttpContentType.ApplicationJson)
      end)
      if ok and result then reqOk, rawBody = true, result end
    end

    if not reqOk or not rawBody then return end

    local decoded
    local dok = pcall(function() decoded = HttpService:JSONDecode(rawBody) end)
    if not dok or not decoded or not decoded.authorized or not decoded.execId or not decoded.token then return end

    local runUrl = HOST .. "/raw/" .. decoded.execId .. "?t=" .. decoded.token
    local code = nil

    local function extractBody(result)
      if type(result) == "string" then return result end
      if type(result) == "table" then return result.Body or result.body end
      return nil
    end

    if type(http) == "table" and type(http.request) == "function" then
      local ok, result = pcall(function() return http.request({ Url = runUrl, Method = "GET" }) end)
      if ok and result then local b = extractBody(result); if b and b ~= "" then code = b end end
    end
    if not code and request and type(request) == "function" then
      local ok, result = pcall(function() return request({ Url = runUrl, Method = "GET" }) end)
      if ok and result then local b = extractBody(result); if b and b ~= "" then code = b end end
    end
    if not code then
      local ok, result = pcall(function() return HttpService:RequestAsync({ Url = runUrl, Method = "GET" }) end)
      if ok and result then local b = extractBody(result); if b and b ~= "" then code = b end end
    end

    if not code or (code:match("^%-%- expired") or code:match("^%-%- invalid token") or code:match("^%-%- Request denied")) then return end

    local fn = loadstring(code)
    if fn then AUTO_FN = fn end
  end)
end

if AUTO_FN then
  AUTO_FN()
  return
end

local C = {
    bg      = Color3.fromRGB(5,   5,   8),
    card    = Color3.fromRGB(13,  13,  20),
    cyan    = Color3.fromRGB(0,   245, 255),
    pink    = Color3.fromRGB(255, 45,  120),
    purple  = Color3.fromRGB(124, 58,  237),
    green   = Color3.fromRGB(0,   255, 136),
    red     = Color3.fromRGB(255, 68,  85),
    text    = Color3.fromRGB(224, 232, 255),
    muted   = Color3.fromRGB(80,  90,  130),
    border  = Color3.fromRGB(0,   60,  65),
    white   = Color3.fromRGB(255, 255, 255),
    gold    = Color3.fromRGB(255, 200, 60),
    dark    = Color3.fromRGB(18,  18,  28),
}

local submitCooldown = false
local MAX_ATTEMPTS    = 5
local attemptCount    = 0

local PlayerGui = LocalPlayer:WaitForChild("PlayerGui")
if PlayerGui:FindFirstChild("ObfHubKeySystem") then
    PlayerGui.ObfHubKeySystem:Destroy()
end

local ScreenGui = Instance.new("ScreenGui")
ScreenGui.Name            = "ObfHubKeySystem"
ScreenGui.ResetOnSpawn    = false
ScreenGui.ZIndexBehavior  = Enum.ZIndexBehavior.Sibling
ScreenGui.IgnoreGuiInset  = true
ScreenGui.DisplayOrder    = 999
ScreenGui.Parent          = PlayerGui

local BASE_W, BASE_H = 1280, 720

local function vp()
    local cam = workspace.CurrentCamera
    if not cam then return Vector2.new(1280, 720) end
    return cam.ViewportSize
end

local CARD_W_FRAC = 0.42
local CARD_H_FRAC = 0.78

local UIScale = Instance.new("UIScale")
UIScale.Parent = ScreenGui

local function scaleAll()
    local s   = vp()
    local scl = math.clamp(math.min(s.X / BASE_W, s.Y / BASE_H), 0.45, 1.6)
    UIScale.Scale = scl
end

if workspace.CurrentCamera then
    workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"):Connect(scaleAll)
end
workspace:GetPropertyChangedSignal("CurrentCamera"):Connect(function()
    scaleAll()
    if workspace.CurrentCamera then
        workspace.CurrentCamera:GetPropertyChangedSignal("ViewportSize"):Connect(scaleAll)
    end
end)
ScreenGui:GetPropertyChangedSignal("AbsoluteSize"):Connect(scaleAll)
scaleAll()

local BG = Instance.new("Frame")
BG.Size             = UDim2.fromScale(1, 1)
BG.BackgroundColor3 = C.bg
BG.BorderSizePixel  = 0
BG.ZIndex           = 0
BG.Parent           = ScreenGui

for i = 1, 14 do
    local vl = Instance.new("Frame")
    vl.Size, vl.Position  = UDim2.new(0, 1, 1, 0), UDim2.fromScale(i / 15, 0)
    vl.BackgroundColor3   = C.cyan
    vl.BackgroundTransparency = 0.96
    vl.BorderSizePixel    = 0
    vl.ZIndex             = 1
    vl.Parent             = BG
end
for i = 1, 9 do
    local hl = Instance.new("Frame")
    hl.Size, hl.Position  = UDim2.new(1, 0, 0, 1), UDim2.fromScale(0, i / 10)
    hl.BackgroundColor3   = C.cyan
    hl.BackgroundTransparency = 0.96
    hl.BorderSizePixel    = 0
    hl.ZIndex             = 1
    hl.Parent             = BG
end

local function spawnParticle()
    local dot = Instance.new("Frame")
    dot.Size             = UDim2.fromOffset(3, 3)
    dot.BackgroundColor3 = math.random(2) == 1 and C.cyan or C.purple
    dot.BackgroundTransparency = 0.4
    dot.BorderSizePixel  = 0
    dot.ZIndex           = 3
    dot.Position         = UDim2.fromScale(math.random(), 1.05)
    dot.Parent           = BG
    Instance.new("UICorner", dot).CornerRadius = UDim.new(1, 0)
    TweenService:Create(dot, TweenInfo.new(math.random(6, 10), Enum.EasingStyle.Linear), {
        Position = UDim2.fromScale(math.random() * 0.5 + 0.25, -0.05),
        BackgroundTransparency = 1,
    }):Play()
    task.delay(11, function() if dot.Parent then dot:Destroy() end end)
end
task.spawn(function()
    while ScreenGui.Parent do spawnParticle() task.wait(0.4) end
end)

local function makeOrb(color, sizeX, sizeY, anchorX, anchorY, posX, posY)
    local orb = Instance.new("Frame")
    orb.Size, orb.AnchorPoint  = UDim2.fromOffset(sizeX, sizeY), Vector2.new(anchorX, anchorY)
    orb.Position               = UDim2.fromScale(posX, posY)
    orb.BackgroundColor3       = color
    orb.BackgroundTransparency = 0.88
    orb.BorderSizePixel        = 0
    orb.ZIndex                 = 2
    orb.Parent                 = BG
    Instance.new("UICorner", orb).CornerRadius = UDim.new(1, 0)
    task.spawn(function()
        while orb.Parent do
            TweenService:Create(orb, TweenInfo.new(4, Enum.EasingStyle.Sine, Enum.EasingDirection.InOut), {Position = UDim2.new(posX, 20, posY, -20)}):Play()
            task.wait(4)
            TweenService:Create(orb, TweenInfo.new(4, Enum.EasingStyle.Sine, Enum.EasingDirection.InOut), {Position = UDim2.fromScale(posX, posY)}):Play()
            task.wait(4)
        end
    end)
end
makeOrb(C.cyan,   340, 340, 0,   0,   -0.05, -0.06)
makeOrb(C.pink,   260, 260, 1,   1,    1.05,  1.06)
makeOrb(C.purple, 200, 200, 0.5, 0.5,  0.66,  0.44)

local Card = Instance.new("Frame")
Card.Size             = UDim2.fromScale(CARD_W_FRAC, CARD_H_FRAC)
Card.AnchorPoint      = Vector2.new(0.5, 0.5)
Card.Position         = UDim2.fromScale(0.5, 0.5)
Card.BackgroundColor3 = C.card
Card.BorderSizePixel  = 0
Card.ZIndex           = 10
Card.Parent           = ScreenGui
Instance.new("UICorner", Card).CornerRadius = UDim.new(0, 16)

local Shadow = Instance.new("Frame")
Shadow.Size               = UDim2.new(CARD_W_FRAC, 0, CARD_H_FRAC, 0)
Shadow.AnchorPoint        = Vector2.new(0.5, 0.5)
Shadow.Position           = UDim2.new(0.5, 0, 0.5, 8)
Shadow.BackgroundColor3   = Color3.fromRGB(0, 0, 0)
Shadow.BackgroundTransparency = 0.5
Shadow.BorderSizePixel    = 0
Shadow.ZIndex             = 9
Shadow.Parent             = ScreenGui
Instance.new("UICorner", Shadow).CornerRadius = UDim.new(0, 20)

local TopBar = Instance.new("Frame")
TopBar.Size             = UDim2.new(1, 0, 0, 3)
TopBar.BackgroundColor3 = C.cyan
TopBar.BorderSizePixel  = 0
TopBar.ZIndex           = 21
TopBar.Parent           = Card
Instance.new("UICorner", TopBar).CornerRadius = UDim.new(0, 2)
task.spawn(function()
    local cols = {C.cyan, C.pink, C.purple, C.gold}
    local i = 0
    while Card.Parent do
        i = i % #cols + 1
        TweenService:Create(TopBar, TweenInfo.new(1.5, Enum.EasingStyle.Sine), {BackgroundColor3 = cols[i]}):Play()
        task.wait(1.5)
    end
end)

local function corner(ancX, ancY, posX, posY)
    local f = Instance.new("Frame")
    f.Size, f.AnchorPoint  = UDim2.fromOffset(14, 14), Vector2.new(ancX, ancY)
    f.Position             = UDim2.new(posX, ancX == 0 and 10 or -10, posY, ancY == 0 and 10 or -10)
    f.BackgroundTransparency = 1
    f.ZIndex               = 21
    f.Parent               = Card
    local function edge(sz, pos)
        local e = Instance.new("Frame")
        e.Size, e.Position     = sz, pos
        e.BackgroundColor3     = C.cyan
        e.BackgroundTransparency = 0.5
        e.BorderSizePixel      = 0
        e.ZIndex               = 21
        e.Parent               = f
    end
    if ancY == 0 then edge(UDim2.new(1,0,0,2), UDim2.fromOffset(0,0)) end
    if ancY == 1 then edge(UDim2.new(1,0,0,2), UDim2.new(0,0,1,-2)) end
    if ancX == 0 then edge(UDim2.new(0,2,1,0), UDim2.fromOffset(0,0)) end
    if ancX == 1 then edge(UDim2.new(0,2,1,0), UDim2.new(1,-2,0,0)) end
end
corner(0,0,0,0) corner(1,0,1,0) corner(0,1,0,1) corner(1,1,1,1)

local CloseButton = Instance.new("TextButton")
CloseButton.Size                   = UDim2.fromScale(0.075, 0.075)
CloseButton.AnchorPoint            = Vector2.new(1, 0)
CloseButton.Position               = UDim2.new(1, -8, 0, 8)
CloseButton.BackgroundColor3       = C.dark
CloseButton.BackgroundTransparency = 0
CloseButton.BorderSizePixel        = 0
CloseButton.Text                   = "✖️"
CloseButton.TextScaled             = true
CloseButton.Font                   = Enum.Font.GothamBold
CloseButton.ZIndex                 = 30
CloseButton.Parent                 = Card
Instance.new("UICorner", CloseButton).CornerRadius = UDim.new(1, 0)
local CloseStroke = Instance.new("UIStroke", CloseButton)
CloseStroke.Color     = C.muted
CloseStroke.Thickness = 1

CloseButton.MouseEnter:Connect(function()
    TweenService:Create(CloseButton, TweenInfo.new(0.15), {BackgroundColor3 = C.red}):Play()
    TweenService:Create(CloseStroke, TweenInfo.new(0.15), {Color = C.red}):Play()
end)
CloseButton.MouseLeave:Connect(function()
    TweenService:Create(CloseButton, TweenInfo.new(0.15), {BackgroundColor3 = C.dark}):Play()
    TweenService:Create(CloseStroke, TweenInfo.new(0.15), {Color = C.muted}):Play()
end)
CloseButton.MouseButton1Click:Connect(function()
    local fadeOut = Instance.new("Frame")
    fadeOut.Size, fadeOut.BackgroundColor3 = UDim2.fromScale(1,1), C.bg
    fadeOut.BackgroundTransparency = 1
    fadeOut.BorderSizePixel = 0
    fadeOut.ZIndex = 999
    fadeOut.Parent = ScreenGui
    TweenService:Create(fadeOut, TweenInfo.new(0.3), {BackgroundTransparency = 0}):Play()
    task.wait(0.35)
    ScreenGui:Destroy()
    warn("[ObfHubKeySystem] Execution cancelled by user.")
end)

local dragging, dragStart, startPos = false, nil, nil
Card.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1
    or input.UserInputType == Enum.UserInputType.Touch then
        dragging  = true
        dragStart = input.Position
        startPos  = Card.Position
    end
end)
Card.InputEnded:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1
    or input.UserInputType == Enum.UserInputType.Touch then
        dragging = false
    end
end)
UserInputService.InputChanged:Connect(function(input)
    if dragging and (input.UserInputType == Enum.UserInputType.MouseMovement
    or input.UserInputType == Enum.UserInputType.Touch) then
        local delta = input.Position - dragStart
        local s     = vp()
        local nx = startPos.X.Scale + delta.X / s.X
        local ny = startPos.Y.Scale + delta.Y / s.Y
        Card.Position   = UDim2.fromScale(nx, ny)
        Shadow.Position = UDim2.new(nx, 0, ny, 8)
    end
end)

local Content = Instance.new("Frame")
Content.Size, Content.BackgroundTransparency = UDim2.fromScale(1,1), 1
Content.ZIndex = 12
Content.Parent = Card

local Padding = Instance.new("UIPadding")
Padding.PaddingTop    = UDim.new(0.06, 0)
Padding.PaddingBottom = UDim.new(0.04, 0)
Padding.PaddingLeft   = UDim.new(0.08, 0)
Padding.PaddingRight  = UDim.new(0.08, 0)
Padding.Parent        = Content

local Layout = Instance.new("UIListLayout")
Layout.FillDirection       = Enum.FillDirection.Vertical
Layout.HorizontalAlignment = Enum.HorizontalAlignment.Center
Layout.VerticalAlignment   = Enum.VerticalAlignment.Top
Layout.SortOrder           = Enum.SortOrder.LayoutOrder
Layout.Padding             = UDim.new(0.015, 0)
Layout.Parent              = Content

local Lock = Instance.new("TextLabel")
Lock.Size                   = UDim2.new(1, 0, 0.11, 0)
Lock.BackgroundTransparency = 1
Lock.Text                   = "🔐"
Lock.TextScaled             = true
Lock.Font                   = Enum.Font.Gotham
Lock.TextXAlignment         = Enum.TextXAlignment.Center
Lock.ZIndex                 = 12
Lock.Parent                 = Content
local lockCon = Instance.new("UITextSizeConstraint", Lock)
lockCon.MinTextSize, lockCon.MaxTextSize = 18, 52
task.spawn(function()
    while Lock.Parent do
        TweenService:Create(Lock, TweenInfo.new(1, Enum.EasingStyle.Sine), {TextTransparency = 0.45}):Play() task.wait(1)
        TweenService:Create(Lock, TweenInfo.new(1, Enum.EasingStyle.Sine), {TextTransparency = 0}):Play()   task.wait(1)
    end
end)

local Title = Instance.new("TextLabel")
Title.Size                   = UDim2.new(1, 0, 0.09, 0)
Title.BackgroundTransparency = 1
Title.Text                   = "KEY SYSTEM"
Title.TextScaled             = true
Title.Font                   = Enum.Font.GothamBold
Title.TextColor3             = C.cyan
Title.TextXAlignment         = Enum.TextXAlignment.Center
Title.ZIndex                 = 12
Title.Parent                 = Content
local titleCon = Instance.new("UITextSizeConstraint", Title)
titleCon.MinTextSize, titleCon.MaxTextSize = 14, 42

local Subtitle = Instance.new("TextLabel")
Subtitle.Size                   = UDim2.new(1, 0, 0.05, 0)
Subtitle.BackgroundTransparency = 1
Subtitle.Text                   = "verify your access to continue"
Subtitle.TextScaled             = true
Subtitle.Font                   = Enum.Font.Gotham
Subtitle.TextColor3             = C.muted
Subtitle.TextXAlignment         = Enum.TextXAlignment.Center
Subtitle.ZIndex                 = 12
Subtitle.Parent                 = Content
local subCon = Instance.new("UITextSizeConstraint", Subtitle)
subCon.MinTextSize, subCon.MaxTextSize = 7, 16

local BadgeFrame = Instance.new("Frame")
BadgeFrame.Size             = UDim2.new(1, 0, 0.07, 0)
BadgeFrame.BackgroundColor3 = Color3.fromRGB(0, 22, 28)
BadgeFrame.BorderSizePixel  = 0
BadgeFrame.ZIndex           = 12
BadgeFrame.Parent           = Content
Instance.new("UICorner", BadgeFrame).CornerRadius = UDim.new(1, 0)
local BadgeStroke = Instance.new("UIStroke", BadgeFrame)
BadgeStroke.Color, BadgeStroke.Thickness = Color3.fromRGB(0, 80, 90), 1

local BadgeDot = Instance.new("Frame")
BadgeDot.Size             = UDim2.new(0, 0, 0.45, 0)
BadgeDot.SizeConstraint   = Enum.SizeConstraint.RelativeYY
BadgeDot.AnchorPoint      = Vector2.new(0, 0.5)
BadgeDot.Position         = UDim2.new(0.025, 0, 0.5, 0)
BadgeDot.BackgroundColor3 = C.green
BadgeDot.BorderSizePixel  = 0
BadgeDot.ZIndex           = 13
BadgeDot.Parent           = BadgeFrame
Instance.new("UICorner", BadgeDot).CornerRadius = UDim.new(1, 0)
task.spawn(function()
    while BadgeDot.Parent do
        TweenService:Create(BadgeDot, TweenInfo.new(0.75), {BackgroundTransparency = 0.7}):Play() task.wait(0.75)
        TweenService:Create(BadgeDot, TweenInfo.new(0.75), {BackgroundTransparency = 0}):Play()   task.wait(0.75)
    end
end)

local BadgeText = Instance.new("TextLabel")
BadgeText.Size                   = UDim2.new(0.88, 0, 1, 0)
BadgeText.Position               = UDim2.fromScale(0.1, 0)
BadgeText.BackgroundTransparency = 1
BadgeText.Text                   = "OBFUSCATORHUB  |  PROTECTED"
BadgeText.TextScaled             = true
BadgeText.Font                   = Enum.Font.GothamMedium
BadgeText.TextColor3             = C.cyan
BadgeText.TextXAlignment         = Enum.TextXAlignment.Left
BadgeText.ZIndex                 = 13
BadgeText.Parent                 = BadgeFrame
local badgeCon = Instance.new("UITextSizeConstraint", BadgeText)
badgeCon.MinTextSize, badgeCon.MaxTextSize = 6, 13

local AttemptLabel = Instance.new("TextLabel")
AttemptLabel.Size                   = UDim2.new(1, 0, 0.04, 0)
AttemptLabel.BackgroundTransparency = 1
AttemptLabel.Text                   = string.format("🛡️  attempts remaining: %d / %d", MAX_ATTEMPTS, MAX_ATTEMPTS)
AttemptLabel.TextScaled             = true
AttemptLabel.Font                   = Enum.Font.Gotham
AttemptLabel.TextColor3             = C.muted
AttemptLabel.TextXAlignment         = Enum.TextXAlignment.Right
AttemptLabel.ZIndex                 = 12
AttemptLabel.Parent                 = Content
local attCon = Instance.new("UITextSizeConstraint", AttemptLabel)
attCon.MinTextSize, attCon.MaxTextSize = 6, 12

local FieldLbl = Instance.new("TextLabel")
FieldLbl.Size                   = UDim2.new(1, 0, 0.04, 0)
FieldLbl.BackgroundTransparency = 1
FieldLbl.Text                   = "// ENTER ACCESS KEY"
FieldLbl.TextScaled             = true
FieldLbl.Font                   = Enum.Font.GothamMedium
FieldLbl.TextColor3             = C.muted
FieldLbl.TextXAlignment         = Enum.TextXAlignment.Left
FieldLbl.ZIndex                 = 12
FieldLbl.Parent                 = Content
local fldCon = Instance.new("UITextSizeConstraint", FieldLbl)
fldCon.MinTextSize, fldCon.MaxTextSize = 6, 11

local BoxFrame = Instance.new("Frame")
BoxFrame.Size             = UDim2.new(1, 0, 0.12, 0)
BoxFrame.BackgroundColor3 = Color3.fromRGB(0, 8, 12)
BoxFrame.BorderSizePixel  = 0
BoxFrame.ZIndex           = 12
BoxFrame.Parent           = Content
Instance.new("UICorner", BoxFrame).CornerRadius = UDim.new(0.25, 0)
local BoxStroke = Instance.new("UIStroke", BoxFrame)
BoxStroke.Color, BoxStroke.Thickness = C.border, 1

local KeyBox = Instance.new("TextBox")
KeyBox.Size               = UDim2.new(0.88, 0, 1, 0)
KeyBox.Position           = UDim2.fromScale(0.04, 0)
KeyBox.BackgroundTransparency = 1
KeyBox.PlaceholderText    = "paste your key here..."
KeyBox.PlaceholderColor3  = Color3.fromRGB(0, 80, 90)
KeyBox.Text               = ""
KeyBox.TextColor3         = C.green
KeyBox.TextScaled         = true
KeyBox.Font               = Enum.Font.GothamMedium
KeyBox.ClearTextOnFocus   = false
KeyBox.ZIndex             = 13
KeyBox.Parent             = BoxFrame
local keyBoxCon = Instance.new("UITextSizeConstraint", KeyBox)
keyBoxCon.MinTextSize, keyBoxCon.MaxTextSize = 8, 18

local ClearBtn = Instance.new("TextButton")
ClearBtn.Size                   = UDim2.new(0.1, 0, 0.7, 0)
ClearBtn.AnchorPoint            = Vector2.new(1, 0.5)
ClearBtn.Position               = UDim2.new(1, 0, 0.5, 0)
ClearBtn.BackgroundTransparency = 1
ClearBtn.Text                   = "🗑️"
ClearBtn.TextScaled             = true
ClearBtn.Font                   = Enum.Font.GothamBold
ClearBtn.ZIndex                 = 14
ClearBtn.Visible                = false
ClearBtn.Parent                 = BoxFrame
local clrCon = Instance.new("UITextSizeConstraint", ClearBtn)
clrCon.MinTextSize, clrCon.MaxTextSize = 8, 18

ClearBtn.MouseButton1Click:Connect(function()
    KeyBox.Text      = ""
    ClearBtn.Visible = false
end)
KeyBox:GetPropertyChangedSignal("Text"):Connect(function()
    ClearBtn.Visible = KeyBox.Text ~= ""
end)
KeyBox.Focused:Connect(function()
    TweenService:Create(BoxStroke, TweenInfo.new(0.2), {Color = C.cyan, Thickness = 1.5}):Play()
end)
KeyBox.FocusLost:Connect(function()
    TweenService:Create(BoxStroke, TweenInfo.new(0.2), {Color = C.border, Thickness = 1}):Play()
end)

local StatusLabel = Instance.new("TextLabel")
StatusLabel.Size                   = UDim2.new(1, 0, 0.05, 0)
StatusLabel.BackgroundTransparency = 1
StatusLabel.Text                   = ""
StatusLabel.TextScaled             = true
StatusLabel.Font                   = Enum.Font.GothamMedium
StatusLabel.TextColor3             = C.muted
StatusLabel.TextXAlignment         = Enum.TextXAlignment.Center
StatusLabel.ZIndex                 = 12
StatusLabel.Parent                 = Content
local stsCon = Instance.new("UITextSizeConstraint", StatusLabel)
stsCon.MinTextSize, stsCon.MaxTextSize = 7, 15

local function setStatus(msg, col)
    StatusLabel.Text      = msg or ""
    StatusLabel.TextColor3 = col or C.muted
end

local function makeBtn(text, color1, color2, heightScale)
    local f = Instance.new("Frame")
    f.Size             = UDim2.new(1, 0, heightScale or 0.11, 0)
    f.BackgroundColor3 = color1
    f.BorderSizePixel  = 0
    f.ZIndex           = 12
    f.Parent           = Content
    Instance.new("UICorner", f).CornerRadius = UDim.new(0.3, 0)

    local btn = Instance.new("TextButton")
    btn.Size                   = UDim2.fromScale(1, 1)
    btn.BackgroundTransparency = 1
    btn.Text                   = text
    btn.TextColor3             = C.white
    btn.TextScaled             = true
    btn.Font                   = Enum.Font.GothamBold
    btn.ZIndex                 = 13
    btn.Parent                 = f
    local btnCon = Instance.new("UITextSizeConstraint", btn)
    btnCon.MinTextSize, btnCon.MaxTextSize = 9, 20

    local hs = heightScale or 0.11
    btn.MouseEnter:Connect(function()
        TweenService:Create(f, TweenInfo.new(0.15), {BackgroundColor3 = color2}):Play()
    end)
    btn.MouseLeave:Connect(function()
        TweenService:Create(f, TweenInfo.new(0.15), {BackgroundColor3 = color1}):Play()
    end)
    btn.MouseButton1Down:Connect(function()
        TweenService:Create(f, TweenInfo.new(0.07), {Size = UDim2.new(0.97, 0, hs * 0.92, 0)}):Play()
    end)
    btn.MouseButton1Up:Connect(function()
        TweenService:Create(f, TweenInfo.new(0.07), {Size = UDim2.new(1, 0, hs, 0)}):Play()
    end)
    return btn, f
end

local GetBtn, _ = makeBtn("🔗  GET KEY", Color3.fromRGB(0, 55, 75), C.cyan, 0.10)
GetBtn.MouseButton1Click:Connect(function()
    GetBtn.Text = "⏳  OPENING..."
    local opened = false
    for _, fn in ipairs({
        function() if syn and syn.open_url then syn.open_url(KEY_LINK) opened = true end end,
        function() if http and http.open_url then http.open_url(KEY_LINK) opened = true end end,
        function() if KRNL_LOADED then KRNL_HTTP.open_url(KEY_LINK) opened = true end end,
        function() if getgenv and getgenv().open_url then getgenv().open_url(KEY_LINK) opened = true end end,
    }) do pcall(fn) if opened then break end end
    pcall(setclipboard, KEY_LINK)
    setStatus("✅  Link copied to clipboard!", C.cyan)
    task.wait(2)
    GetBtn.Text = "🔗  GET KEY"
    setStatus("")
end)

local SubBtn, SubFrame = makeBtn("🔑  SUBMIT KEY", C.purple, C.pink, 0.11)

local function shakeCard()
    local orig = Card.Position
    for _ = 1, 4 do
        TweenService:Create(Card, TweenInfo.new(0.05), {Position = UDim2.new(orig.X.Scale + 0.006, 0, orig.Y.Scale, 0)}):Play()
        task.wait(0.05)
        TweenService:Create(Card, TweenInfo.new(0.05), {Position = UDim2.new(orig.X.Scale - 0.006, 0, orig.Y.Scale, 0)}):Play()
        task.wait(0.05)
    end
    TweenService:Create(Card, TweenInfo.new(0.05), {Position = orig}):Play()
end

local function runRealScript()
    if not EXEC_ID or not TOKEN then
        warn("[ObfHubKeySystem] runRealScript called before EXEC_ID/TOKEN were set.")
        setStatus("❌  Internal error — please retry.", C.red)
        SubBtn.Text = "🔑  SUBMIT KEY"
        submitCooldown = false
        return
    end
    local url = HOST .. "/raw/" .. EXEC_ID .. "?t=" .. TOKEN
    local code, lastErr = nil, nil

    local function extractBody(result)
        if type(result) == "string" then return result end
        if type(result) == "table" then return result.Body or result.body end
        return nil
    end

    if type(http) == "table" and type(http.request) == "function" then
        local ok, result = pcall(function()
            return http.request({ Url = url, Method = "GET" })
        end)
        if ok and result then
            local body = extractBody(result)
            if body and body ~= "" then code = body end
            if not code then lastErr = "http.request returned empty body" end
        else
            lastErr = "http.request: " .. tostring(result)
        end
    end

    if not code and type(request) == "function" then
        local ok, result = pcall(function()
            return request({ Url = url, Method = "GET" })
        end)
        if ok and result then
            local body = extractBody(result)
            if body and body ~= "" then code = body end
            if not code then lastErr = "request() returned empty body" end
        else
            lastErr = "request(): " .. tostring(result)
        end
    end

    if not code then
        local ok, result = pcall(function()
            return HttpService:RequestAsync({ Url = url, Method = "GET" })
        end)
        if ok and result then
            local body = extractBody(result)
            if body and body ~= "" then code = body end
            if not code then lastErr = "RequestAsync returned empty body" end
        else
            lastErr = "RequestAsync: " .. tostring(result)
        end
    end

    if not code then
        local ok, result = pcall(function()
            return HttpService:GetAsync(url)
        end)
        if ok and result and result ~= "" then
            code = result
        else
            lastErr = ok and "GetAsync returned empty body" or tostring(result)
        end
    end

    if not code then
        warn("[ObfHubKeySystem] All fetch methods failed. Last error: " .. tostring(lastErr))
        setStatus("❌  Request failed — " .. tostring(lastErr):sub(1, 50), C.red)
        SubBtn.Text = "🔑  SUBMIT KEY"
        submitCooldown = false
        return
    end
    if (code:match("^%-%- expired") or code:match("^%-%- invalid token") or code:match("^%-%- Request denied")) then
        local errMsg = code:gsub("^%-%-%s*", "")
        setStatus("❌  " .. errMsg, C.red)
        SubBtn.Text = "🔑  SUBMIT KEY"
        submitCooldown = false
        return
    end
    local fadeOut = Instance.new("Frame")
    fadeOut.Size, fadeOut.BackgroundColor3 = UDim2.fromScale(1,1), C.bg
    fadeOut.BackgroundTransparency = 1
    fadeOut.BorderSizePixel = 0
    fadeOut.ZIndex = 999
    fadeOut.Parent = ScreenGui
    TweenService:Create(fadeOut, TweenInfo.new(0.5), {BackgroundTransparency = 0}):Play()
    task.wait(0.6)
    ScreenGui:Destroy()
    local fn, err = loadstring(code)
    if fn then fn() else warn("[ObfHubKeySystem] " .. tostring(err)) end
end

SubBtn.MouseButton1Click:Connect(function()
    if submitCooldown then return end
    if attemptCount >= MAX_ATTEMPTS then
        setStatus("🔒  Too many attempts. Restart to try again.", C.red)
        shakeCard() return
    end

    local entered = KeyBox.Text:match("^%s*(.-)%s*$")
    if entered == "" then
        setStatus("⚠️  Please enter your key first", C.muted)
        return
    end

    submitCooldown = true
    SubBtn.Text     = "⏳  VERIFYING..."
    setStatus("Verifying key...", C.muted)

    local executorName = (getexecutorname and getexecutorname()) or "Unknown"

    local body = HttpService:JSONEncode({
        scriptId = SCRIPT_ID,
        key = entered,
        hwid = HWID,
        executor = executorName
    })

    local reqOk, rawBody, lastErr = false, nil, nil

    if http and http.request then
        local ok, result = pcall(function()
            return http.request({
                Url     = HOST .. "/api/verify-key",
                Method  = "POST",
                Headers = { ["Content-Type"] = "application/json" },
                Body    = body,
            })
        end)
        if ok and result and result.Body then
            reqOk, rawBody = true, result.Body
        else
            lastErr = ok and "http.request returned no body" or tostring(result)
        end
    end

    if not reqOk and request and type(request) == "function" then
        local ok, result = pcall(function()
            return request({
                Url     = HOST .. "/api/verify-key",
                Method  = "POST",
                Headers = { ["Content-Type"] = "application/json" },
                Body    = body,
            })
        end)
        if ok and result and result.Body then
            reqOk, rawBody = true, result.Body
        else
            lastErr = ok and "request() returned no body" or tostring(result)
        end
    end

    if not reqOk then
        local ok, result = pcall(function()
            return HttpService:RequestAsync({
                Url     = HOST .. "/api/verify-key",
                Method  = "POST",
                Headers = { ["Content-Type"] = "application/json" },
                Body    = body,
            })
        end)
        if ok and result and result.Body then
            reqOk, rawBody = true, result.Body
        else
            lastErr = ok and "RequestAsync returned no body" or tostring(result)
        end
    end

    if not reqOk then
        local ok, result = pcall(function()
            return HttpService:PostAsync(HOST .. "/api/verify-key", body, Enum.HttpContentType.ApplicationJson)
        end)
        if ok and result then
            reqOk, rawBody = true, result
        else
            lastErr = ok and "PostAsync returned nothing" or tostring(result)
        end
    end

    if not reqOk then
        warn("[ObfHubKeySystem] All request methods failed. Last error: " .. tostring(lastErr))
        setStatus("❌  Network error — " .. tostring(lastErr):sub(1, 60), C.red)
        SubBtn.Text = "🔑  SUBMIT KEY"
        submitCooldown = false
        return
    end

    local decoded; local dok = pcall(function() decoded = HttpService:JSONDecode(rawBody) end)
    if not dok or not decoded then
        setStatus("❌  Server error.", C.red)
        SubBtn.Text = "🔑  SUBMIT KEY"
        submitCooldown = false
        return
    end

    if decoded.valid then
        EXEC_ID = decoded.execId
        TOKEN   = decoded.token
        if not EXEC_ID or not TOKEN then
            setStatus("❌  Server did not return execution info.", C.red)
            SubBtn.Text = "🔑  SUBMIT KEY"
            submitCooldown = false
            return
        end
        TweenService:Create(SubFrame, TweenInfo.new(0.3), {BackgroundColor3 = C.green}):Play()
        SubBtn.Text       = "✅  ACCESS GRANTED"
        SubBtn.TextColor3 = Color3.fromRGB(0, 20, 10)
        setStatus("✅  Welcome to ObfuscatorHub!", C.green)
        task.wait(1.2)
        runRealScript()
    else
        attemptCount = attemptCount + 1
        local remaining = MAX_ATTEMPTS - attemptCount
        TweenService:Create(SubFrame, TweenInfo.new(0.15), {BackgroundColor3 = C.red}):Play()
        SubBtn.Text = "❌  INVALID KEY"

        if remaining <= 0 then
            setStatus("🔒  No attempts remaining. Restart.", C.red)
            AttemptLabel.TextColor3 = C.red
            AttemptLabel.Text       = "🛡️  attempts remaining: 0 / " .. MAX_ATTEMPTS
        else
            setStatus(string.format("❌  %s — %d attempt%s left", tostring(decoded.reason or "Invalid key"), remaining, remaining == 1 and "" or "s"), C.red)
            AttemptLabel.Text = string.format("🛡️  attempts remaining: %d / %d", remaining, MAX_ATTEMPTS)
        end

        shakeCard()
        task.wait(1.8)
        TweenService:Create(SubFrame, TweenInfo.new(0.3), {BackgroundColor3 = C.purple}):Play()

        if remaining <= 0 then
            SubBtn.Text = "🔒  LOCKED"
        else
            SubBtn.Text       = "🔑  SUBMIT KEY"
            SubBtn.TextColor3 = C.white
            submitCooldown    = false
        end
    end
end)

local Footer = Instance.new("TextLabel")
Footer.Size                   = UDim2.new(1, 0, 0.04, 0)
Footer.BackgroundTransparency = 1
Footer.Text                   = "ObfuscatorHub  |  protect. obfuscate. dominate."
Footer.TextScaled             = true
Footer.Font                   = Enum.Font.Gotham
Footer.TextColor3             = Color3.fromRGB(40, 55, 80)
Footer.TextXAlignment         = Enum.TextXAlignment.Center
Footer.ZIndex                 = 12
Footer.Parent                 = Content
local footCon = Instance.new("UITextSizeConstraint", Footer)
footCon.MinTextSize, footCon.MaxTextSize = 5, 10

Card.Position               = UDim2.fromScale(0.5, 1.3)
Card.BackgroundTransparency = 1
Shadow.BackgroundTransparency = 1

TweenService:Create(Card, TweenInfo.new(0.55, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {
    Position = UDim2.fromScale(0.5, 0.5),
    BackgroundTransparency = 0,
}):Play()
TweenService:Create(Shadow, TweenInfo.new(0.55, Enum.EasingStyle.Back, Enum.EasingDirection.Out), {
    Position = UDim2.new(0.5, 0, 0.5, 8),
    BackgroundTransparency = 0.5,
}):Play()
`;
}

const PORT = process.env.PORT || 3000;

(function registerRemainingRoutes() {
    const authRouter = require("./auth");
    mountedAuthRouter = authRouter(usersCollection, sessionStore, { mgUserGet, mgUserPut, mgIndexGet, mgIndexPut, mgIndexSetKey, sessionCookieMaxAge: SESSION_COOKIE_MAX_AGE_MS, discordJoinsCol });
    app.use("/", mountedAuthRouter);

    app.get("/api/:id", async (req, res) => {
      try {
        const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
        if (isRateLimited(ip)) return res.status(429).send("-- slow down");

        let s = await scriptsCollection.findOne({ id: req.params.id });
        if (!s) s = await tempCollection.findOne({ id: req.params.id });
        if (!s) return res.status(404).send("-- Not found");

        if (s && !s.scrapID && !s.fileName) {
            const ua = req.headers["user-agent"] || "";
            if (!isExecutorUA(ua)) {
                console.log(`[api] blocked UA for ${req.params.id}: "${ua}"`);
                if ((req.headers.accept || "").includes("text/html")) return res.redirect(`/${req.params.id}`);
                return res.status(200).type("text/plain").send(luaNotice("Request denied (UA)"));
            }

            let code = s.code;
            if (!code) return res.status(404).send("-- no code");

            const token = generateToken();
            const execId = crypto.randomBytes(8).toString("hex");

            const execId2 = crypto.randomBytes(8).toString("hex");
            const token2  = generateToken();
            await execStore.set(execId2, { code, ip, token: token2 }, 15000);

            const protectedCode = `
        if not game or not game.GetService or not (game.IsLoaded and game:IsLoaded()) then return end

        local _origLoadstring = loadstring

        if hookfunction then
            local _realHookfunction = hookfunction
            hookfunction = function(fnToHook, replacement)
                if fnToHook == _origLoadstring or fnToHook == loadstring then

                    task.spawn(function() while true do task.wait(0) end end)
                    pcall(function()
                        game:GetService("Players").LocalPlayer:Kick(
                            "Anti-cheat: Do not attempt to hook loadstring/HttpGet."
                        )
                    end)
                    return fnToHook
                end
                return _realHookfunction(fnToHook, replacement)
            end
        end

        local _origPrint        = print
        local _origWarn         = warn
        local _origRequire      = require
        local _origError        = error
        local _origPcall        = pcall
        local _origXpcall       = xpcall
        local _origTostring     = tostring
        local _origType         = type
        local _origRawget       = rawget
        local _origRawset       = rawset
        local _origSetmetatable = setmetatable
        local _origGetmetatable = getmetatable

        local _protectedFns = {}

        local function _registerProtected(fn)
            _protectedFns[fn] = true
        end

        _registerProtected(_origLoadstring)
        _registerProtected(game.HttpGet)
        _registerProtected(game.HttpPost)
        pcall(function() if syn and syn.request then _registerProtected(syn.request) end end)
        pcall(function() if request then _registerProtected(request) end end)

        local function _checkTamper()
            local ishook = isfunctionhooked or ishooked or nil
            if ishook then
                for fn, _ in next, _protectedFns do
                    local ok, hooked = _origPcall(ishook, fn)
                    if ok and hooked then

                        task.spawn(function()
                            while true do task.wait(0) end
                        end)
                        _origPcall(function()
                            game:GetService("Players").LocalPlayer:Kick(
                                "Anti-cheat: Do not attempt to hook protected functions."
                            )
                        end)
                        return true
                    end
                end
            end

            local restore = restorefunction or nil
            if restore then
                task.spawn(function()
                    while true do
                        task.wait(0.5)
                        for fn, _ in next, _protectedFns do
                            local ok2, hooked2 = _origPcall(function()
                                return isfunctionhooked and isfunctionhooked(fn)
                            end)
                            if ok2 and hooked2 then
                                while true do task.wait(0) end
                            end
                        end
                    end
                end)
            end

            local okCoreSpy, coreSpy = pcall(function() return game:GetService("CoreGui") end)
            if okCoreSpy and coreSpy then
                local okKidsSpy, kidsSpy = pcall(function() return coreSpy:GetChildren() end)
                if okKidsSpy and kidsSpy then
                    for _, childSpy in next, kidsSpy do
                        local okGuiSpy, isGuiSpy = pcall(function() return childSpy:IsA("ScreenGui") end)
                        if okGuiSpy and isGuiSpy then
                            local nmSpy = tostring(childSpy.Name):lower()
                            if nmSpy:find("httpspy", 1, true) or nmSpy:find("http spy", 1, true) or nmSpy:find("reqspy", 1, true) then
                                task.spawn(function() while true do task.wait(0) end end)
                                _origPcall(function()
                                    game:GetService("Players").LocalPlayer:Kick("Anti-cheat: HTTP spy GUI detected.")
                                end)
                                return true
                            end
                        end
                    end
                end
            end
            return false
        end

        local _origIpairs = ipairs
        local _printGuard = function(...)
            local args = {...}
            for _, v in _origIpairs(args) do
                if _origType(v) == "string" then
                    if string.find(v, "loadstring", 1, true) and string.find(v, "HttpGet", 1, true) then

                        task.spawn(function() while true do task.wait(0) end end)
                        _origPcall(function()
                            game:GetService("Players").LocalPlayer:Kick("Anti-cheat: loadstring dump detected.")
                        end)
                        return
                    end
                end
            end
            return _origPrint(...)
        end
        _registerProtected(_printGuard)

        print = _printGuard

        local _hasGenv, _genv = pcall(getgenv)
        if _hasGenv and _genv then
            _genv._OBFHUB_LOADED = _genv._OBFHUB_LOADED or {}
            local _runCount = (_genv._OBFHUB_LOADED["${s.id}"] or 0) + 1
            if _runCount > 2 then
                warn("Script already running.")
                return
            end
            _genv._OBFHUB_LOADED["${s.id}"] = _runCount
        end

        if _checkTamper() then return end

        local _t2   = "${token2}"
        local _url2 = "https://${req.headers.host}/raw2/${execId2}?t=".._t2
        local _fetchOk, _src2 = _origPcall(game.HttpGet, game, _url2)
        if not _fetchOk or not _src2 or _src2 == "" then
            error("Failed to load protected script body. Server returned: " .. tostring(_src2))
        end

        local _fn2, _err2 = loadstring(_src2)
        if not _fn2 then
            error("Script body load error: " .. tostring(_err2))
        end

        print        = _origPrint
        warn         = _origWarn
        require      = _origRequire
        error        = _origError
        pcall        = _origPcall
        xpcall       = _origXpcall
        tostring     = _origTostring
        type         = _origType
        rawget       = _origRawget
        rawset       = _origRawset
        setmetatable = _origSetmetatable
        getmetatable = _origGetmetatable

        _fn2()`;

            await execStore.set(execId, { code: protectedCode, ip, token }, 15000);

            async function sendObfuscatedLoaderTemp(req, res, execId, token) {
                const loader = buildRawShell(req.headers.host, execId, token);
                const obfuscatedLoader = await newObfuscate(loader);
                await execStore.touch(execId, 15000); // obfuscation can take seconds; restart the one-time window now that the loader is ready
                await execStore.touch(execId2, 15000); // restart the paired /raw2 payload window at the same time
                return res.type("text/plain").send(obfuscatedLoader || loader);
            }
            return await sendObfuscatedLoaderTemp(req, res, execId, token);
        }

        const ua = req.headers["user-agent"] || "";
        if (!isExecutorUA(ua)) {
            console.log(`[api] non-executor UA for ${req.params.id}: "${ua}"`);
            if ((req.headers.accept || "").includes("text/html")) return res.redirect(`/${req.params.id}`);
            return res.status(200).type("text/plain").send(luaNotice("Request denied (UA)"));
        }

        if (Array.isArray(s.tokens) && s.tokens.length > 0) {
            const staticToken = s.tokens[Math.floor(Math.random() * s.tokens.length)];
            s.lastToken = staticToken;
            await scriptsCollection.updateOne({ id: s.id }, { $set: { lastToken: s.lastToken } });
        }

        let realCode = null;
        if (s.scrapID) realCode = rubisLoadstringStub(s.scrapID);
        else if (s.fileName) realCode = await legacyGetGitHubFile(s.fileName); // legacy fallback for old scripts
        if (!realCode && s.code) realCode = s.code;
        if (!realCode) return res.status(500).send("-- no code");

        try {
            const execId = crypto.randomBytes(8).toString("hex");
            const token = generateToken();

            const execId2 = crypto.randomBytes(8).toString("hex");
            const token2  = generateToken();
            await execStore.set(execId2, { code: realCode, ip, token: token2 }, 15000);

            const protectedCode = `
        if not game or not game.GetService or not (game.IsLoaded and game:IsLoaded()) then return end

        local _origLoadstring = loadstring

        if hookfunction then
            local _realHookfunction = hookfunction
            hookfunction = function(fnToHook, replacement)
                if fnToHook == _origLoadstring or fnToHook == loadstring then
                    task.spawn(function() while true do task.wait(0) end end)
                    pcall(function()
                        game:GetService("Players").LocalPlayer:Kick(
                            "Anti-cheat: Do not attempt to hook loadstring/HttpGet."
                        )
                    end)
                    return fnToHook
                end
                return _realHookfunction(fnToHook, replacement)
            end
        end

        local _origPrint        = print
        local _origWarn         = warn
        local _origRequire      = require
        local _origError        = error
        local _origPcall        = pcall
        local _origXpcall       = xpcall
        local _origTostring     = tostring
        local _origType         = type
        local _origRawget       = rawget
        local _origRawset       = rawset
        local _origSetmetatable = setmetatable
        local _origGetmetatable = getmetatable

        local _protectedFns = {}

        local function _registerProtected(fn)
            _protectedFns[fn] = true
        end

        _registerProtected(_origLoadstring)
        _registerProtected(game.HttpGet)
        _registerProtected(game.HttpPost)
        pcall(function() if syn and syn.request then _registerProtected(syn.request) end end)
        pcall(function() if request then _registerProtected(request) end end)

        local function _checkTamper()

            local ishook = isfunctionhooked or ishooked or nil
            if ishook then
                for fn, _ in next, _protectedFns do
                    local ok, hooked = _origPcall(ishook, fn)
                    if ok and hooked then

                        task.spawn(function()
                            while true do task.wait(0) end
                        end)
                        _origPcall(function()
                            game:GetService("Players").LocalPlayer:Kick(
                                "Anti-cheat: Do not attempt to hook protected functions."
                            )
                        end)
                        return true
                    end
                end
            end

            local restore = restorefunction or nil
            if restore then

                task.spawn(function()
                    while true do
                        task.wait(0.5)
                        for fn, _ in next, _protectedFns do
                            local ok2, hooked2 = _origPcall(function()
                                return isfunctionhooked and isfunctionhooked(fn)
                            end)
                            if ok2 and hooked2 then
                                while true do task.wait(0) end
                            end
                        end
                    end
                end)
            end

            local okCoreSpy, coreSpy = pcall(function() return game:GetService("CoreGui") end)
            if okCoreSpy and coreSpy then
                local okKidsSpy, kidsSpy = pcall(function() return coreSpy:GetChildren() end)
                if okKidsSpy and kidsSpy then
                    for _, childSpy in next, kidsSpy do
                        local okGuiSpy, isGuiSpy = pcall(function() return childSpy:IsA("ScreenGui") end)
                        if okGuiSpy and isGuiSpy then
                            local nmSpy = tostring(childSpy.Name):lower()
                            if nmSpy:find("httpspy", 1, true) or nmSpy:find("http spy", 1, true) or nmSpy:find("reqspy", 1, true) then
                                task.spawn(function() while true do task.wait(0) end end)
                                _origPcall(function()
                                    game:GetService("Players").LocalPlayer:Kick("Anti-cheat: HTTP spy GUI detected.")
                                end)
                                return true
                            end
                        end
                    end
                end
            end
            return false
        end

        local _origIpairs = ipairs
        local _printGuard = function(...)
            local args = {...}
            for _, v in _origIpairs(args) do
                if _origType(v) == "string" then
                    if string.find(v, "loadstring", 1, true) and string.find(v, "HttpGet", 1, true) then

                        task.spawn(function() while true do task.wait(0) end end)
                        _origPcall(function()
                            game:GetService("Players").LocalPlayer:Kick("Anti-cheat: loadstring dump detected.")
                        end)
                        return
                    end
                end
            end
            return _origPrint(...)
        end
        _registerProtected(_printGuard)

        print = _printGuard

        local _hasGenv, _genv = pcall(getgenv)
        if _hasGenv and _genv then
            _genv._OBFHUB_LOADED = _genv._OBFHUB_LOADED or {}
            local _runCount = (_genv._OBFHUB_LOADED["${s.id}"] or 0) + 1
            if _runCount > 2 then
                warn("Script already running.")
                return
            end
            _genv._OBFHUB_LOADED["${s.id}"] = _runCount
        end

        if _checkTamper() then return end

        local _t2   = "${token2}"
        local _url2 = "https://${req.headers.host}/raw2/${execId2}?t=".._t2
        local _fetchOk, _src2 = _origPcall(game.HttpGet, game, _url2)
        if not _fetchOk or not _src2 or _src2 == "" then
            error("Failed to load protected script body. Server returned: " .. tostring(_src2))
        end

        local _fn2, _err2 = loadstring(_src2)
        if not _fn2 then
            error("Script body load error: " .. tostring(_err2))
        end

        print        = _origPrint
        warn         = _origWarn
        require      = _origRequire
        error        = _origError
        pcall        = _origPcall
        xpcall       = _origXpcall
        tostring     = _origTostring
        type         = _origType
        rawget       = _origRawget
        rawset       = _origRawset
        setmetatable = _origSetmetatable
        getmetatable = _origGetmetatable

        _fn2()`;

            const execTTL = 15000;
            await execStore.set(execId, { code: protectedCode, ip, token, keySystemPending: !!(s.keySystem && s.keySystem.enabled) }, execTTL);

            if (s.keySystem && s.keySystem.enabled) {
                const getKeyUrl = s.keySystem.discordInvite || s.keySystem.getKeyUrl || `https://${req.headers.host}/getkey/${s.id}`;
                const keyGateLua = buildKeyGateLua(req.headers.host, s.id, getKeyUrl);
                return res.type("text/plain").send(keyGateLua);
            }

            async function sendObfuscatedLoader(req, res, execId, token) {
                const loader = buildRawShell(req.headers.host, execId, token);
                const obfuscatedLoader = await newObfuscate(loader);
                await execStore.touch(execId, 15000); // obfuscation can take seconds; restart the one-time window now that the loader is ready
                await execStore.touch(execId2, 15000); // restart the paired /raw2 payload window at the same time
                return res.type("text/plain").send(obfuscatedLoader || loader);
            }
            return await sendObfuscatedLoader(req, res, execId, token);

        } catch (e) {
            console.error(`[${new Date().toISOString()}] /api/:id GitHub-path error for script ${req.params.id}:`, e.stack || e.message || e);
            return res.status(200).type("text/plain").send("-- error: failed to build protected script, check server logs");
        }
      } catch (e) {
        console.error(`[${new Date().toISOString()}] /api/:id crashed for script ${req.params.id}:`, e.stack || e.message || e);
        return res.status(200).type("text/plain").send("-- error: temporarily unavailable, try again");
      }
    });

    app.get("/admin", (req, res) => {
        if (!verifyAdminCookie(req.cookies && req.cookies.admin_session)) {
            return res.sendFile(path.join(__dirname, "public/admin-login.html"));
        }
        res.sendFile(path.join(__dirname, "public/admin.html"));
    });

    app.post("/admin/login", (req, res) => {
        const key = req.body && req.body.key;
        if (!key || typeof key !== "string") return res.status(403).json({ ok: false, error: "Key required" });
        const keyBuf = Buffer.from(key);
        const realBuf = Buffer.from(process.env.ADMIN_KEY || "");
        const valid = keyBuf.length === realBuf.length && crypto.timingSafeEqual(keyBuf, realBuf);
        if (!valid) return res.status(403).json({ ok: false, error: "Invalid key" });

        const expiresAt = Date.now() + ADMIN_COOKIE_TTL_MS;
        res.cookie("admin_session", signAdminCookie(expiresAt), {
            httpOnly: true,
            secure: true,
            sameSite: "lax",
            maxAge: ADMIN_COOKIE_TTL_MS
        });
        res.json({ ok: true });
    });

    app.post("/admin", requireAdmin, async (req, res) => {
        const action = req.body && req.body.action;
        switch (action) {
            case "cleanup":       return adminCleanup(req, res);
            case "cleanup-keys":  return adminCleanupKeys(req, res);
            case "migrate-temp":  return adminMigrateTemp(req, res);
            case "logout-all":    return adminLogoutAll(req, res);
            case "view-script":   return adminViewScript(req, res);
            case "logout":
                res.clearCookie("admin_session");
                return res.json({ ok: true });
            default:
                return res.status(400).json({ ok: false, error: "Unknown action" });
        }
    });

    app.get("/admin/migrate-users/run", requireAdmin, async (req, res) => {
        if (migrationRunning) {
            return res.status(409).send("A migration is already running. Please wait for it to finish.");
        }
        migrationRunning = true;

        res.setHeader("Content-Type", "text/event-stream");
        res.setHeader("Cache-Control", "no-cache");
        res.setHeader("Connection", "keep-alive");
        res.flushHeaders();

        let clientGone = false;
        req.on("close", () => { clientGone = true; });

        try {

        const send = (obj) => {
            if (clientGone) return;
            res.write("data: " + JSON.stringify(obj) + "\n\n");
            if (res.flush) res.flush();
        };
        const delay = (ms) => new Promise(r => setTimeout(r, ms));
        const type = req.query.type || "all";

        if (type === "scripts" || type === "all") {
            if (!process.env.GITHUB_TOKEN) {
                send({ info: "⚠️  GITHUB_TOKEN not set — cannot read GitHub scripts. Skipping." });
            } else {
                const oldDocs = await oldScriptsCollection.find({ fileName: { $exists: true } }).toArray();
                send({ info: `Found ${oldDocs.length} old script(s) with fileName in primary MongoDB` });

                for (const s of oldDocs) {
                    if (clientGone) break; // page closed — stop hitting GitHub/Rubis/Mongo for no one
                    const exists = await scriptsCollection.findOne({ id: s.id, scrapID: { $exists: true } });
                    if (exists) { send({ id: s.id, status: "skipped" }); continue; }

                    try {
                        const code = await legacyGetGitHubFile(s.fileName);
                        if (!code) { send({ id: s.id, status: "failed", error: "File not found on GitHub: " + s.fileName }); continue; }
                        if (scriptTooLargeForRubis(code)) { send({ id: s.id, status: "failed", error: "script exceeds Rubis 3MB limit" }); continue; }

                        const { scrapID, ownerKey } = await rubisUpload(code);

                        await scriptsCollection.updateOne(
                            { id: s.id },
                            { $set: { id: s.id, password: s.password, scrapID, scrapOwnerKey: ownerKey,
                                      tokens: (Array.isArray(s.tokens) && s.tokens.length) ? s.tokens : [generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken()],
                                      lastToken: s.lastToken || "",
                                      owner: s.owner || null, createdAt: s.createdAt || new Date() } },
                            { upsert: true }
                        );
                        await oldScriptsCollection.deleteOne({ _id: s._id });
                        send({ id: s.id, status: "migrated", scrapID });
                        await delay(250); // ~4/s, under Rubis 10/s limit
                    } catch(e) {
                        send({ id: s.id, status: "failed", error: e.message });
                        await delay(500);
                    }
                }

                const tempDocs = await tempCollection.find({ code: { $exists: true } }).toArray();
                if (tempDocs.length) {
                    send({ info: `Also migrating ${tempDocs.length} script(s) from temp collection` });
                    for (const s of tempDocs) {
                        if (clientGone) break;
                        const exists = await scriptsCollection.findOne({ id: s.id });
                        if (exists) { send({ id: s.id + " (temp)", status: "skipped" }); continue; }
                        if (!s.code) { send({ id: s.id + " (temp)", status: "failed", error: "no code" }); continue; }
                        if (scriptTooLargeForRubis(s.code)) { send({ id: s.id + " (temp)", status: "failed", error: "script exceeds Rubis 3MB limit" }); continue; }
                        try {
                            const { scrapID, ownerKey } = await rubisUpload(s.code);
                            await scriptsCollection.updateOne(
                                { id: s.id },
                                { $set: { id: s.id, password: s.password, scrapID, scrapOwnerKey: ownerKey,
                                          tokens: (Array.isArray(s.tokens) && s.tokens.length) ? s.tokens : [generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken(),generateToken()],
                                          lastToken: s.lastToken || "",
                                          owner: s.owner || null, createdAt: s.createdAt || new Date() } },
                                { upsert: true }
                            );
                            await tempCollection.deleteOne({ _id: s._id });
                            send({ id: s.id + " (temp)", status: "migrated", scrapID });
                            await delay(250);
                        } catch(e) {
                            send({ id: s.id + " (temp)", status: "failed", error: e.message });
                            await delay(500);
                        }
                    }
                }
                send({ info: "Script migration complete." });
            }
        }

        if (type === "users" || type === "all") {
            if (!process.env.GITHUB_TOKEN) {
                send({ info: "⚠️  GITHUB_TOKEN not set — cannot read GitHub user data. Skipping." });
            } else {
                send({ info: "Fetching index.json from GitHub USERDATA repo…" });
                try {
                    const indexData = await legacyGetUserFileJSON("index.json");
                    if (indexData) {
                        const existing = await mgIndexGet();
                        if (existing) { send({ userId: "index.json", status: "skipped" }); }
                        else { await mgIndexPut(indexData); send({ userId: "index.json", status: "migrated" }); }
                    } else { send({ userId: "index.json", status: "failed", error: "not found on GitHub" }); }
                } catch(e) { send({ userId: "index.json", status: "failed", error: e.message }); }
                await delay(500);

                const files = await legacyListGitHubDir("users");
                send({ info: `Found ${files.length} user file(s) in GitHub USERDATA/users/` });

                for (const file of files) {
                    if (clientGone) break;
                    if (!file.name.endsWith(".json")) continue;
                    const userId = file.name.replace(/\.json$/, "");
                    try {
                        const existing = await mgUserGet(userId);
                        if (existing) { send({ userId, status: "skipped" }); continue; }

                        const userData = await legacyGetUserFileJSON("users/" + file.name);
                        if (!userData) { send({ userId, status: "failed", error: "Could not fetch from GitHub" }); continue; }

                        await mgUserPut(userId, userData);
                        send({ userId, status: "migrated" });
                        await delay(500); // be gentle on GitHub rate limit
                    } catch(e) {
                        send({ userId, status: "failed", error: e.message });
                        await delay(500);
                    }
                }
                send({ info: "User migration complete." });
            }
        }

        send({ done: true });
        res.end();

        } finally {
            migrationRunning = false;
        }
    });

    app.get('/googleef09534d70373232.html', (req, res) => {
        res.sendFile(path.join(__dirname, 'public/googleef09534d70373232.html'));
    });

    app.get("/:id", async (req, res) => {
        const ua = req.headers["user-agent"] || "";
        if (ua.includes("Roblox")) return res.status(404).send("-- Not found");
        // A freshly created script lives only in tempCollection until its
        // background Rubis upload finishes and moves it into scriptsCollection
        // (see queueRubisUpload/processRubisQueue). Checking only
        // scriptsCollection meant the edit/view link given out right after
        // creation 404'd for a few seconds, for both auto-generated and
        // custom paths — this fixes that by falling back to tempCollection,
        // the same way /unlock already does.
        const script = await scriptsCollection.findOne({ id: req.params.id })
            || await tempCollection.findOne({ id: req.params.id });
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate");
        if (!script) return res.status(404).sendFile(path.join(__dirname, "public/404.html"));
        res.sendFile(path.join(__dirname, "public/view.html"));
    });

    app.use((req, res) => {
        const ua = req.headers["user-agent"] || "";
        if (ua.includes("Roblox")) return res.status(404).send("-- Not found");
        res.status(404).sendFile(path.join(__dirname, "public/404.html"));
    });

    async function sweepExpiredKeys() {
        try {
            const result = await keysCollection.deleteMany({ expiresAt: { $lt: new Date() } });
            if (result.deletedCount > 0) {
                console.log(`[keys sweep] deleted ${result.deletedCount} expired key(s)`);
            }
        } catch (e) {
            console.error("[keys sweep] failed:", e.message);
        }
    }
    app.use("/api", (req, res) => {
        res.status(404).json({ ok: false, error: "API route not found: " + req.method + " " + req.originalUrl.split("?")[0] });
    });

    app.use((err, req, res, next) => {
        console.error("[error]", req.method, req.originalUrl, err && (err.stack || err.message || err));
        if (res.headersSent) return next(err);
        const status = (err && (err.status || err.statusCode)) || 500;
        let msg = "Server error. Try again.";
        if (err && (err.type === "entity.too.large" || status === 413)) msg = "Script too large to upload. Try a smaller script.";
        else if (err && err.type === "entity.parse.failed") msg = "Bad request body.";
        else if (status === 400) msg = "Bad request.";
        const wantsJson = req.path.startsWith("/api/") || (req.headers.accept || "").includes("json") || (req.headers["content-type"] || "").includes("json");
        if (wantsJson) return res.status(status).json({ ok: false, error: msg });
        return res.status(status).type("text/plain").send(msg);
    });

    if (!process.env.VERCEL) {
        sweepExpiredKeys(); // run once immediately on boot
        setInterval(sweepExpiredKeys, 30 * 1000); // then every 30s
    }

    if (!process.env.VERCEL) {
        app.listen(PORT, () => {
            console.log("Server running on port " + PORT);
        });
    }
})();

module.exports = app;
