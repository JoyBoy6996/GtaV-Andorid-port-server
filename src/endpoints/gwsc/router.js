import express from "express";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { prisma, sendLogMessage } from "../../main.js";
import {
  getGwscSession,
  destroyGwscSession,
  destroyGwscSessionsByUserId,
  issueGwscSession,
  issueGwscLaunchTicket,
} from "../../services/gwscSessionService.js";

/**
 * JSON backend endpoints used by the GTA Online client inside the Android port
 * (com.thegwchr.fuzzy). These mirror the /gwsc/api surface decompiled from the
 * client's GwscClient so the server can answer the client exactly like the
 * production backend does.
 *
 * Contract highlights (from decompiled GwscClient / LauncherActivity):
 *  - base path: https://<host>/gwsc/api/<endpoint>
 *  - headers:  Accept: application/json, Authorization: Bearer <token>,
 *              Content-Type: application/json
 *  - errors:   JSON body with an `error` string; HTTP >= 400 marks failure
 *              (the client treats the response body as null on failure and
 *              clears the session on 401)
 *  - success:  JSON body is passed to the callback (ApprovalCallback.done)
 */
export const GwscRouter = express.Router();

const SERVER_NAME = process.env.DOMAIN || "dev.lossantosonline.com";

// Avatar presets + colours, mirroring the private backend contract used by the
// GTA Online client (com.thegwchr.fuzzy). `preset_N` ids plus raw colour values.
const PRESET_COLOURS = [
  "#1abc9c", "#2ecc71", "#3498db", "#9b59b6", "#34495e",
  "#f1c40f", "#e67e22", "#e74c3c", "#ecf0f1", "#95a5a6",
  "#d35400", "#c0392b", "#bdc3c7", "#7f8c8d", "#2c3e50",
];
const VALID_AVATARS = new Set([
  ...PRESET_COLOURS,
  ...Array.from({ length: PRESET_COLOURS.length }, (_, index) => `preset_${index}`),
]);

const NICKNAME_RE = /^[A-Za-z0-9_. -]{3,16}$/;
const EMAIL_RE = /^[^@\s]{1,64}@[^@\s]{1,255}\.[^@\s]{2,}$/;

function getBearerToken(req) {
  const authHeader = req.headers.authorization || req.headers.Authorization || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
  return String(token || "").trim();
}

function sendGwscError(res, status, error, message, extra = {}) {
  return res.status(status).json({
    error,
    message,
    detail: { error, message, ...extra },
  });
}

// Simple in-memory social graph / achievements store keyed by user / rockstar id.
const gwscSocialLists = new Map(); // userId -> { friends, incoming, outgoing, blocked }
const gwscAchievements = new Map(); // rockstarId -> [{ id, at, offline }]

function getGwscSocialList(userId) {
  let list = gwscSocialLists.get(userId);
  if (!list) {
    list = { friends: [], incoming: [], outgoing: [], blocked: [] };
    gwscSocialLists.set(userId, list);
  }
  return list;
}

function toFriendEntry(entry) {
  return {
    rockstarId: entry.rockstarId ?? 0,
    online: entry.online === true,
    nickname: entry.nickname || "",
  };
}

function extractLaunchToken(body) {
  if (!body || typeof body !== "object") {
    return null;
  }
  const preferredKeys = ["ticket", "sessionTicket", "session", "token", "launchTicket", "authToken"];
  for (const preferredKey of preferredKeys) {
    const value = body[preferredKey];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  const keys = Object.keys(body);
  for (const key of keys) {
    const value = body[key];
    if (typeof value === "string" && value.length > 0) {
      return value;
    }
  }
  return null;
}

// GET /gwsc/api/info -> { name, online, accounts, registration, webUrl? }
export const getGwscInfoHandler = async (_req, res) => {
  try {
    const accounts = await prisma.user.count();
    const onlinePlayers = await prisma.activePlayer.count();
    return res.json({
      name: SERVER_NAME,
      online: 1,
      accounts: onlinePlayers,
      registration: true,
      webUrl: process.env.DOMAIN || "",
    });
  } catch (error) {
    console.error("Gwsc info error:", error);
    return res.status(500).json({ error: error?.message || "Failed to load server info" });
  }
};

// GET /gwsc/api/me -> { token, profile: { nickname, rockstarId, email } }
export const getGwscMeHandler = async (req, res) => {
  try {
    const token = getBearerToken(req);
    const session = getGwscSession(token);
    if (!session) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    return res.json({
      token,
      profile: {
        nickname: session.nickname || "Player",
        rockstarId: session.rockstarId ?? 0,
        email: session.email || "",
      },
    });
  } catch (error) {
    console.error("Gwsc me error:", error);
    return res.status(500).json({ error: "Failed to load session" });
  }
};

// POST /gwsc/api/login -> { token, profile: { nickname, rockstarId, email } }
export const loginGwscHandler = async (req, res) => {
  try {
    const email = (req.body?.email || "").trim().toLowerCase();
    const password = req.body?.password || "";
    if (!email || !password) {
      return sendGwscError(res, 400, "invalid_credentials", "Invalid email or password");
    }
    const user = await prisma.user.findFirst({ where: { email } });
    if (!user || !user.PCPassword || !(await bcrypt.compare(password, user.PCPassword))) {
      return sendGwscError(res, 401, "invalid_credentials", "Invalid email or password");
    }
    if (user.banned) {
      return sendGwscError(res, 403, "account_disabled", "This account is not active");
    }
    const nickname = user.name || user.PS4Username || `User${user.RockstarId}`;
    const token = issueGwscSession({
      userId: user.id,
      email: user.email,
      nickname,
      rockstarId: user.RockstarId,
    });
    return res.json({
      token,
      profile: {
        nickname,
        rockstarId: user.RockstarId,
        email: user.email,
      },
    });
  } catch (error) {
    console.error("Gwsc login error:", error);
    return res.status(500).json({ error: "Login failed" });
  }
};

// POST /gwsc/api/logout
export const logoutGwscHandler = async (req, res) => {
  try {
    const token = getBearerToken(req);
    destroyGwscSession(token);
    return res.json({ status: "ok" });
  } catch (error) {
    return res.status(500).json({ error: "Logout failed" });
  }
};

// POST /gwsc/api/logout-all -> revoke every session of the account
export const logoutAllGwscHandler = async (req, res) => {
  try {
    const token = getBearerToken(req);
    const session = getGwscSession(token);
    if (!session?.userId) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    destroyGwscSessionsByUserId(session.userId);
    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Gwsc logout-all error:", error);
    return res.status(500).json({ error: "Logout failed" });
  }
};

// POST /gwsc/api/register -> { token, profile } (used by the account creation flow)
export const registerGwscHandler = async (req, res) => {
  try {
    const email = String(req.body?.email || "").trim().toLowerCase();
    const nickname = String(req.body?.nickname || "").trim();
    const password = String(req.body?.password || "");
    const client = String(req.body?.client || "launcher");

    if (!EMAIL_RE.test(email)) {
      return sendGwscError(res, 400, "invalid_email", "A valid email address is required");
    }
    if (!NICKNAME_RE.test(nickname)) {
      return sendGwscError(
        res,
        400,
        "invalid_nickname",
        "Nickname must be 3-16 characters and contain only letters, numbers, spaces, '.', '_' or '-'",
      );
    }
    if (password.length < 8 || password.length > 64) {
      return sendGwscError(res, 400, "invalid_password", "Password must be at least 8 and at most 64 characters");
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const randomHex = () => crypto.randomBytes(16).toString("hex");

    const existing = await prisma.user.findFirst({
      where: { OR: [{ email }, { PCNickname: nickname }] },
    });
    if (existing) {
      return sendGwscError(
        res,
        409,
        existing.email === email ? "email_exists" : "nickname_taken",
        "An account with this email or nickname already exists",
      );
    }

    const user = await prisma.user.create({
      data: {
        email,
        name: nickname,
        CountryCode: "US",
        LanguageCode: "en",
        PCNickname: nickname,
        PCPassword: passwordHash,
        SessionId: randomHex(),
        SessionKey: randomHex(),
        SessionTicket: randomHex(),
        SCAuthToken: randomHex(),
        Ticket: randomHex(),
      },
    });

    const token = issueGwscSession({
      userId: user.id,
      email: user.email,
      nickname: user.name || nickname,
      rockstarId: user.RockstarId,
    });

    return res.json({
      token,
      profile: {
        rockstarId: user.RockstarId,
        nickname: user.name || nickname,
        email: user.email,
        avatar: "",
        online: false,
      },
    });
  } catch (error) {
    console.error("Gwsc register error:", error);
    if (error?.code === "P2002") {
      return sendGwscError(res, 409, "account_exists", "Account or nickname already exists");
    }
    return res.status(500).json({ error: "register_failed", message: "Failed to register", detail: { error: "register_failed", message: "Failed to register" } });
  }
};

// POST /gwsc/api/game-launch -> { ticket } (ticket must match ^[A-Za-z0-9_-]{43}$)
export const gameLaunchGwscHandler = async (req, res) => {
  try {
    const token = getBearerToken(req) || extractLaunchToken(req.body);
    const session = getGwscSession(token);
    if (!session) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    const buildReport = req.body?.buildReport;
    if (typeof buildReport !== "string" || !buildReport.trim()) {
      return sendGwscError(res, 400, "invalid_build_report", "buildReport must be a non-empty string");
    }
    if (buildReport.length > 512) {
      return sendGwscError(res, 400, "invalid_build_report", "buildReport is too long");
    }
    const ticket = issueGwscLaunchTicket(session);
    return res.json({ ticket });
  } catch (error) {
    console.error("Gwsc game-launch error:", error);
    return res.status(500).json({ error: "Failed to create game launch ticket" });
  }
};

// POST /gwsc/api/me/password -> { status }
export const mePasswordGwscHandler = async (req, res) => {
  try {
    const token = getBearerToken(req);
    const session = getGwscSession(token);
    if (!session?.userId) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    const user = await prisma.user.findUnique({ where: { id: session.userId } });
    if (!user || !user.PCPassword) {
      return sendGwscError(res, 400, "invalid_password", "Current password is incorrect");
    }
    const valid = await bcrypt.compare(String(req.body?.current || ""), user.PCPassword);
    if (!valid) {
      return sendGwscError(res, 400, "invalid_password", "Current password is incorrect");
    }
    const next = String(req.body?.next || "");
    if (next.length < 8 || next.length > 64) {
      return sendGwscError(res, 400, "weak_password", "New password must be at least 8 and at most 64 characters");
    }
    if (next === String(req.body?.current || "")) {
      return sendGwscError(res, 400, "password_unchanged", "New password must differ from the current one");
    }
    const passwordHash = await bcrypt.hash(next, 10);
    await prisma.user.update({ where: { id: user.id }, data: { PCPassword: passwordHash } });
    // Keep the current device signed in, revoke the rest.
    destroyGwscSessionsByUserId(session.userId);
    const tokenAfter = getGwscSession(token);
    if (tokenAfter) {
      tokenAfter.createdAt = Date.now();
      tokenAfter.expiresAt = Date.now() + 1000 * 60 * 60 * 24 * 7;
    }
    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Gwsc me password error:", error);
    return res.status(500).json({ error: "Failed to change password" });
  }
};

// GET /gwsc/api/avatars/presets -> { colours, presets }
export const avatarsPresetsGwscHandler = async (_req, res) => {
  return res.json({ colours: PRESET_COLOURS, presets: Array.from(VALID_AVATARS) });
};

// POST /gwsc/api/me/avatar/preset -> { status, avatar }
export const meAvatarPresetGwscHandler = async (req, res) => {
  try {
    const preset = String(req.body?.preset || "");
    if (!VALID_AVATARS.has(preset)) {
      return sendGwscError(res, 400, "invalid_avatar", "Unknown avatar preset");
    }
    const token = getBearerToken(req);
    const session = getGwscSession(token);
    if (!session?.userId) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    session.avatar = preset;
    return res.json({ status: "ok", avatar: preset });
  } catch (error) {
    console.error("Gwsc me avatar preset error:", error);
    return res.status(500).json({ error: "Failed to set avatar preset" });
  }
};

// PATCH /gwsc/api/me -> { token, profile } (nickname change)
export const mePatchGwscHandler = async (req, res) => {
  try {
    const token = getBearerToken(req);
    const session = getGwscSession(token);
    if (!session?.userId) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    const nickname = String(req.body?.nickname || "").trim();
    if (!NICKNAME_RE.test(nickname)) {
      return sendGwscError(res, 400, "invalid_nickname", "Nickname must be 3-16 characters and contain only letters, numbers, spaces, '.', '_' or '-'");
    }
    const user = await prisma.user.findUnique({ where: { id: session.userId } });
    if (!user) {
      return sendGwscError(res, 404, "user_not_found", "User not found");
    }
    const clash = await prisma.user.findFirst({
      where: { AND: [{ id: { not: user.id } }, { PCNickname: nickname }] },
    });
    if (clash) {
      return sendGwscError(res, 409, "nickname_taken", "Nickname is already in use");
    }
    await prisma.user.update({ where: { id: user.id }, data: { PCNickname: nickname, name: nickname } });
    const freshSession = getGwscSession(token);
    if (freshSession) {
      freshSession.nickname = nickname;
    }
    return res.json({
      token,
      profile: { nickname, rockstarId: user.RockstarId, email: user.email },
    });
  } catch (error) {
    console.error("Gwsc me patch error:", error);
    return res.status(500).json({ error: "Failed to update profile" });
  }
};

// GET /gwsc/api/users/:rockstarId/profile -> public profile
export const getGwscUserProfileHandler = async (req, res) => {
  try {
    const token = getBearerToken(req);
    const session = getGwscSession(token);
    const rockstarId = Number(req.params.rockstarId);
    if (!session?.userId) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    const user = await prisma.user.findUnique({ where: { RockstarId: rockstarId } });
    if (!user) {
      return sendGwscError(res, 404, "user_not_found", "User not found");
    }
    const list = getGwscSocialList(session.userId);
    const blockedEntry = list.blocked.find((entry) => (entry.rockstarId ?? 0) === rockstarId);
    if (blockedEntry) {
      return sendGwscError(res, 404, "user_not_found", "User not found");
    }
    const relationRow = list.friends.find((entry) => (entry.rockstarId ?? 0) === rockstarId);
    const relation = blockedEntry
      ? "blocked"
      : relationRow
        ? "friends"
        : list.outgoing.some((entry) => (entry.rockstarId ?? 0) === rockstarId)
          ? "outgoing"
          : list.incoming.some((entry) => (entry.rockstarId ?? 0) === rockstarId)
            ? "incoming"
            : "none";
    return res.json({
      rockstarId,
      nickname: user.name || user.PS4Username || "",
      online: false,
      avatar: session.avatar || "",
      crewTag: user.ClanTag || "",
      relation,
      friendsCount: list.friends.length,
    });
  } catch (error) {
    console.error("Gwsc user profile error:", error);
    return res.status(500).json({ error: "Failed to load user profile" });
  }
};

// POST /gwsc/api/users/:rockstarId/block -> { status }
export const blockGwscUserHandler = async (req, res) => {
  try {
    const token = getBearerToken(req);
    const session = getGwscSession(token);
    const rockstarId = Number(req.params.rockstarId);
    if (!session?.userId) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    const user = await prisma.user.findUnique({ where: { RockstarId: rockstarId } });
    if (!user) {
      return sendGwscError(res, 404, "user_not_found", "User not found");
    }
    const list = getGwscSocialList(session.userId);
    list.blocked = list.blocked.filter((entry) => (entry.rockstarId ?? 0) !== rockstarId);
    list.blocked.push({ rockstarId, online: false, nickname: user.name || user.PS4Username || "" });
    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Gwsc block user error:", error);
    return res.status(500).json({ error: "Failed to block user" });
  }
};

// DELETE /gwsc/api/users/:rockstarId/block -> { status }
export const unblockGwscUserHandler = async (req, res) => {
  try {
    const token = getBearerToken(req);
    const session = getGwscSession(token);
    const rockstarId = Number(req.params.rockstarId);
    if (!session?.userId) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    const list = getGwscSocialList(session.userId);
    list.blocked = list.blocked.filter((entry) => (entry.rockstarId ?? 0) !== rockstarId);
    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Gwsc unblock user error:", error);
    return res.status(500).json({ error: "Failed to unblock user" });
  }
};

// GET /gwsc/api/events -> Server-Sent Events stream (text/event-stream)
const gwscSseClients = new Map(); // token -> { res, userId }

function broadcastGwscEvent(userId, event, data) {
  for (const [token, client] of gwscSseClients.entries()) {
    if (client.userId !== userId) {
      continue;
    }
    try {
      client.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
    } catch (error) {
      // Client went away; cleanup happens on close.
    }
  }
}

export const eventsGwscHandler = async (req, res) => {
  try {
    const token = getBearerToken(req) || String(req.query?.token || "");
    const session = getGwscSession(token);
    if (!session?.userId) {
      return sendGwscError(res, 401, "unauthorized", "A valid token is required for the event stream");
    }
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache, no-store");
    res.setHeader("Connection", "keep-alive");
    res.setHeader("X-Accel-Buffering", "no");
    res.status(200);
    res.write(": connected\n\n");
    const client = { res, userId: session.userId, timer: null };
    gwscSseClients.set(token, client);
    client.timer = setInterval(() => {
      try {
        res.write(": ping\n\n");
      } catch (error) {
        // ignore write errors on closed streams
      }
    }, 25000);
    const cleanup = () => {
      clearInterval(client.timer);
      if (gwscSseClients.get(token) === client) {
        gwscSseClients.delete(token);
      }
      try {
        res.end();
      } catch (error) {
        // ignore end errors on closed streams
      }
    };
    req.on("close", cleanup);
    req.on("error", cleanup);
    return res;
  } catch (error) {
    console.error("Gwsc events error:", error);
    return res.status(500).json({ error: "Failed to open event stream" });
  }
};

// GET /gwsc/api/friends -> { friends: [{ rockstarId, online, nickname }], incoming, outgoing, blocked }
export const getGwscFriendsHandler = async (req, res) => {
  try {
    const token = getBearerToken(req);
    const session = getGwscSession(token);
    if (!session?.userId) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    const list = getGwscSocialList(session.userId);
    return res.json({
      friends: list.friends.map(toFriendEntry),
      incoming: list.incoming.map(toFriendEntry),
      outgoing: list.outgoing.map(toFriendEntry),
      blocked: list.blocked.map(toFriendEntry),
    });
  } catch (error) {
    console.error("Gwsc friends error:", error);
    return res.status(500).json({ error: "Failed to load friends" });
  }
};

// POST /gwsc/api/friends { nickname } -> { status }
export const addGwscFriendHandler = async (req, res) => {
  try {
    const token = getBearerToken(req);
    const session = getGwscSession(token);
    const nickname = String(req.body?.nickname || "").trim();
    if (!session?.userId) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    if (!nickname) {
      return sendGwscError(res, 400, "invalid_friend_request", "A nickname is required to add a friend");
    }
    const list = getGwscSocialList(session.userId);
    list.outgoing.push({ rockstarId: 0, online: false, nickname });
    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Gwsc friends add error:", error);
    return res.status(500).json({ error: "Failed to add friend" });
  }
};

// POST /gwsc/api/friends/:rockstarId/reject -> { status }
export const rejectGwscFriendHandler = async (req, res) => {
  try {
    const token = getBearerToken(req);
    const session = getGwscSession(token);
    const rockstarId = Number(req.params.rockstarId);
    if (!session?.userId) {
      return sendGwscError(res, 401, "session_not_found", "Session not found");
    }
    const list = getGwscSocialList(session.userId);
    // Remove the incoming pending request (it can no longer be accepted).
    list.incoming = list.incoming.filter((entry) => (entry.rockstarId ?? 0) !== rockstarId);
    // Clean up any outgoing pending request towards the same peer.
    list.outgoing = list.outgoing.filter((entry) => (entry.rockstarId ?? 0) !== rockstarId);
    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Gwsc friends reject error:", error);
    return res.status(500).json({ error: "Failed to reject friend" });
  }
};

// POST /gwsc/api/friends/:rockstarId/accept -> { status }
export const acceptGwscFriendHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
    const session = getGwscSession(token);
    const rockstarId = Number(req.params.rockstarId);
    const list = getGwscSocialList(session?.userId);
    const incoming = list.incoming.filter((entry) => (entry.rockstarId ?? 0) === rockstarId);
    list.incoming = list.incoming.filter((entry) => (entry.rockstarId ?? 0) !== rockstarId);
    if (incoming.length > 0) {
      list.friends.push({ ...incoming[0], online: false });
    }
    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Gwsc friends accept error:", error);
    return res.status(500).json({ error: "Failed to accept friend" });
  }
};

// DELETE /gwsc/api/friends/:rockstarId -> { status }
export const removeGwscFriendHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
    const session = getGwscSession(token);
    const rockstarId = Number(req.params.rockstarId);
    const list = getGwscSocialList(session?.userId);
    list.friends = list.friends.filter((entry) => (entry.rockstarId ?? 0) !== rockstarId);
    list.incoming = list.incoming.filter((entry) => (entry.rockstarId ?? 0) !== rockstarId);
    list.outgoing = list.outgoing.filter((entry) => (entry.rockstarId ?? 0) !== rockstarId);
    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Gwsc friends remove error:", error);
    return res.status(500).json({ error: "Failed to remove friend" });
  }
};

// GET /gwsc/api/achievements -> { achievements: [{ id, at, offline }] }
export const getGwscAchievementsHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
    const session = getGwscSession(token);
    const rockstarId = session?.rockstarId ?? 0;
    return res.json({ achievements: gwscAchievements.get(rockstarId) || [] });
  } catch (error) {
    console.error("Gwsc achievements error:", error);
    return res.status(500).json({ error: "Failed to load achievements" });
  }
};

// POST /gwsc/api/achievements { achievements: [{ id, at, offline }] } -> { achievements }
export const postGwscAchievementsHandler = async (req, res) => {
  try {
    const achievements = req.body?.achievements;
    if (!Array.isArray(achievements)) {
      return res.status(400).json({ error: "Invalid achievements payload" });
    }
    const authHeader = req.headers.authorization || req.headers.Authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
    const session = getGwscSession(token);
    const rockstarId = session?.rockstarId ?? 0;
    gwscAchievements.set(rockstarId, achievements);
    return res.json({ achievements });
  } catch (error) {
    console.error("Gwsc achievements post error:", error);
    return res.status(500).json({ error: "Failed to save achievements" });
  }
};

// GET /gwsc/api/users/:rockstarId/achievements -> { achievements: [{ id, at, offline }] }
export const getGwscUserAchievementsHandler = async (req, res) => {
  try {
    const rockstarId = Number(req.params.rockstarId);
    return res.json({ achievements: gwscAchievements.get(rockstarId) || [] });
  } catch (error) {
    console.error("Gwsc user achievements error:", error);
    return res.status(500).json({ error: "Failed to load user achievements" });
  }
};

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

GwscRouter.get("/info", getGwscInfoHandler);
GwscRouter.get("/me", getGwscMeHandler);
GwscRouter.post("/login", express.json(), loginGwscHandler);
GwscRouter.post("/logout", express.json(), logoutGwscHandler);
GwscRouter.post("/logout-all", express.json(), logoutAllGwscHandler);
GwscRouter.post("/register", express.json(), registerGwscHandler);
GwscRouter.post("/game-launch", express.json(), gameLaunchGwscHandler);
GwscRouter.get("/friends", getGwscFriendsHandler);
GwscRouter.post("/friends", express.json(), addGwscFriendHandler);
GwscRouter.post("/friends/:rockstarId/accept", express.json(), acceptGwscFriendHandler);
GwscRouter.post("/friends/:rockstarId/reject", express.json(), rejectGwscFriendHandler);
GwscRouter.delete("/friends/:rockstarId", express.json(), removeGwscFriendHandler);
GwscRouter.get("/achievements", getGwscAchievementsHandler);
GwscRouter.post("/achievements", express.json(), postGwscAchievementsHandler);
GwscRouter.get("/users/:rockstarId/achievements", getGwscUserAchievementsHandler);
GwscRouter.get("/avatars/presets", avatarsPresetsGwscHandler);
GwscRouter.patch("/me", express.json(), mePatchGwscHandler);
GwscRouter.post("/me/password", express.json(), mePasswordGwscHandler);
GwscRouter.post("/me/avatar/preset", express.json(), meAvatarPresetGwscHandler);
GwscRouter.get("/events", eventsGwscHandler);
GwscRouter.post("/users/:rockstarId/block", express.json(), blockGwscUserHandler);
GwscRouter.delete("/users/:rockstarId/block", express.json(), unblockGwscUserHandler);
GwscRouter.get("/users/:rockstarId/profile", getGwscUserProfileHandler);
