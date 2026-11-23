import express from "express";
import bcrypt from "bcrypt";
import { prisma, sendLogMessage } from "../../main.js";
import {
  getGwscSession,
  destroyGwscSession,
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

// Simple in-memory social graph / achievements store keyed by user / rockstar id.
const gwscSocialLists = new Map(); // userId -> { friends, incoming, outgoing }
const gwscAchievements = new Map(); // rockstarId -> [{ id, at, offline }]

function getGwscSocialList(userId) {
  let list = gwscSocialLists.get(userId);
  if (!list) {
    list = { friends: [], incoming: [], outgoing: [] };
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
    return res.status(500).json({ error: "Failed to load server info" });
  }
};

// GET /gwsc/api/me -> { token, profile: { nickname, rockstarId, email } }
export const getGwscMeHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
    const session = getGwscSession(token);
    if (!session) {
      return res.status(401).json({ error: "Session not found" });
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
      return res.status(400).json({ error: "Invalid email or password" });
    }
    const user = await prisma.user.findFirst({ where: { email } });
    if (!user || !user.PCPassword || !(await bcrypt.compare(password, user.PCPassword))) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    if (user.banned) {
      return res.status(403).json({ error: "User banned" });
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
    const authHeader = req.headers.authorization || req.headers.Authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
    destroyGwscSession(token);
    return res.json({ status: "ok" });
  } catch (error) {
    return res.status(500).json({ error: "Logout failed" });
  }
};

// POST /gwsc/api/game-launch -> { ticket } (ticket must match ^[A-Za-z0-9_-]{43}$)
export const gameLaunchGwscHandler = async (req, res) => {
  try {
    const token = extractLaunchToken(req.body);
    const session = getGwscSession(token);
    if (!session) {
      return res.status(401).json({ error: "Session not found" });
    }
    const ticket = issueGwscLaunchTicket(session);
    return res.json({ ticket });
  } catch (error) {
    console.error("Gwsc game-launch error:", error);
    return res.status(500).json({ error: "Failed to create game launch ticket" });
  }
};

// GET /gwsc/api/friends -> { friends: [{ rockstarId, online, nickname }], incoming, outgoing }
export const getGwscFriendsHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
    const session = getGwscSession(token);
    if (!session?.userId) {
      return res.status(401).json({ error: "Session not found" });
    }
    const list = getGwscSocialList(session.userId);
    return res.json({
      friends: list.friends.map(toFriendEntry),
      incoming: list.incoming.map(toFriendEntry),
      outgoing: list.outgoing.map(toFriendEntry),
    });
  } catch (error) {
    console.error("Gwsc friends error:", error);
    return res.status(500).json({ error: "Failed to load friends" });
  }
};

// POST /gwsc/api/friends { nickname } -> { status }
export const addGwscFriendHandler = async (req, res) => {
  try {
    const authHeader = req.headers.authorization || req.headers.Authorization || "";
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
    const session = getGwscSession(token);
    const nickname = (req.body?.nickname || "").trim();
    if (!session?.userId || !nickname) {
      return res.status(400).json({ error: "Invalid friend request" });
    }
    const list = getGwscSocialList(session.userId);
    list.outgoing.push({ rockstarId: 0, online: false, nickname });
    return res.json({ status: "ok" });
  } catch (error) {
    console.error("Gwsc friends add error:", error);
    return res.status(500).json({ error: "Failed to add friend" });
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
GwscRouter.post("/game-launch", express.json(), gameLaunchGwscHandler);
GwscRouter.get("/friends", getGwscFriendsHandler);
GwscRouter.post("/friends", express.json(), addGwscFriendHandler);
GwscRouter.post("/friends/:rockstarId/accept", express.json(), acceptGwscFriendHandler);
GwscRouter.delete("/friends/:rockstarId", express.json(), removeGwscFriendHandler);
GwscRouter.get("/achievements", getGwscAchievementsHandler);
GwscRouter.post("/achievements", express.json(), postGwscAchievementsHandler);
GwscRouter.get("/users/:rockstarId/achievements", getGwscUserAchievementsHandler);
