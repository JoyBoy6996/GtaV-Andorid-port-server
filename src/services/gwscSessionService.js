import crypto from "crypto";

/**
 * In-memory session store backing the GTA Online (Gwsc) JSON API used by the
 * Android port client (com.thegwchr.fuzzy).
 *
 * Flow implemented here (mirrors decompiled com.thegwchr.fuzzy.GwscClient usage):
 *   POST /gwsc/api/login     -> issues bearer token + profile
 *   GET  /gwsc/api/me         -> resolves bearer token -> profile
 *   POST /gwsc/api/logout     -> destroys bearer token
 *   POST /gwsc/api/game-launch-> mints launch ticket (`^[A-Za-z0-9_-]{43}$`)
 */
const sessions = new Map();
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // one week

function pruneSessions() {
  const now = Date.now();
  for (const [token, session] of sessions.entries()) {
    if (session.expiresAt < now) {
      sessions.delete(token);
    }
  }
}

function toBase64Url(buffer) {
  return buffer
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function issueGwscSession({ userId = null, email = null, nickname = null, rockstarId = null } = {}) {
  pruneSessions();
  const token = toBase64Url(crypto.randomBytes(32));
  const now = Date.now();
  sessions.set(token, {
    token,
    userId: userId ?? null,
    email: email ?? null,
    nickname: nickname ?? null,
    rockstarId: rockstarId ?? null,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS,
  });
  return token;
}

export function getGwscSession(token) {
  if (!token) {
    return null;
  }
  const session = sessions.get(token);
  if (!session) {
    return null;
  }
  if (session.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return session;
}

export function destroyGwscSession(token) {
  if (!token) {
    return;
  }
  sessions.delete(token);
}

/**
 * Removes every in-memory Gwsc session belonging to a user. Used when an
 * account logs out of all devices (POST /gwsc/api/logout-all).
 */
export function destroyGwscSessionsByUserId(userId) {
  if (!userId) {
    return;
  }
  for (const [token, session] of sessions.entries()) {
    if (session.userId === userId) {
      sessions.delete(token);
    }
  }
}

/**
 * Mints the game launch ticket expected by the Android client:
 * the response of POST /gwsc/api/game-launch must contain a `ticket` value
 * matching ^[A-Za-z0-9_-]{43}$.
 */
export function issueGwscLaunchTicket(session) {
  const ticket = toBase64Url(crypto.randomBytes(32));
  if (session) {
    session.ticket = ticket;
  }
  return ticket;
}
