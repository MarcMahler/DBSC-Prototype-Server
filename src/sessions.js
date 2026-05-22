const crypto = require("crypto");
const logger = require("./logger");
const SESSION_LIFETIME_MS = 3 * 60 * 1000 ; // 3 min
const sessions = new Map();

function createSession(username) {
  const sessionId = crypto.randomBytes(32).toString("hex");

  const session = {
    id: sessionId,
    username,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_LIFETIME_MS,
  };

  sessions.set(sessionId, session);
  logger.info("SESSION", `Created session=${sessionId} for user=${username}`);
  return session;
}

function getSession(sessionId) {
  if (!sessionId) {
    return null;
  }
  const session = sessions.get(sessionId);
  if (!session) {
    return null;
  }
  return session;
}

function deleteSession(sessionId) {
  if (!sessionId) {
    return;
  }
  sessions.delete(sessionId);
  logger.info("SESSION", `Deleted session=${sessionId}`);
}

function getSessionLifetimeMs() {
  return SESSION_LIFETIME_MS;
}
function refreshSession(sessionId) {
  const session = sessions.get(sessionId);
  if (!session) {
    logger.warn("SESSION", `Failed to refresh: session=${sessionId} not found`);
    return null;
  }
  session.expiresAt = Date.now() + SESSION_LIFETIME_MS;
  logger.info("SESSION", `Refreshed session=${sessionId}. New expiry: ${new Date(session.expiresAt).toISOString()}`);
  return session;
}

module.exports = {
  createSession,
  getSession,
  deleteSession,
  getSessionLifetimeMs,
  refreshSession
};



