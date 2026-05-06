const crypto = require("crypto");
const SESSION_LIFETIME_MS = 60 * 1000; // 1 minute for testing
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
  if (Date.now() > session.expiresAt) {
    sessions.delete(sessionId);
    return null;
  }
  return session;
}

function deleteSession(sessionId) {
  if (!sessionId) {
    return;
  }
  sessions.delete(sessionId);
}

function getSessionLifetimeMs() {
  return SESSION_LIFETIME_MS;
}

module.exports = {
  createSession,
  getSession,
  deleteSession,
  getSessionLifetimeMs,
};



