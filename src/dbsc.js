

const crypto = require("crypto");
const dbscSessions = new Map();

function createDbscSession({ userId, sessionId, publicKey = null }) {
  const dbscSessionId = crypto.randomBytes(32).toString("hex");

  const dbscSession = {
    id: dbscSessionId,
    userId,
    sessionId,
    publicKey,
    createdAt: Date.now(),
    lastRefreshAt: null,
    currentChallenge: null,
    challengeExpiresAt: null,
  };

  dbscSessions.set(dbscSessionId, dbscSession);

  return dbscSession;
}

function getDbscSession(dbscSessionId) {
  if (!dbscSessionId) {
    return null;
  }

  return dbscSessions.get(dbscSessionId) || null;
}

function getAllDbscSessions() {
  return Array.from(dbscSessions.values());
}

function createChallenge(dbscSessionId) {
  const dbscSession = getDbscSession(dbscSessionId);

  if (!dbscSession) {
    return null;
  }

  const challenge = crypto.randomBytes(32).toString("base64url");

  dbscSession.currentChallenge = challenge;
  dbscSession.challengeExpiresAt = Date.now() + 60 * 1000;

  return challenge;
}

function markRefreshSuccessful(dbscSessionId) {
  const dbscSession = getDbscSession(dbscSessionId);

  if (!dbscSession) {
    return null;
  }

  dbscSession.lastRefreshAt = Date.now();
  dbscSession.currentChallenge = null;
  dbscSession.challengeExpiresAt = null;

  return dbscSession;
}

module.exports = {
  createDbscSession,
  getDbscSession,
  getAllDbscSessions,
  createChallenge,
  markRefreshSuccessful,
};