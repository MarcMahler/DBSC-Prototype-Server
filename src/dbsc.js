const crypto = require("crypto");
const logger = require("./logger");
const dbscSessions = new Map();
const { refreshSession } = require("./sessions");

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

  logger.info("DBSC", `Challenge issued: ${challenge} for session=${dbscSessionId}`);
  return challenge;
}

function markRefreshSuccessful(dbscSessionId) {
  const dbscSession = getDbscSession(dbscSessionId);

  if (!dbscSession) {
    return null;
  }

  dbscSession.lastRefreshAt = Date.now();
  refreshSession(dbscSession.sessionId);
  logger.info("DBSC", `Session renewed: session=${dbscSession.sessionId}`);
  
  // Challenge is cleared inside verifyRefreshResponse after successful verification
  dbscSession.currentChallenge = null;
  dbscSession.challengeExpiresAt = null;

  return dbscSession;
}

/**
 * Parses a compact JWT into its parts.
 */
function parseCompactJwt(jwt) {
  if (typeof jwt !== 'string') return null;
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    logger.warn("DBSC", "Proof received: Invalid JWT format (not 3 parts)");
    return null;
  }

  try {
    const [headerB64, payloadB64, signatureB64] = parts;
    const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
    const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
    const signature = Buffer.from(signatureB64, "base64url");
    const signingInput = headerB64 + "." + payloadB64;

    return { header, payload, signature, signingInput };
  } catch (e) {
    logger.warn("DBSC", `Proof received: Failed to parse JWT: ${e.message}`);
    return null;
  }
}

/**
 * Verifies an ES256 JWT using the provided public key.
 */
function verifyEs256Jwt(jwtParts, publicKey) {
  const { header, signature, signingInput } = jwtParts;

  if (header.typ !== "dbsc+jwt") {
    logger.warn("DBSC", `Invalid typ: ${header.typ}`);
    return false;
  }

  if (header.alg !== "ES256") {
    logger.warn("DBSC", `Invalid alg: ${header.alg}`);
    return false;
  }

  try {
    let keyObj = publicKey;
    if (publicKey && publicKey.kty) {
      keyObj = crypto.createPublicKey({
        key: publicKey,
        format: "jwk",
      });
    }

    const verified = crypto.verify(
      "sha256",
      Buffer.from(signingInput),
      {
        key: keyObj,
        dsaEncoding: "ieee-p1363",
      },
      signature
    );

    if (verified) {
      logger.info("DBSC", "Signature verified");
    } else {
      logger.warn("DBSC", "Signature failed");
    }

    return verified;
  } catch (e) {
    logger.error("DBSC", `Signature verification error: ${e.message}`);
    return false;
  }
}

/**
 * Verify DBSC registration response.
 */
function verifyRegistrationResponse(jwt, expectedChallenge) {
  logger.info("DBSC", "Registration proof received");
  const jwtParts = parseCompactJwt(jwt);
  if (!jwtParts) return { verified: false };

  const { header, payload } = jwtParts;

  if (!header.jwk) {
    logger.warn("DBSC", "Missing jwk during registration");
    return { verified: false };
  }

  if (!payload.jti) {
    logger.warn("DBSC", "Missing jti in registration payload");
    return { verified: false };
  }

  if (payload.jti !== expectedChallenge) {
    logger.warn("DBSC", `Challenge mismatch. Expected: ${expectedChallenge}, got: ${payload.jti}`);
    return { verified: false };
  }

  const verified = verifyEs256Jwt(jwtParts, header.jwk);
  return { verified, publicKey: header.jwk };
}

/**
 * Verify DBSC refresh response.
 */
function verifyRefreshResponse(jwt, dbscSession) {
  logger.info("DBSC", "Refresh proof received");
  const jwtParts = parseCompactJwt(jwt);
  if (!jwtParts) return false;

  const { header, payload } = jwtParts;

  if (header.jwk) {
    logger.warn("DBSC", "Unexpected jwk during refresh, ignoring it");
  }

  if (!payload.jti) {
    logger.warn("DBSC", "Missing jti in refresh payload");
    return false;
  }

  if (!dbscSession.currentChallenge) {
    logger.warn("DBSC", "No active challenge for this DBSC session (possible replay or missing challenge step)");
    return false;
  }

  if (payload.jti !== dbscSession.currentChallenge) {
    logger.warn("DBSC", `Challenge mismatch. Expected: ${dbscSession.currentChallenge}, got: ${payload.jti}`);
    return false;
  }

  if (Date.now() > dbscSession.challengeExpiresAt) {
    logger.warn("DBSC", "Challenge expired");
    return false;
  }

  const verified = verifyEs256Jwt(jwtParts, dbscSession.publicKey);
  
  if (verified) {
    logger.info("DBSC", `Challenge consumed: ${dbscSession.currentChallenge}`);
    dbscSession.currentChallenge = null;
    dbscSession.challengeExpiresAt = null;
  }

  return verified;
}

module.exports = {
  createDbscSession,
  getDbscSession,
  getAllDbscSessions,
  createChallenge,
  markRefreshSuccessful,
  parseCompactJwt,
  verifyEs256Jwt,
  verifyRegistrationResponse,
  verifyRefreshResponse,
};