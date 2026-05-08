

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

/**
 * Decodes and verifies a DBSC JWT.
 * @param {string} jwt 
 * @param {Object|null} expectedPublicKey JWK or KeyObject. If null, extracts from JWT header.
 * @returns {Object} { header, payload, verified, publicKey }
 */
function verifyDbscJwt(jwt, expectedPublicKey = null) {
  const parts = jwt.split(".");
  if (parts.length !== 3) {
    throw new Error("Invalid JWT format");
  }

  const [headerB64, payloadB64, signatureB64] = parts;
  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString());
  const payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString());
  const signature = Buffer.from(signatureB64, "base64url");
  const data = Buffer.from(headerB64 + "." + payloadB64);

  let publicKey = expectedPublicKey;
  if (!publicKey && header.jwk) {
    publicKey = crypto.createPublicKey({
      key: header.jwk,
      format: "jwk",
    });
  } else if (publicKey && publicKey.kty) {
    // If it's a JWK object
    publicKey = crypto.createPublicKey({
      key: publicKey,
      format: "jwk",
    });
  }

  if (!publicKey) {
    throw new Error("No public key available for verification");
  }

  // DBSC signatures might use raw format (R || S) instead of DER
  let signatureToVerify = signature;
  if (header.alg === "ES256" && signature.length === 64) {
    const r = signature.slice(0, 32);
    const s = signature.slice(32, 64);

    // Convert to DER format: 0x30 <len> 0x02 <len_r> <r> 0x02 <len_s> <s>
    const encodeInteger = (buf) => {
      let start = 0;
      while (start < buf.length && buf[start] === 0) start++;
      let len = buf.length - start;
      if (buf[start] >= 0x80) len++;

      const out = Buffer.alloc(2 + len);
      out[0] = 0x02;
      out[1] = len;
      if (buf[start] >= 0x80) {
        out[2] = 0x00;
        buf.copy(out, 3, start);
      } else {
        buf.copy(out, 2, start);
      }
      return out;
    };

    const rDer = encodeInteger(r);
    const sDer = encodeInteger(s);
    signatureToVerify = Buffer.concat([
      Buffer.from([0x30, rDer.length + sDer.length]),
      rDer,
      sDer,
    ]);
  }

  const verified = crypto.verify(
    null, // Algorithm is determined by the key
    data,
    publicKey,
    signatureToVerify
  );

  return {
    header,
    payload,
    verified,
    publicKey: header.jwk, // Return the JWK for storage
  };
}

module.exports = {
  createDbscSession,
  getDbscSession,
  getAllDbscSessions,
  createChallenge,
  markRefreshSuccessful,
  verifyDbscJwt,
};