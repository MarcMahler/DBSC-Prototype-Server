const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const https = require("https");  // for https connections with local CA
const fs = require("fs");
const pc = require("picocolors");
const logger = require("./logger");

const {
  createSession,
  getSession,
  deleteSession,
  getSessionLifetimeMs,
} = require("./sessions");

const {
  createDbscSession,
  getDbscSession,
  getAllDbscSessions,
  createChallenge,
  markRefreshSuccessful,
  verifyDbscJwt,
} = require("./dbsc");

const app = express();
const PORT = 3000;

const COOKIE_NAME = "auth_cookie";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Request logging middleware
app.use((req, res, next) => {
  const start = Date.now();
  
  // Log request
  logger.info("HTTP", pc.cyan(`--> ${req.method} ${req.url}`));
  logger.info("HTTP", "Headers:", req.headers);
  if (req.body && Object.keys(req.body).length > 0) {
    logger.info("HTTP", "Body:", req.body);
  }

  // Intercept response body
  const oldWrite = res.write;
  const oldEnd = res.end;
  const chunks = [];

  res.write = (...args) => {
    chunks.push(Buffer.from(args[0]));
    return oldWrite.apply(res, args);
  };

  res.end = (...args) => {
    if (args[0]) {
      chunks.push(Buffer.from(args[0]));
    }
    const body = Buffer.concat(chunks).toString('utf8');
    res.body = body;
    return oldEnd.apply(res, args);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    const statusColor = res.statusCode >= 400 ? pc.red : (res.statusCode >= 300 ? pc.yellow : pc.green);
    logger.info("HTTP", statusColor(`<-- ${req.method} ${req.url} ${res.statusCode}`) + pc.gray(` - ${duration}ms`));
    logger.info("HTTP", "Headers:", res.getHeaders());
    if (res.body) {
      logger.info("HTTP", "Body:", res.body);
    }
  });
  next();
});

function requireAuth(req, res, next) {
  const sessionId = req.cookies[COOKIE_NAME];
  const session = getSession(sessionId);

  if (!session) {
    return res.redirect("/login");
  }

  req.session = session;
  next();
}

app.get("/", (req, res) => {
  res.redirect("/protected");
});

app.get("/login", (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>DBSC Prototype Login</title>
      </head>
      <body>
        <h1>DBSC Prototype</h1>
        <h2>Login</h2>

        <form method="POST" action="/login">
          <label>Username</label>
          <input name="username" value="alice" />

          <br><br>

          <label>Password</label>
          <input name="password" type="password" value="password" />

          <br><br>

          <button type="submit">Login</button>
        </form>
      </body>
    </html>
  `);
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (username !== "alice" || password !== "password") {
    return res.status(401).send("Invalid credentials");
  }

  const session = createSession(username);

  res.cookie(COOKIE_NAME, session.id, {
    httpOnly: true,
    sameSite: "Lax",
    maxAge: getSessionLifetimeMs(),
    secure: true, // enable later when using HTTPS
  });

  const registrationChallenge = crypto.randomBytes(32).toString("base64url");
  session.registrationChallenge = registrationChallenge;

  res.setHeader(
      "Secure-Session-Registration",
      `(ES256);path="/dbsc/register";challenge="${registrationChallenge}"`
  );
  logger.info("DBSC", `Registration challenge issued for user=${username}`);
  res.redirect("/protected");
});

app.get("/protected", requireAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Protected Page</title>
        <meta charset="utf-8" />
        <style>
          body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; line-height: 1.4; padding: 20px;}
          pre, code { background: #f6f8fa; border: 1px solid #e5e7eb; border-radius: 4px; }
          pre { padding: 8px; overflow: auto; }
          code { padding: 2px 4px; }
          section { margin-top: 20px; padding-top: 12px; border-top: 1px solid #e5e7eb; }
          .actions button { margin-right: 8px; padding: 4px 8px; border: 1px solid #e5e7eb; border-radius: 4px; cursor: pointer; margin-top: 20px; margin-bottom: 20px; background: rgba(129,240,244,0.85); }
          h4 { margin: 30px 0 10px 0 }
        </style>
      </head>
      <body>
        <h1>Protected Page</h1>

        <p>Hello, <strong>${req.session.username}</strong>.</p>
        <p>This page is only accessible with a valid session cookie.</p>

        <section id="auth">
          <h2>Session information</h2>
          <pre>${JSON.stringify(
      {
        sessionId: req.session.id,
        createdAt: new Date(req.session.createdAt).toISOString(),
        expiresAt: new Date(req.session.expiresAt).toISOString(),
      },
      null,
      2
  )}</pre>
        </section>

        <section id="dbsc">
          <h2>DBSC</h2>
          <div>Current DBSC session id: <code id="dbsc-id">—</code></div>
          <div class="actions">
            <button id="dbsc-register" type="button">Register</button>
            <button id="dbsc-refresh" type="button">Refresh</button>
          </div>
          <h4>Session Info</h4>
          <pre id="dbsc-info">—</pre>
          <h4>Challenge</h4>
          <pre id="dbsc-challenge">—</pre>
          <h4>Last Response</h4>
          <pre id="dbsc-last">—</pre>
        </section>

        <section id="logout">
          <form method="POST" action="/logout">
            <button type="submit">Logout</button>
          </form>
        </section>

        <script>
          (function () {
            const $ = (id) => document.getElementById(id);
            const setText = (id, v) => { const el = $(id); if (el) el.textContent = (v == null || v === '') ? '—' : String(v); };
            const setJSON = (id, obj) => setText(id, obj == null ? '—' : JSON.stringify(obj, null, 2));

            const currentUser = '${req.session.username}';
            const currentAuthSessionId = '${req.session.id}';
            let dbscSessionId = localStorage.getItem('dbscSessionId') || null;

            function persist(id) {
              dbscSessionId = id || null;
              if (dbscSessionId) localStorage.setItem('dbscSessionId', dbscSessionId);
              else localStorage.removeItem('dbscSessionId');
              setText('dbsc-id', dbscSessionId || '—');
            }

            async function loadStatus() {
              try {
                const res = await fetch('/debug/dbsc', { credentials: 'same-origin' });
                const data = await res.json();
                const mine = (data.sessions || []).filter(s => s.userId === currentUser || s.sessionId === currentAuthSessionId);
                let selected = null;
                if (mine.length) {
                  selected = mine.find(s => s.id === dbscSessionId) || mine[0];
                  if (!dbscSessionId || selected.id !== dbscSessionId) persist(selected.id);
                } else {
                  persist(null);
                }
                setJSON('dbsc-info', selected || { info: 'No DBSC session yet.' });
              } catch (e) {
                setJSON('dbsc-info', { error: String(e) });
              }
            }

            async function registerDbsc() {
              setText('dbsc-challenge', '—');
              setJSON('dbsc-last', { status: 'loading...' });
              try {
                const res = await fetch('/dbsc/register', { method: 'POST', credentials: 'same-origin' });
                const body = await res.json().catch(() => null);
                setJSON('dbsc-last', { status: res.status, body });
                if (res.ok && body && body.dbscSessionId) {
                  persist(body.dbscSessionId);
                  await loadStatus();
                }
              } catch (e) {
                setJSON('dbsc-last', { error: String(e) });
              }
            }

            async function refreshDbsc() {
              setJSON('dbsc-last', { status: 'loading...' });
              setText('dbsc-challenge', '—');
              if (!dbscSessionId) {
                setJSON('dbsc-last', { error: 'No DBSC session id. Please register first.' });
                return;
              }
              try {
                const res = await fetch('/dbsc/refresh', {
                  method: 'POST',
                  credentials: 'same-origin',
                  headers: { 'X-DBSC-Session-Id': dbscSessionId }
                });
                const challenge = res.headers.get('Secure-Session-Challenge');
                if (challenge) setText('dbsc-challenge', challenge);
                const body = await res.json().catch(() => null);
                setJSON('dbsc-last', { status: res.status, headers: { 'Secure-Session-Challenge': challenge }, body });
                if (res.ok) loadStatus();
              } catch (e) {
                setJSON('dbsc-last', { error: String(e) });
              }
            }

            $('dbsc-register').addEventListener('click', registerDbsc);
            $('dbsc-refresh').addEventListener('click', refreshDbsc);

            setText('dbsc-id', dbscSessionId || '—');
            loadStatus();
          })();
        </script>
      </body>
    </html>
  `);
});

app.post("/logout", (req, res) => {
  const sessionId = req.cookies[COOKIE_NAME];

  if (sessionId) {
    deleteSession(sessionId);
    logger.info("AUTH", `Logout: session=${sessionId}`);
  }

  res.clearCookie(COOKIE_NAME);
  res.redirect("/login");
});

// -------------------- DBSC ----------------------------

// DBSC registration endpoint
app.post("/dbsc/register", (req, res) => {
  const sessionId = req.cookies[COOKIE_NAME];
  const session = getSession(sessionId);

  if (!session) {
    logger.warn("DBSC", "Registration failed: No valid auth session found");
    return res.status(401).json({
      error: "No valid auth session found",
    });
  }

  const secureSessionResponse = req.header("Secure-Session-Response");
  let publicKey = null;

  if (secureSessionResponse) {
    try {
      // Mock dbscSession object to provide the registration challenge to verifyDbscJwt
      const mockDbscSession = {
        currentChallenge: session.registrationChallenge
      };

      const { verified, publicKey: extractedKey } = verifyDbscJwt(secureSessionResponse, mockDbscSession);
      if (verified) {
        publicKey = extractedKey;
        logger.info("DBSC", "Registration Secure-Session-Response verified successfully");
        // Clear the challenge after successful verification
        delete session.registrationChallenge;
      } else {
        logger.warn("DBSC", "Registration Secure-Session-Response verification failed (challenge mismatch or signature error)");
        return res.status(401).json({
          error: "Registration verification failed",
        });
      }
    } catch (e) {
      logger.error("DBSC", `Error verifying Registration Secure-Session-Response: ${e.message}`);
      return res.status(400).json({
        error: "Error verifying registration: " + e.message,
      });
    }
  } else {
    logger.warn("DBSC", "Registration failed: Missing Secure-Session-Response header");
    return res.status(400).json({
      error: "Missing Secure-Session-Response header",
    });
  }

  const dbscSession = createDbscSession({
    userId: session.username,
    sessionId: session.id,
    publicKey: publicKey,
  });

  logger.info("DBSC", `Created DBSC session=${dbscSession.id} for user=${session.username}`);

  const responseData = {
    session_identifier: dbscSession.id,
    refresh_url: "/dbsc/refresh",
    scope: {
      origin: "https://localhost:3000",
      include_site: false,
    },
    credentials: [
      {
        type: "cookie",
        name: COOKIE_NAME,
        attributes: "Path=/; Secure; HttpOnly; SameSite=Lax",
      },
    ],
  };

  res.setHeader("Cache-Control", "no-store");
  
  // Re-set the auth cookie to match DBSC credentials and ensure it's fresh
  res.cookie(COOKIE_NAME, session.id, {
    httpOnly: true,
    sameSite: "Lax",
    maxAge: getSessionLifetimeMs(),
    secure: true,
    path: "/",
  });

  res.status(200).json(responseData);
});

// DBSC refresh endpoint
app.post("/dbsc/refresh", (req, res) => {
  const dbscSessionId =
      req.header("Sec-Secure-Session-Id") ||
      req.header("X-DBSC-Session-Id");

  if (!dbscSessionId) {
    logger.warn("DBSC", "Refresh failed: Missing Sec-Secure-Session-Id header (or X-DBSC-Session-Id header)");

    return res.status(400).json({
      error: "Missing Sec-Secure-Session-Id header (or X-DBSC-Session-Id header)",
    });
  }

  const dbscSession = getDbscSession(dbscSessionId);

  if (!dbscSession) {
    logger.warn("DBSC", `Refresh failed: Unknown DBSC session=${dbscSessionId}`);

    return res.status(404).json({
      error: "Unknown DBSC session",
    });
  }

  const secureSessionResponse = req.header("Secure-Session-Response");

  if (!secureSessionResponse) {
    const challenge = createChallenge(dbscSessionId);

    logger.info("DBSC", `Refresh challenge issued for DBSC session=${dbscSessionId}`);

    const responseData = {
      message: "Challenge required",
      dbscSessionId,
      challenge,
    };

    return res
        .status(403)
        .set(
            "Secure-Session-Challenge",
            `"${challenge}";id="${dbscSessionId}"`
        )
        .set("Cache-Control", "no-store")
        .json(responseData);
  }

  logger.info("DBSC", "Secure-Session-Response received");

  try {
    const { verified } = verifyDbscJwt(secureSessionResponse, dbscSession);
    if (!verified) {
      logger.warn("DBSC", "Refresh failed: Signature verification failed");
      return res.status(401).json({
        error: "Signature verification failed",
      });
    }
    logger.info("DBSC", "Signature verified successfully");
  } catch (e) {
    logger.error("DBSC", `Error verifying signature: ${e.message}`);
    return res.status(400).json({
      error: "Error verifying signature: " + e.message,
    });
  }

  markRefreshSuccessful(dbscSessionId);

  const responseData = {
    message: "Refresh successful",
    dbscSessionId,
  };

  res.status(200)
  res.setHeader("Cache-Control", "no-store");
  res.cookie(COOKIE_NAME, dbscSession.sessionId, {
    httpOnly: true,
    sameSite: "Lax",
    maxAge: getSessionLifetimeMs(),
    secure: true,
    path: "/",
  });

  res.end();
});


// DBSC debug endpoint
app.get("/debug/dbsc", (req, res) => {
  const sessions = getAllDbscSessions().map((session) => ({
    id: session.id,
    userId: session.userId,
    sessionId: session.sessionId,
    hasPublicKey: Boolean(session.publicKey),
    createdAt: new Date(session.createdAt).toISOString(),
    lastRefreshAt: session.lastRefreshAt
        ? new Date(session.lastRefreshAt).toISOString()
        : null,
    hasCurrentChallenge: Boolean(session.currentChallenge),
    challengeExpiresAt: session.challengeExpiresAt
        ? new Date(session.challengeExpiresAt).toISOString()
        : null,
  }));

  res.json({
    dbscSessionCount: sessions.length,
    sessions,
  });
});


// ------------------------------ Server starting code -----------------------------------------------

//
// with HTTPS and local CA

const httpsOptions = {
  key: fs.readFileSync("certs/localhost-key.pem"),
  cert: fs.readFileSync("certs/localhost.pem"),
};

https.createServer(httpsOptions, app).listen(PORT, () => {
  logger.info("SERVER", `DBSC prototype server running at https://localhost:${PORT}`);
});