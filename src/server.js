const express = require("express");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const https = require("https");  // for https connections with local CA
const fs = require("fs");
const pc = require("picocolors");
const logger = require("./logger");
const measurement = require("./measurement");

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
  verifyRegistrationResponse,
  verifyRefreshResponse,
} = require("./dbsc");

measurement.measurePoint("manual_startup_test", {
  message: "measurement file writing works",
  pid: process.pid
});

function normalizeStructuredHeaderString(value) {
  if (!value) return null;
  // Chrome might send "abc123" or abc123
  return value.replace(/^"(.*)"$/, '$1');
}

const app = express();
const PORT = 3069;

const COOKIE_NAME = "auth_cookie";

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Request logging middleware
app.use((req, res, next) => {
  req.requestId = measurement.newRequestId();
  res.setHeader("X-Request-Id", req.requestId);

  const start = Date.now();


  const httpMeasurement = measurement.startMeasurement("http_request_total", {
    request_id: req.requestId,
    method: req.method,
    url: req.originalUrl || req.url
  });

  
  // Log request
  logger.info("HTTP", pc.cyan(`--> ${req.method} ${req.url}`), {
    request_id: req.requestId
  });
  logger.debug("HTTP", "Headers:", req.headers);
  if (req.body && Object.keys(req.body).length > 0) {
    logger.debug("HTTP", "Body:", req.body);
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
    res.body = Buffer.concat(chunks).toString('utf8');
    return oldEnd.apply(res, args);
  };

  res.on("finish", () => {
    const duration = Date.now() - start;
    const statusColor = res.statusCode >= 400 ? pc.red : (res.statusCode >= 300 ? pc.yellow : pc.green);
    logger.info("HTTP", statusColor(`<-- ${req.method} ${req.url} ${res.statusCode}`) + pc.gray(` - ${duration}ms`), {request_id: req.requestId});
    logger.debug("HTTP", "Headers:", res.getHeaders());
    if (res.body) {
      logger.debug("HTTP", "Body:", res.body);
    }
    measurement.endMeasurement(httpMeasurement, {
      status: res.statusCode,
      result: res.statusCode >= 400 ? "error" : "success"
    });
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

          <label>
            <input type="checkbox" name="use_dbsc" value="true" checked />
            Establish DBSC session
          </label>

          <br><br>

          <button type="submit">Login</button>
        </form>
      </body>
    </html>
  `);
});

app.post("/login", (req, res) => {
  const { username, password, use_dbsc } = req.body;

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

  if (use_dbsc === "true") {
    const registrationChallenge = crypto.randomBytes(32).toString("base64url");
    session.registrationChallenge = registrationChallenge;

    res.setHeader(
        "Secure-Session-Registration",
        `(ES256);path="/dbsc/register";challenge="${registrationChallenge}"`
    );
    logger.info("DBSC", `Registration challenge issued for user=${username}`);
  } else {
    logger.info("DBSC", `DBSC registration skipped for user=${username} (toggle off)`);
  }

  res.redirect("/protected");
});

app.get("/randint", requireAuth, (req, res) => {
  const randomInt = Math.floor(Math.random() * 100) + 1;
  res.json({ value: randomInt });
});

app.get("/protected", requireAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Protected Page</title>
        <meta charset="utf-8" />
        <style>
          body { 
            font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; 
            background-color: #f4f7f6;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            color: #333;
          }
          .card {
            background: white;
            padding: 2rem;
            border-radius: 12px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.1);
            max-width: 400px;
            width: 100%;
            text-align: center;
          }
          h1 { margin-top: 0; font-weight: 600; font-size: 1.5rem; }
          .info { text-align: left; margin: 1.5rem 0; font-size: 0.9rem; color: #666; }
          .info div { margin-bottom: 0.5rem; }
          .info strong { color: #222; }
          .number-container {
            margin-top: 2rem;
            padding: 1.5rem;
            background: #eef2f3;
            border-radius: 8px;
            border: 2px solid #d1d9e6;
          }
          #random-value {
            display: block;
            font-size: 3rem;
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 1rem;
          }
          button {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 0.8rem 1.5rem;
            font-size: 1rem;
            border-radius: 6px;
            cursor: pointer;
            transition: background 0.2s;
          }
          button:hover { background-color: #2980b9; }
          .logout-form { margin-top: 1.5rem; }
          .logout-btn { background-color: transparent; color: #e74c3c; font-size: 0.8rem; border: 1px solid #e74c3c; padding: 0.4rem 0.8rem; }
          .logout-btn:hover { background-color: #fdf2f2; }
        </style>
      </head>
      <body>
        <div class="card">
          <h1>Willkommen</h1>
          
          <div class="info">
            <div>Username: <strong>${req.session.username}</strong></div>
            <div>Session ID: <strong>${req.session.id}</strong></div>
          </div>

          <div class="number-container">
            <span id="random-value">?</span>
            <button id="fetch-btn">Random Zahl holen</button>
          </div>

          <form class="logout-form" method="POST" action="/logout">
            <button type="submit" class="logout-btn">Abmelden</button>
          </form>
        </div>

        <script>
          const valueEl = document.getElementById('random-value');
          const btn = document.getElementById('fetch-btn');

          btn.addEventListener('click', async () => {
            try {
              btn.disabled = true;
              const res = await fetch('/randint');
              const data = await res.json();
              
              valueEl.textContent = data.value;
              
              // Visueller Effekt
              valueEl.style.transform = 'scale(1.2)';
              setTimeout(() => valueEl.style.transform = 'scale(1)', 150);
            } catch (err) {
              console.error('Fetch error:', err);
              valueEl.textContent = 'Err';
            } finally {
              btn.disabled = false;
            }
          });
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
    const { verified, publicKey: extractedKey } = verifyRegistrationResponse(
      secureSessionResponse,
      session.registrationChallenge
    );

    if (verified) {
      publicKey = extractedKey;
      // Clear the challenge after successful verification
      delete session.registrationChallenge;
    } else {
      return res.status(401).json({
        error: "Registration verification failed",
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
      origin: "https://localhost:3069",
      include_site: false,
      scope_specification: [
        {
          type: "include",
          domain: "localhost",
          path: "/protected"
        },
        {
          type: "exclude",
          domain: "localhost",
          path: "/.well-known"
        },
        {
          type: "exclude",
          domain: "localhost",
          path: "/debug"
        },
        {
          type: "exclude",
          domain: "localhost",
          path: "/dbsc"
        },
        // {
        //   type: "exclude",
        //   domain: "localhost",
        //   path: "/refresh"
        // }
      ]
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
  const rawDbscSessionId =
    req.header("Sec-Secure-Session-Id") ||
    req.header("X-DBSC-Session-Id");

  if (!rawDbscSessionId) {
    logger.warn("DBSC", "Refresh failed: Missing Sec-Secure-Session-Id header (or X-DBSC-Session-Id header)");

    return res.status(400).json({
      error: "Missing Sec-Secure-Session-Id header (or X-DBSC-Session-Id header)",
    });
  }

  const dbscSessionId = normalizeStructuredHeaderString(rawDbscSessionId);
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

  const verified = verifyRefreshResponse(secureSessionResponse, dbscSession);
  if (!verified) {
    // If verification failed (e.g. mismatch, expired, or no active challenge),
    // issue a new challenge instead of just 401, to allow Chrome to retry.
    const challenge = createChallenge(dbscSessionId);
    const responseData = {
      message: "Challenge required (retry)",
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

  markRefreshSuccessful(dbscSessionId);

  res.status(200);
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
  logger.info("MAIN", "Measurements enabled? use dev:m", {
    'env.MEASUREMENTS_ENABLED': process.env.MEASUREMENTS_ENABLED ? 'true' : 'false'
  });
});