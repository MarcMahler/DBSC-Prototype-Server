const express = require("express");
const cookieParser = require("cookie-parser");

const https = require("https");  // for https connections with local CA
const fs = require("fs");

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
} = require("./dbsc");

const app = express();
const PORT = 3000;

const COOKIE_NAME = "auth_cookie";

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

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

  console.log(
      `[LOGIN] user=${username}, session=${session.id}, expiresAt=${new Date(
          session.expiresAt
      ).toISOString()}`
  );

  res.redirect("/protected");
});

app.get("/protected", requireAuth, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
      <head>
        <title>Protected Page</title>
      </head>
      <body>
        <h1>Protected Page</h1>

        <p>Hello, <strong>${req.session.username}</strong>.</p>
        <p>This page is only accessible with a valid session cookie.</p>

        <h3>Session information</h3>
        <pre>${JSON.stringify(
      {
        sessionId: req.session.id,
        createdAt: new Date(req.session.createdAt).toISOString(),
        expiresAt: new Date(req.session.expiresAt).toISOString(),
      },
      null,
      2
  )}</pre>

        <form method="POST" action="/logout">
          <button type="submit">Logout</button>
        </form>
      </body>
    </html>
  `);
});

app.post("/logout", (req, res) => {
  const sessionId = req.cookies[COOKIE_NAME];

  if (sessionId) {
    deleteSession(sessionId);
    console.log(`[LOGOUT] session=${sessionId}`);
  }

  res.clearCookie(COOKIE_NAME);
  res.redirect("/login");
});

// -------------------- DBSC ----------------------------

// DBSC registration endpoint
app.post("/dbsc/register", (req, res) => {
  console.log("[DBSC REGISTER] Request received");
  console.log("[DBSC REGISTER] Headers:", req.headers);

  const sessionId = req.cookies[COOKIE_NAME];
  const session = getSession(sessionId);

  if (!session) {
    console.log("[DBSC REGISTER] No valid auth session found");
    return res.status(401).json({
      error: "No valid auth session found",
    });
  }

  const dbscSession = createDbscSession({
    userId: session.username,
    sessionId: session.id,
    publicKey: null,
  });

  console.log(
      `[DBSC REGISTER] Created DBSC session=${dbscSession.id} for user=${session.username}`
  );

  res.status(200).json({
    message: "DBSC registration endpoint reached",
    dbscSessionId: dbscSession.id,
  });
});

// DBSC refresh endpoint
app.post("/dbsc/refresh", (req, res) => {
  console.log("[DBSC REFRESH] Request received");
  console.log("[DBSC REFRESH] Headers:", req.headers);

  const dbscSessionId =
      req.header("Sec-Secure-Session-Id") ||
      req.header("X-DBSC-Session-Id");

  if (!dbscSessionId) {
    console.log("[DBSC REFRESH] Missing Sec-Secure-Session-Id header (or X-DBSC-Session-Id header)");

    return res.status(400).json({
      error: "Missing Sec-Secure-Session-Id header (or X-DBSC-Session-Id header)",
    });
  }

  const dbscSession = getDbscSession(dbscSessionId);

  if (!dbscSession) {
    console.log(`[DBSC REFRESH] Unknown DBSC session=${dbscSessionId}`);

    return res.status(404).json({
      error: "Unknown DBSC session",
    });
  }

  const secureSessionResponse = req.header("Secure-Session-Response");

  if (!secureSessionResponse) {
    const challenge = createChallenge(dbscSessionId);

    console.log(
        `[DBSC REFRESH] Challenge issued for DBSC session=${dbscSessionId}`
    );

    return res
        .status(403)
        .set("Secure-Session-Challenge", challenge)
        .json({
          message: "Challenge required",
          dbscSessionId,
          challenge,
        });
  }

  // Placeholder only.
  // Later, this is where the signature/JWT from Chrome will be verified.
  console.log("[DBSC REFRESH] Secure-Session-Response received");
  console.log("[DBSC REFRESH] Signature verification not implemented yet");

  markRefreshSuccessful(dbscSessionId);

  res.status(200).json({
    message: "Refresh endpoint reached, but signature verification is not implemented yet",
    dbscSessionId,
  });
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
  console.log(`DBSC prototype server running at https://localhost:${PORT}`);
});