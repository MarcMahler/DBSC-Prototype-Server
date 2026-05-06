const express = require("express");
const cookieParser = require("cookie-parser");

const {
  createSession,
  getSession,
  deleteSession,
  getSessionLifetimeMs,
} = require("./sessions");

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
    <html>
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
    // secure: true, // enable later when using HTTPS
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
    <html>
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

app.listen(PORT, () => {
  console.log(`DBSC prototype server running at http://localhost:${PORT}`);
});