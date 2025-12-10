const express = require("express");
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const app = express();
const PORT = 3001;

// Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static("public"));

// -----------------------------------------------------------------------------
// USER DATABASE (bcrypt-secured)
// -----------------------------------------------------------------------------
const users = [
  {
    id: 1,
    username: "student",
    passwordHash: bcrypt.hashSync("password123", 10) // bcrypt salted hash
  }
];

// -----------------------------------------------------------------------------
// SESSION STORE
// -----------------------------------------------------------------------------
const sessions = {}; // token -> { userId, expiresAt }

// Create a strong, unpredictable session token
function createSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

// Retrieve and validate a session from the request
function loadSession(req) {
  const token = req.cookies.session;
  if (!token) return null;

  const session = sessions[token];
  if (!session) return null;

  // Expired -> remove it
  if (Date.now() >= session.expiresAt) {
    delete sessions[token];
    return null;
  }

  return session;
}

// -----------------------------------------------------------------------------
// AUTHENTICATION ENDPOINTS
// -----------------------------------------------------------------------------

// Returns info about the currently authenticated user
app.get("/api/me", (req, res) => {
  const session = loadSession(req);
  if (!session) {
    return res.status(401).json({ authenticated: false });
  }

  const user = users.find((u) => u.id === session.userId);
  return res.json({ authenticated: true, username: user.username });
});

// Login endpoint (secure)
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  // Find user without leaking which part is incorrect
  const account = users.find((u) => u.username === username);
  if (!account) {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }

  // Validate password using bcrypt
  const passwordsMatch = await bcrypt.compare(password, account.passwordHash);
  if (!passwordsMatch) {
    return res.status(401).json({ success: false, message: "Invalid credentials" });
  }

  // Create session + expiration
  const token = createSessionToken();
  sessions[token] = {
    userId: account.id,
    expiresAt: Date.now() + 30 * 60 * 1000 // 30 minutes
  };

  // Secure cookie
  res.cookie("session", token, {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    maxAge: 30 * 60 * 1000
  });

  return res.json({ success: true });
});

// Logout endpoint
app.post("/api/logout", (req, res) => {
  const token = req.cookies.session;
  if (token) {
    delete sessions[token];
  }

  res.clearCookie("session");
  return res.json({ success: true });
});

// -----------------------------------------------------------------------------
// SERVER START
// -----------------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`FastBank Auth Lab (Hardened Version) running at http://localhost:${PORT}`);
});
