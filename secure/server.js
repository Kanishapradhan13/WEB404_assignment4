// SECURE VERSION - rewritten to remove the injection points demonstrated
// in vulnerable/server.js. Same routes and behaviour for legitimate input.
//
// Defences applied here:
//   1. Parameterised queries / prepared statements (primary defence).
//      User input is always bound as a parameter, never concatenated into
//      the SQL string, so the database driver treats it strictly as data.
//   2. Input validation at the boundary (allowlist pattern, length limits)
//      before the input ever reaches the query layer. This is a defence
//      in depth measure, not a substitute for parameterisation.
//   3. Generic error responses - no raw database error text is returned
//      to the client, removing the error-based SQLi information leak.
//
// Operational notes (not implemented in this local demo, documented for
// the report):
//   - The database account used by the application should be a
//     least-privilege account: SELECT-only on `products`, and SELECT-only
//     on `users` for authentication, with no DDL/DROP/ALTER rights and no
//     access to any other schema. SQLite has no user/role model, so this
//     applies when the same logic is deployed against MySQL/Postgres.
//   - A Web Application Firewall (WAF) can be layered in front of this
//     application as defence in depth, to detect and block common SQLi
//     signatures (UNION SELECT, OR 1=1, comment sequences) before they
//     reach the application. It is not a substitute for parameterised
//     queries, since custom or obfuscated payloads can bypass signatures.

const path = require("path");
const express = require("express");
const Database = require("better-sqlite3");

const db = new Database(path.join(__dirname, "app.db"));
const app = express();
const PORT = 3002;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get("/", (req, res) => {
  res.send(`
    <h1>Secure Demo App (port ${PORT})</h1>
    <ul>
      <li><a href="/login">Login form</a></li>
      <li><a href="/search">Product search</a></li>
    </ul>
  `);
});

// ---------- Input validation helpers ----------

// Allowlist: letters, digits, underscore, hyphen, dot - typical for usernames.
const USERNAME_PATTERN = /^[A-Za-z0-9_.-]{1,32}$/;
// Passwords can contain more characters, but length is bounded and type is enforced.
const MAX_PASSWORD_LENGTH = 128;
// Search terms: bounded length, restricted character set (letters, digits, spaces, basic punctuation).
const SEARCH_PATTERN = /^[A-Za-z0-9 _.-]{0,64}$/;

function isValidUsername(value) {
  return typeof value === "string" && USERNAME_PATTERN.test(value);
}

function isValidPassword(value) {
  return typeof value === "string" && value.length > 0 && value.length <= MAX_PASSWORD_LENGTH;
}

function isValidSearchTerm(value) {
  return typeof value === "string" && SEARCH_PATTERN.test(value);
}

// ---------- LOGIN (parameterised) ----------

app.get("/login", (req, res) => {
  res.send(`
    <h1>Login (secure)</h1>
    <form method="POST" action="/login">
      <input name="username" placeholder="username" /><br/>
      <input name="password" placeholder="password" type="password" /><br/>
      <button type="submit">Log in</button>
    </form>
  `);
});

app.post("/login", (req, res) => {
  const { username = "", password = "" } = req.body;

  if (!isValidUsername(username) || !isValidPassword(password)) {
    return res.status(400).json({ outcome: "INVALID_INPUT" });
  }

  // SECURE: parameterised query. The placeholders are bound as data,
  // never concatenated into the SQL text, so injection payloads cannot
  // change the query structure.
  const stmt = db.prepare("SELECT id, username, role FROM users WHERE username = ? AND password = ?");

  try {
    const row = stmt.get(username, password);
    if (row) {
      res.status(200).json({ outcome: "AUTHENTICATED", user: row });
    } else {
      res.status(401).json({ outcome: "REJECTED" });
    }
  } catch (err) {
    // SECURE: no raw error detail leaked to the client.
    console.error("Login query failed:", err.message);
    res.status(500).json({ outcome: "SERVER_ERROR" });
  }
});

// ---------- PRODUCT SEARCH (parameterised) ----------

app.get("/search", (req, res) => {
  res.send(`
    <h1>Product Search (secure)</h1>
    <form method="GET" action="/api/search">
      <input name="q" placeholder="product name" /><br/>
      <button type="submit">Search</button>
    </form>
  `);
});

app.get("/api/search", (req, res) => {
  const q = req.query.q || "";

  if (!isValidSearchTerm(q)) {
    return res.status(400).json({ outcome: "INVALID_INPUT" });
  }

  // SECURE: parameterised LIKE query. The % wildcards are applied to the
  // bound value in JavaScript, not spliced into the SQL string.
  const stmt = db.prepare("SELECT id, name, category, price FROM products WHERE name LIKE ?");
  const likeValue = `%${q}%`;

  try {
    const rows = stmt.all(likeValue);
    res.status(200).json({ outcome: "OK", count: rows.length, rows });
  } catch (err) {
    console.error("Search query failed:", err.message);
    res.status(500).json({ outcome: "SERVER_ERROR" });
  }
});

app.listen(PORT, () => {
  console.log(`Secure app listening on http://localhost:${PORT}`);
});
