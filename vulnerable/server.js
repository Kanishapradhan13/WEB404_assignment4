// VULNERABLE VERSION - for isolated local demonstration only.
// Builds SQL queries by concatenating raw user input into the query string.
// Do not deploy. Do not expose to any network. Educational use only.

const path = require("path");
const express = require("express");
const Database = require("better-sqlite3");

const db = new Database(path.join(__dirname, "app.db"));
const app = express();
const PORT = 3001;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.get("/", (req, res) => {
  res.send(`
    <h1>Vulnerable Demo App (port ${PORT})</h1>
    <ul>
      <li><a href="/login">Login form</a></li>
      <li><a href="/search">Product search</a></li>
    </ul>
  `);
});

// ---------- LOGIN (vulnerable to authentication bypass) ----------

app.get("/login", (req, res) => {
  res.send(`
    <h1>Login (vulnerable)</h1>
    <form method="POST" action="/login">
      <input name="username" placeholder="username" /><br/>
      <input name="password" placeholder="password" type="password" /><br/>
      <button type="submit">Log in</button>
    </form>
  `);
});

app.post("/login", (req, res) => {
  const { username = "", password = "" } = req.body;

  // VULNERABLE: raw string concatenation, no parameterisation.
  const query =
    "SELECT id, username, role FROM users WHERE username = '" +
    username +
    "' AND password = '" +
    password +
    "'";

  console.log("[VULNERABLE QUERY]", query);

  try {
    const row = db.prepare(query).get();
    if (row) {
      res.status(200).json({ outcome: "AUTHENTICATED", user: row, queryExecuted: query });
    } else {
      res.status(401).json({ outcome: "REJECTED", queryExecuted: query });
    }
  } catch (err) {
    // VULNERABLE: raw database error returned to the client (error-based SQLi).
    res.status(500).json({ outcome: "DB_ERROR", error: err.message, queryExecuted: query });
  }
});

// ---------- PRODUCT SEARCH (vulnerable to UNION / error / blind SQLi) ----------

app.get("/search", (req, res) => {
  res.send(`
    <h1>Product Search (vulnerable)</h1>
    <form method="GET" action="/api/search">
      <input name="q" placeholder="product name" /><br/>
      <button type="submit">Search</button>
    </form>
  `);
});

app.get("/api/search", (req, res) => {
  const q = req.query.q || "";

  // VULNERABLE: raw string concatenation, no parameterisation.
  const query = "SELECT id, name, category, price FROM products WHERE name LIKE '%" + q + "%'";

  console.log("[VULNERABLE QUERY]", query);

  try {
    const rows = db.prepare(query).all();
    res.status(200).json({ outcome: "OK", count: rows.length, rows, queryExecuted: query });
  } catch (err) {
    // VULNERABLE: raw database error returned to the client (error-based SQLi).
    res.status(500).json({ outcome: "DB_ERROR", error: err.message, queryExecuted: query });
  }
});

app.listen(PORT, () => {
  console.log(`Vulnerable app listening on http://localhost:${PORT}`);
});
