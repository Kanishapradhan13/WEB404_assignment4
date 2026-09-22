// Builds a fresh app.db with sample users and products.
// Run with: node db/seed.js <path-to-db-file>
// Defaults to the vulnerable app's database when no path is given.

const path = require("path");
const fs = require("fs");
const Database = require("better-sqlite3");

const dbPath = process.argv[2] || path.join(__dirname, "..", "vulnerable", "app.db");

if (fs.existsSync(dbPath)) {
  fs.unlinkSync(dbPath);
}

const db = new Database(dbPath);

db.exec(`
  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'customer'
  );

  CREATE TABLE products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL
  );
`);

const insertUser = db.prepare(
  "INSERT INTO users (username, password, role) VALUES (?, ?, ?)"
);
insertUser.run("admin", "SuperSecretAdminPass!", "admin");
insertUser.run("alice", "alice2024", "customer");
insertUser.run("bob", "bobspassword", "customer");

const insertProduct = db.prepare(
  "INSERT INTO products (name, category, price) VALUES (?, ?, ?)"
);
insertProduct.run("Wireless Mouse", "Electronics", 19.99);
insertProduct.run("Mechanical Keyboard", "Electronics", 59.99);
insertProduct.run("USB-C Hub", "Electronics", 24.5);
insertProduct.run("Notebook", "Stationery", 2.5);
insertProduct.run("Desk Lamp", "Home", 15.0);

console.log(`Seeded database at ${dbPath}`);
console.log("Users:", db.prepare("SELECT id, username, role FROM users").all());
console.log("Products:", db.prepare("SELECT id, name, category, price FROM products").all());

db.close();
