# WEB404_assignment4

SQL injection lab for the WEB404 Secure Coding Practices assignment. Local, isolated, educational use only.

## Structure

- `db/seed.js` - seeds a fresh SQLite database with sample `users` and `products` tables
- `vulnerable/server.js` - vulnerable Express app (string-concatenated SQL), port 3001
- `secure/server.js` - secure Express app (parameterised queries, validation), port 3002
- `evidence/` - captured terminal transcripts of every exploit and its fix
- `report.md` - full assignment report

## Run it

```
npm install
node db/seed.js vulnerable/app.db
node db/seed.js secure/app.db
node vulnerable/server.js    # http://localhost:3001
node secure/server.js        # http://localhost:3002
```

See `report.md` for the full writeup, including every payload used, the exact query it produces, and the observed outcome on both versions.
