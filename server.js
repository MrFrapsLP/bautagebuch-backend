const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
require("dotenv").config();

const app = express();
app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./database.db");

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS baustellen (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    adresse TEXT,
    kunde TEXT,
    notizen TEXT
  )`);

  db.get(`SELECT * FROM users WHERE email = ?`, ["admin@test.de"], (err, row) => {
    if (!row) {
      const hashedPassword = bcrypt.hashSync("admin123", 10);
      db.run(`INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
        ["admin@test.de", hashedPassword, "admin"]);
    }
  });
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get(`SELECT * FROM users WHERE email = ?`, [email], (err, user) => {
    if (!user) return res.status(401).json({ message: "User not found" });

    bcrypt.compare(password, user.password, (err, result) => {
      if (!result) return res.status(401).json({ message: "Invalid password" });

      const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: "1d" });
      res.json({ token });
    });
  });
});

function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Kein Token" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Ungültiger Token" });
    req.user = decoded;
    next();
  });
}

// GET all
app.get("/baustellen", authenticate, (req, res) => {
  db.all(`SELECT * FROM baustellen`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

// POST new
app.post("/baustellen", authenticate, (req, res) => {
  const { name, adresse, kunde, notizen } = req.body;
  db.run(`INSERT INTO baustellen (name, adresse, kunde, notizen) VALUES (?, ?, ?, ?)`,
    [name, adresse, kunde, notizen],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

// PUT update
app.put("/baustellen/:id", authenticate, (req, res) => {
  const { name, adresse, kunde, notizen } = req.body;
  db.run(`UPDATE baustellen SET name=?, adresse=?, kunde=?, notizen=? WHERE id=?`,
    [name, adresse, kunde, notizen, req.params.id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ changes: this.changes });
    });
});

// DELETE
app.delete("/baustellen/:id", authenticate, (req, res) => {
  db.run(`DELETE FROM baustellen WHERE id=?`,
    [req.params.id],
    function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ changes: this.changes });
    });
});

app.get("/", (req, res) => {
  res.send("Bautagebuch API läuft!");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));
