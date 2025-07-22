const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();
const multer = require("multer");
require("dotenv").config();

const app = express();
const upload = multer({ dest: "./uploads" });

app.use(cors());
app.use(express.json());

const db = new sqlite3.Database("./database.db");

// Tabellen erstellen
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS stockwerke (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    baustelle_id INTEGER,
    name TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS tueren (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stockwerk_id INTEGER,
    name TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS maengel (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tuer_id INTEGER,
    titel TEXT,
    beschreibung TEXT,
    behoben INTEGER,
    timestamp TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS grundrisse (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    stockwerk_id INTEGER,
    dateiname TEXT,
    pfad TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS baustellen (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT,
    adresse TEXT,
    kunde TEXT,
    notizen TEXT,
    status TEXT
  )`);

  db.get(`SELECT * FROM users WHERE email = ?`, ["admin@test.de"], (err, row) => {
    if (!row) {
      const hashedPassword = bcrypt.hashSync("admin123", 10);
      db.run(`INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
        ["admin@test.de", hashedPassword, "admin"]);
    }
  });
});

// Auth
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Kein Token" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Ungültiger Token" });
    req.user = decoded;
    next();
  });
}

// Login
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

// Baustellen CRUD
app.get("/baustellen", authenticate, (req, res) => {
  db.all("SELECT * FROM baustellen", (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post("/baustellen", authenticate, (req, res) => {
  const { name, adresse, kunde, notizen } = req.body;
  db.run("INSERT INTO baustellen (name, adresse, kunde, notizen, status) VALUES (?, ?, ?, ?, 'aktiv')",
    [name, adresse, kunde, notizen], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

app.put("/baustellen/:id", authenticate, (req, res) => {
  const { name, adresse, kunde, notizen, status } = req.body;
  db.run("UPDATE baustellen SET name=?, adresse=?, kunde=?, notizen=?, status=? WHERE id=?",
    [name, adresse, kunde, notizen, status || 'aktiv', req.params.id], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ updated: this.changes });
    });
});

app.delete("/baustellen/:id", authenticate, (req, res) => {
  db.run("DELETE FROM baustellen WHERE id=?", [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ deleted: this.changes });
  });
});

// Stockwerke
app.get("/baustellen/:id/stockwerke", authenticate, (req, res) => {
  db.all("SELECT * FROM stockwerke WHERE baustelle_id=?", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post("/baustellen/:id/stockwerke", authenticate, (req, res) => {
  const { name } = req.body;
  db.run("INSERT INTO stockwerke (baustelle_id, name) VALUES (?, ?)",
    [req.params.id, name], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

// Türen
app.get("/stockwerke/:id/tueren", authenticate, (req, res) => {
  db.all("SELECT * FROM tueren WHERE stockwerk_id=?", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post("/stockwerke/:id/tueren", authenticate, (req, res) => {
  const { name } = req.body;
  db.run("INSERT INTO tueren (stockwerk_id, name) VALUES (?, ?)",
    [req.params.id, name], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

// Mängel
app.get("/tueren/:id/maengel", authenticate, (req, res) => {
  db.all("SELECT * FROM maengel WHERE tuer_id=?", [req.params.id], (err, rows) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json(rows);
  });
});

app.post("/tueren/:id/maengel", authenticate, (req, res) => {
  const { titel, beschreibung, behoben } = req.body;
  const timestamp = new Date().toISOString();
  db.run("INSERT INTO maengel (tuer_id, titel, beschreibung, behoben, timestamp) VALUES (?, ?, ?, ?, ?)",
    [req.params.id, titel, beschreibung, behoben ? 1 : 0, timestamp], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID });
    });
});

// Grundrisse
app.post("/stockwerke/:id/grundriss", authenticate, upload.single("file"), (req, res) => {
  const pfad = req.file.path;
  const dateiname = req.file.originalname;
  db.run("INSERT INTO grundrisse (stockwerk_id, dateiname, pfad) VALUES (?, ?, ?)",
    [req.params.id, dateiname, pfad], function (err) {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ id: this.lastID, pfad });
    });
});

app.get("/", (req, res) => {
  res.send("Bautagebuch API läuft!");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));
