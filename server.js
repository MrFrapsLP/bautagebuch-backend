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

// Admin-User anlegen
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

  db.get(`SELECT * FROM users WHERE email = ?`, ["admin@test.de"], (err, row) => {
    if (!row) {
      const hashedPassword = bcrypt.hashSync("admin123", 10);
      db.run(`INSERT INTO users (email, password, role) VALUES (?, ?, ?)`,
        ["admin@test.de", hashedPassword, "admin"]);
    }
  });
});

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

// Middleware für Auth
function authenticate(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Kein Token" });

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) return res.status(403).json({ message: "Ungültiger Token" });
    req.user = decoded;
    next();
  });
}

// Dummy-Baustellen
const demoBaustellen = [
  { id: 1, name: "Baustelle A", adresse: "Musterstraße 1", kunde: "Kunde A", notizen: "Notiz A" },
  { id: 2, name: "Baustelle B", adresse: "Beispielweg 2", kunde: "Kunde B", notizen: "Notiz B" }
];

// Baustellen-Route
app.get("/baustellen", authenticate, (req, res) => {
  res.json(demoBaustellen);
});

// Test
app.get("/", (req, res) => {
  res.send("Bautagebuch API läuft!");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server läuft auf Port ${PORT}`));
