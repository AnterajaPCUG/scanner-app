const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");
const mysql = require("mysql2/promise");

const app = express();
app.use(bodyParser.json());
app.use(express.static("public"));
app.get("/", (req, res) => {
  res.sendFile(__dirname + "/public/login.html");
});

// 🔧 Koneksi ke MariaDB/MySQL
const db = mysql.createPool({
  host: process.env.MYSQLHOST,
  user: process.env.MYSQLUSER,
  password: process.env.MYSQLPASSWORD,
  database: process.env.MYSQLDATABASE,
  port: process.env.MYSQLPORT
});

// Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: "Username dan password wajib diisi" });
  }

  try {
    const hashed = await bcrypt.hash(password, 10);
    await db.query("INSERT INTO users (username, password) VALUES (?, ?)", [username, hashed]);
    res.json({ message: "Registrasi berhasil" });
  } catch (err) {
    res.status(400).json({ error: "User sudah ada atau error DB" });
  }
});

// Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const [rows] = await db.query("SELECT * FROM users WHERE username = ?", [username]);

  if (rows.length === 0) return res.status(400).json({ error: "User tidak ditemukan" });

  const user = rows[0];
  const match = await bcrypt.compare(password, user.password);

  if (!match) return res.status(400).json({ error: "Password salah" });

  const token = jwt.sign({ id: user.id, username: user.username }, "secretkey");
  res.json({ token });
});

// Scan
app.post("/scan", async (req, res) => {
  const { userId, result } = req.body;
  if (!userId || !result) {
    return res.status(400).json({ error: "Data tidak lengkap" });
  }

  await db.query("INSERT INTO scans (user_id, result) VALUES (?, ?)", [userId, result]);
  res.json({ message: "Scan berhasil disimpan" });
});
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server jalan di port ${PORT}`);
});
