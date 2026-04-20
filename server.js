const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
app.use(cors());
app.use(express.json());

// 🔐 AUTH CONFIG
const JWT_SECRET = "guardian_secret_key";
const users = [];

// ✅ Test route
app.get("/", (req, res) => {
  res.send("Guardian X backend is running 🚀");
});

// 👤 REGISTER
app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = {
    id: Date.now(),
    email,
    password: hashedPassword
  };

  users.push(user);

  res.json({
    success: true,
    message: "User registered"
  });
});

// 🔑 LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  const user = users.find(u => u.email === email);

  if (!user) {
    return res.json({ success: false, message: "User not found" });
  }

  const isValid = await bcrypt.compare(password, user.password);

  if (!isValid) {
    return res.json({ success: false, message: "Wrong password" });
  }

  const token = jwt.sign(
    { id: user.id, email: user.email },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  res.json({
    success: true,
    token
  });
});

// 📊 STATUS
app.get("/status", (req, res) => {
  res.json({ status: "ok", system: "Guardian X" });
});

// ❤️ HEALTH
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    system: "guardian-x",
    uptime: process.uptime()
  });
});

// 🚨 ALERT
app.post("/alert", (req, res) => {
  const data = req.body;
  console.log("ALERT RECEIVED:", data);

  res.json({
    success: true,
    message: "Alert received",
    data: data
  });
});

// 📷 CAMERA
app.post("/camera", (req, res) => {
  console.log("Camera event:", req.body);

  res.json({
    success: true,
    message: "Camera data received"
  });
});

// 🚀 START SERVER
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("Server running on port", PORT);
});
