const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const PORT = process.env.PORT || 3000;

// Create HTTP server for Socket.IO
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

app.use(cors());
app.use(express.json());

// =========================
// ROOT ROUTE
// =========================
app.get("/", (req, res) => {
  res.send("Guardian X Backend Running");
});

// =========================
// REGISTER ROUTE
// =========================
app.post("/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({
      message: "All fields are required"
    });
  }

  res.json({
    success: true,
    message: "User registered successfully"
  });
});

// =========================
// LOGIN ROUTE
// =========================
app.post("/login", async (req, res) => {
  const { email, password } = req.body;

  if (
    email === "test@guardian.com" &&
    password === "123456"
  ) {
    const token = jwt.sign(
      { email },
      "secret_key_guardian",
      { expiresIn: "7d" }
    );

    return res.json({
      success: true,
      token
    });
  }

  return res.status(401).json({
    message: "Invalid credentials"
  });
});

// =========================
// JWT VERIFY MIDDLEWARE
// =========================
function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({
      message: "No token provided"
    });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({
      message: "Invalid token format"
    });
  }

  try {
    const decoded = jwt.verify(
      token,
      "secret_key_guardian"
    );

    req.user = decoded;
    next();

  } catch (err) {
    return res.status(403).json({
      message: "Invalid or expired token"
    });
  }
}

// =========================
// PROTECTED PROFILE ROUTE
// =========================
app.get("/api/profile", verifyToken, (req, res) => {
  res.json({
    message: "Protected data accessed successfully",
    user: req.user
  });
});

// =========================
// SOS ROUTE
// =========================
app.post("/sos", (req, res) => {
  const payload = {
    type: "SOS",
    timestamp: Date.now()
  };

  console.log("🚨 SOS Triggered", payload);

  io.emit("alert", payload);

  res.json({
    success: true
  });
});

// =========================
// SOCKET CONNECTION
// =========================
io.on("connection", (socket) => {
  console.log("Client connected:", socket.id);
});

// =========================
// START SERVER
// =========================
server.listen(PORT, () => {
  console.log(`Guardian backend running on port ${PORT}`);
});
