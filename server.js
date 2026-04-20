const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// =========================
// TEMP "DATABASE" (for testing)
// =========================
const users = [];

// =========================
// HEALTH CHECK
// =========================
app.get("/", (req, res) => {
  res.json({ message: "Guardian is live 🚀" });
});

// =========================
// REGISTER USER
// =========================
app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Missing email or password" });
    }

    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = {
      id: Date.now(),
      email,
      password: hashedPassword
    };

    users.push(user);

    res.json({ message: "User created successfully" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

function verifyToken(req, res, next) {
  const authHeader = req.headers["authorization"];

  if (!authHeader) {
    return res.status(401).json({ message: "No token provided" });
  }

  const token = authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Invalid token format" });
  }

  try {
    const decoded = jwt.verify(token, "secret_key_guardian");
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
}

// =========================
// LOGIN USER
// =========================
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = users.find(u => u.email === email);
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email },
      "secret_key_guardian",
      { expiresIn: "1h" }
    );

    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

app.get("/api/profile", verifyToken, (req, res) => {
  res.json({
    message: "Protected data accessed successfully",
    user: req.user
  });
});

// =========================
// START SERVER
// =========================
app.listen(PORT, () => {
  console.log(`Guardian backend running on port ${PORT}`);
});
