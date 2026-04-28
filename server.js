const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const http = require("http");
const { Server } = require("socket.io");

const app = express();
const PORT = process.env.PORT || 3000;

// =========================
// MIDDLEWARE
// =========================
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"]
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =========================
// MONGODB CONNECTION
// =========================
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log("MongoDB connection error:", err));

// =========================
// USER MODEL
// =========================
const UserSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  }
});

const User = mongoose.model("User", UserSchema);

// =========================
// HTTP + SOCKET SETUP
// =========================
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

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
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Missing email or password"
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        error: "User already exists"
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      email,
      password: hashedPassword
    });

    await newUser.save();

    res.json({
      success: true,
      message: "User registered successfully"
    });

  } catch (err) {
    console.log(err);
    res.status(500).json({
      error: "Server error"
    });
  }
});

// =========================
// REAL LOGIN ROUTE
// =========================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        error: "Missing email or password"
      });
    }

    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        error: "User not found"
      });
    }

    const isMatch = await bcrypt.compare(
      password,
      user.password
    );

    if (!isMatch) {
      return res.status(401).json({
        error: "Invalid password"
      });
    }

    const token = jwt.sign(
      {
        userId: user._id,
        email: user.email
      },
      process.env.JWT_SECRET || "guardian_secret",
      {
        expiresIn: "7d"
      }
    );

    res.json({
      success: true,
      message: "Login successful",
      token
    });

  } catch (err) {
    console.log(err);
    res.status(500).json({
      error: "Server error"
    });
  }
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
      process.env.JWT_SECRET || "guardian_secret"
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

  socket.on("disconnect", () => {
    console.log("Client disconnected:", socket.id);
  });
});

// =========================
// START SERVER
// =========================
server.listen(PORT, () => {
  console.log(`Guardian backend running on port ${PORT}`);
});
