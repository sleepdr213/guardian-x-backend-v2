const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const http = require("http");
const { Server } = require("socket.io");
const twilio = require("twilio");

const app = express();
const PORT = process.env.PORT || 3000;

// =====================================
// TWILIO SETUP
// =====================================
const client = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
);

// =====================================
// MIDDLEWARE
// =====================================
app.use(cors({
  origin: "*",
  methods: ["GET", "POST", "PUT", "DELETE"]
}));

app.use(express.json());

app.use(express.urlencoded({
  extended: true
}));

// =====================================
// MONGODB CONNECTION
// =====================================
mongoose.connect(process.env.MONGODB_URI)

.then(() => {
  console.log("✅ MongoDB connected");
})

.catch((err) => {
  console.log("❌ MongoDB connection error:", err);
});

// =====================================
// USER MODEL
// =====================================
const UserSchema = new mongoose.Schema({

  email: {
    type: String,
    required: true,
    unique: true,
    trim: true
  },

  password: {
    type: String,
    required: true
  }

});

const User = mongoose.model(
  "User",
  UserSchema
);

// =====================================
// EMERGENCY CONTACT MODEL
// =====================================
const ContactSchema = new mongoose.Schema({

  userEmail: {
    type: String,
    required: true
  },

  name: {
    type: String,
    required: true
  },

  phone: {
    type: String,
    required: true
  },

  relationship: {
    type: String,
    default: "Contact"
  },

  createdAt: {
    type: Date,
    default: Date.now
  }

});

const Contact = mongoose.model(
  "Contact",
  ContactSchema
);

// =====================================
// LIVE LOCATION MODEL
// =====================================
const LocationSchema = new mongoose.Schema({

  userEmail: {
    type: String,
    required: true
  },

  latitude: {
    type: Number,
    required: true
  },

  longitude: {
    type: Number,
    required: true
  },

  accuracy: {
    type: Number,
    default: 0
  },

  timestamp: {
    type: Date,
    default: Date.now
  }

});

const Location = mongoose.model(
  "Location",
  LocationSchema
);

// =====================================
// INCIDENT MODEL
// =====================================
const IncidentSchema = new mongoose.Schema({

  incidentId: {
    type: String,
    required: true,
    unique: true
  },

  userEmail: {
    type: String,
    required: true
  },

  type: {
    type: String,
    default: "SOS"
  },

  severity: {
    type: String,
    default: "HIGH"
  },

  location: {
    type: String,
    default: "Unknown"
  },

  status: {
    type: String,
    default: "ACTIVE"
  },

  createdAt: {
    type: Date,
    default: Date.now
  }

});

const Incident = mongoose.model(
  "Incident",
  IncidentSchema
);

// =====================================
// EVIDENCE MODEL
// =====================================
const EvidenceSchema = new mongoose.Schema({

  incidentId: {
    type: String,
    required: true
  },

  userEmail: {
    type: String,
    required: true
  },

  type: {
    type: String,
    default: "PHOTO"
  },

  fileUrl: {
    type: String,
    required: true
  },

  description: {
    type: String,
    default: ""
  },

  timestamp: {
    type: Date,
    default: Date.now
  }

});

const Evidence = mongoose.model(
  "Evidence",
  EvidenceSchema
);

// =====================================
// HTTP SERVER + SOCKET.IO
// =====================================
const server = http.createServer(app);

const io = new Server(server, {

  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }

});

// =====================================
// ROOT ROUTE
// =====================================
app.get("/", (req, res) => {

  res.send("🚀 Guardian X Backend Running");

});

// =====================================
// HEALTH CHECK ROUTE
// =====================================
app.get("/health", (req, res) => {

  return res.json({
    success: true,
    message: "Guardian X API Healthy"
  });

});

// =====================================
// SYSTEM STATUS ROUTE
// =====================================
app.get("/status", async (req, res) => {

  try {

    const userCount =
      await User.countDocuments();

    const incidentCount =
      await Incident.countDocuments();

    const contactCount =
      await Contact.countDocuments();

    const evidenceCount =
      await Evidence.countDocuments();

    const locationCount =
      await Location.countDocuments();

    return res.json({

      success: true,

      system: "Guardian X",

      status: "ONLINE",

      database: "CONNECTED",

      stats: {

        users: userCount,

        incidents: incidentCount,

        contacts: contactCount,

        evidence: evidenceCount,

        locations: locationCount

      },

      timestamp: new Date()

    });

  } catch (err) {

    console.log(
      "Status route error:",
      err
    );

    return res.status(500).json({

      success: false,

      status: "ERROR",

      error: err.message

    });

  }

});

// =====================================
// REGISTER ROUTE
// =====================================
app.post("/register", async (req, res) => {

  try {

    const {
      email,
      password
    } = req.body;

    if (!email || !password) {

      return res.status(400).json({
        error: "Missing email or password"
      });

    }

    const existingUser =
      await User.findOne({
        email
      });

    if (existingUser) {

      return res.status(400).json({
        error: "User already exists"
      });

    }

    const hashedPassword =
      await bcrypt.hash(password, 10);

    const newUser = new User({

      email,
      password: hashedPassword

    });

    await newUser.save();

    return res.json({

      success: true,
      message:
        "User registered successfully"

    });

  } catch (err) {

    console.log(
      "Register error:",
      err
    );

    return res.status(500).json({
      error: "Server error"
    });

  }

});

// =====================================
// LOGIN ROUTE
// =====================================
app.post("/login", async (req, res) => {

  try {

    const {
      email,
      password
    } = req.body;

    if (!email || !password) {

      return res.status(400).json({
        error:
          "Missing email or password"
      });

    }

    const user =
      await User.findOne({
        email
      });

    if (!user) {

      return res.status(401).json({
        error: "User not found"
      });

    }

    const isMatch =
      await bcrypt.compare(
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

      process.env.JWT_SECRET ||
      "guardian_secret",

      {
        expiresIn: "7d"
      }

    );

    return res.json({

      success: true,
      message: "Login successful",
      token

    });

  } catch (err) {

    console.log(
      "Login error:",
      err
    );

    return res.status(500).json({
      error: "Server error"
    });

  }

});

// =====================================
// JWT VERIFY MIDDLEWARE
// =====================================
function verifyToken(req, res, next) {

  const authHeader =
    req.headers["authorization"];

  if (!authHeader) {

    return res.status(401).json({
      message: "No token provided"
    });

  }

  const token =
    authHeader.split(" ")[1];

  if (!token) {

    return res.status(401).json({
      message:
        "Invalid token format"
    });

  }

  try {

    const decoded = jwt.verify(

      token,

      process.env.JWT_SECRET ||
      "guardian_secret"

    );

    req.user = decoded;

    next();

  } catch (err) {

    return res.status(403).json({
      message:
        "Invalid or expired token"
    });

  }

}

// =====================================
// PROFILE ROUTE
// =====================================
app.get(
  "/api/profile",
  verifyToken,
  (req, res) => {

    return res.json({

      success: true,
      user: req.user

    });

  }
);

// =====================================
// START SERVER
// =====================================
server.listen(PORT, () => {

  console.log(
    `🚀 Guardian backend running on port ${PORT}`
  );

});
