// =====================================
// IMPORTS
// =====================================
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const mongoose = require("mongoose");
const http = require("http");
const { Server } = require("socket.io");
const twilio = require("twilio");

// =====================================
// APP SETUP
// =====================================
const app = express();
const PORT = process.env.PORT || 3000;

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
// CONTACT MODEL
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
// LOCATION MODEL
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
      message: "Invalid token format"
    });

  }

  try {

    const decoded = jwt.verify(
      token,
      process.env.JWT_SECRET
    );

    req.user = decoded;

    next();

  } catch (err) {

    return res.status(403).json({
      message: "Invalid or expired token"
    });

  }

}

// =====================================
// ROOT ROUTE
// =====================================
app.get("/", (req, res) => {

  res.send("🚀 Guardian X Backend Running");

});

// =====================================
// HEALTH ROUTE
// =====================================
app.get("/health", (req, res) => {

  return res.json({
    success: true,
    message: "Guardian X API Healthy"
  });

});

// =====================================
// STATUS ROUTE
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

    return res.status(500).json({
      success: false,
      error: err.message
    });

  }

});

// =====================================
// REGISTER ROUTE
// =====================================

// =====================================
// LOGIN ROUTE
// =====================================

// =====================================
// PROFILE ROUTE
// =====================================

// =====================================
// CONTACT ROUTES
// =====================================

// =====================================
// LOCATION ROUTES
// =====================================

// =====================================
// INCIDENT ROUTES
// =====================================

// =====================================
// EVIDENCE ROUTES
// =====================================

// =====================================
// SOS ROUTES
// =====================================

// =====================================
// SOCKET CONNECTION
// =====================================
io.on("connection", (socket) => {

  console.log(
    "🔌 Client connected:",
    socket.id
  );

  socket.on("disconnect", () => {

    console.log(
      "❌ Client disconnected:",
      socket.id
    );

  });

});

// =====================================
// START SERVER
// =====================================
server.listen(PORT, () => {

  console.log(
    `🚀 Guardian backend running on port ${PORT}`
  );

});
