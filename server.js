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

    const existingUser = await User.findOne({
      email
    });

    if (existingUser) {

      return res.status(400).json({
        error: "User already exists"
      });

    }

    const hashedPassword = await bcrypt.hash(
      password,
      10
    );

    const newUser = new User({

      email,
      password: hashedPassword

    });

    await newUser.save();

    return res.json({

      success: true,
      message: "User registered successfully"

    });

  } catch (err) {

    console.log("Register error:", err);

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
        error: "Missing email or password"
      });

    }

    const user = await User.findOne({
      email
    });

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

    return res.json({

      success: true,
      message: "Login successful",
      token

    });

  } catch (err) {

    console.log("Login error:", err);

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
// ADD CONTACT
// =====================================
app.post("/add-contact", async (req, res) => {

  try {

    const {
      userEmail,
      name,
      phone,
      relationship
    } = req.body;

    if (
      !userEmail ||
      !name ||
      !phone
    ) {

      return res.status(400).json({
        error: "Missing required fields"
      });

    }

    const newContact = new Contact({

      userEmail,
      name,
      phone,
      relationship

    });

    await newContact.save();

    return res.json({

      success: true,
      message: "Emergency contact added",
      contact: newContact

    });

  } catch (err) {

    console.log("Add contact error:", err);

    return res.status(500).json({
      error: "Failed to add contact"
    });

  }

});

// =====================================
// GET CONTACTS
// =====================================
app.get("/contacts/:email", async (req, res) => {

  try {

    const contacts = await Contact.find({

      userEmail: req.params.email

    });

    return res.json({

      success: true,
      contacts

    });

  } catch (err) {

    console.log("Fetch contacts error:", err);

    return res.status(500).json({
      error: "Failed to fetch contacts"
    });

  }

});

// =====================================
// UPDATE LIVE LOCATION
// =====================================
app.post("/update-location", async (req, res) => {

  try {

    const {
      userEmail,
      latitude,
      longitude,
      accuracy
    } = req.body;

    if (
      !userEmail ||
      latitude === undefined ||
      longitude === undefined
    ) {

      return res.status(400).json({
        error: "Missing required fields"
      });

    }

    const newLocation = new Location({

      userEmail,
      latitude,
      longitude,
      accuracy

    });

    await newLocation.save();

    io.emit("live_location", {

      userEmail,
      latitude,
      longitude,
      accuracy,
      timestamp: new Date()

    });

    return res.json({

      success: true,
      message: "Location updated",
      location: newLocation

    });

  } catch (err) {

    console.log("Location update error:", err);

    return res.status(500).json({
      error: "Failed to update location"
    });

  }

});

// =====================================
// GET LAST LOCATION
// =====================================
app.get("/last-location/:email", async (req, res) => {

  try {

    const location = await Location.findOne({

      userEmail: req.params.email

    }).sort({

      timestamp: -1

    });

    if (!location) {

      return res.status(404).json({
        error: "No location found"
      });

    }

    return res.json({

      success: true,
      location

    });

  } catch (err) {

    console.log("Fetch location error:", err);

    return res.status(500).json({
      error: "Failed to fetch location"
    });

  }

});

// =====================================
// SEND SINGLE SOS SMS
// =====================================
app.post("/send-sos", async (req, res) => {

  try {

    const {
      to,
      message
    } = req.body;

    const sms = await client.messages.create({

      body: message,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: to

    });

    return res.json({

      success: true,
      sid: sms.sid

    });

  } catch (error) {

    console.log("Twilio error:", error);

    return res.status(500).json({

      success: false,
      error: error.message

    });

  }

});

// =====================================
// FULL SOS BROADCAST SYSTEM
// =====================================
app.post("/sos", async (req, res) => {

  try {

    const {
      email,
      location,
      alertType
    } = req.body;

    const payload = {

      type: alertType || "SOS",

      email:
        email || "unknown@guardian.com",

      location:
        location || "Location not provided",

      timestamp:
        new Date().toISOString(),

      status: "ACTIVE"

    };

    console.log(
      "🚨 Guardian Alert Triggered:",
      payload
    );

    // FIND CONTACTS
    const contacts = await Contact.find({

      userEmail: email

    });

    // SEND ALERTS
    for (const contact of contacts) {

      const message =
`🚨 GUARDIAN X SOS ALERT

${email} triggered an emergency alert.

📍 Location:
${location}

⏰ Time:
${payload.timestamp}`;

      try {

        await client.messages.create({

          body: message,
          from:
            process.env.TWILIO_PHONE_NUMBER,
          to: contact.phone

        });

        console.log(
          `✅ SMS sent to ${contact.phone}`
        );

      } catch (smsError) {

        console.log(
          `❌ Failed SMS to ${contact.phone}:`,
          smsError.message
        );

      }

    }

    // REALTIME ALERT EVENT
    io.emit(
      "guardian_alert",
      payload
    );

    return res.json({

      success: true,
      message: "SOS broadcast sent",
      contactsAlerted: contacts.length,
      alert: payload

    });

  } catch (err) {

    console.log("SOS error:", err);

    return res.status(500).json({
      error: "Failed to trigger SOS alert"
    });

  }

});

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
