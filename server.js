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
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");

// =====================================
// APP SETUP
// =====================================
const app = express();
const PORT = process.env.PORT || 3000;

// =====================================
// REQUIRED ENVIRONMENT VARIABLES
// =====================================
if (
  !process.env.JWT_SECRET ||
  !process.env.MONGODB_URI
) {

  console.error(
    "❌ Missing environment variables"
  );

  process.exit(1);

}

// =====================================
// HTTP SERVER + SOCKET.IO
// =====================================
const server = http.createServer(app);

const io = new Server(server, {

  cors: {

    origin:
      process.env.CLIENT_URL || "*",

    methods: [
      "GET",
      "POST",
      "PUT",
      "DELETE"
    ],

    credentials: true

  }

});

// =====================================
// TWILIO SETUP
// =====================================
let client = null;

if (
  process.env.TWILIO_ACCOUNT_SID &&
  process.env.TWILIO_AUTH_TOKEN
) {

  client = twilio(

    process.env.TWILIO_ACCOUNT_SID,
    process.env.TWILIO_AUTH_TOKEN

  );

  console.log(
    "✅ Twilio configured"
  );

} else {

  console.log(
    "⚠️ Twilio environment variables missing"
  );

}

// =====================================
// SECURITY + MIDDLEWARE
// =====================================
app.use(helmet());

app.use(cors({

  origin:
    process.env.CLIENT_URL || "*",

  methods: [
    "GET",
    "POST",
    "PUT",
    "DELETE"
  ],

  credentials: true

}));

app.use(express.json());

app.use(express.urlencoded({
  extended: true
}));

// =====================================
// API RATE LIMITER
// =====================================
const limiter = rateLimit({

  windowMs:
    15 * 60 * 1000,

  max: 100,

  message: {

    success: false,

    error:
      "Too many requests. Please try again later."

  }

});

app.use(limiter);

// =====================================
// MONGODB CONNECTION
// =====================================
mongoose.connect(

  process.env.MONGODB_URI,

  {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000
  }

)

.then(() => {

  console.log(
    "✅ MongoDB connected"
  );

})

.catch((err) => {

  console.log(
    "❌ MongoDB connection error:",
    err
  );

});

// =====================================
// MONGODB DISCONNECT LOGGER
// =====================================
mongoose.connection.on(
  "disconnected",
  () => {

    console.log(
      "⚠️ MongoDB disconnected"
    );

  }
);

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
  },

  createdAt: {
    type: Date,
    default: Date.now
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
function verifyToken(
  req,
  res,
  next
) {

  const authHeader =
    req.headers["authorization"];

  if (!authHeader) {

    return res.status(401).json({

      success: false,
      error: "No token provided"

    });

  }

  const token =
    authHeader.split(" ")[1];

  if (!token) {

    return res.status(401).json({

      success: false,
      error: "Invalid token format"

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

      success: false,
      error: "Invalid or expired token"

    });

  }

}

// =====================================
// ADMIN VERIFY MIDDLEWARE
// =====================================
function verifyAdmin(
  req,
  res,
  next
) {

  const adminSecret =
    req.headers["x-admin-secret"];

  if (
    adminSecret !==
    process.env.ADMIN_SECRET
  ) {

    return res.status(403).json({

      success: false,
      error: "Unauthorized admin access"

    });

  }

  next();

}

// =====================================
// ROOT ROUTE
// =====================================
app.get("/", (req, res) => {

  res.send(
    "🚀 Guardian X Backend Running"
  );

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

      timestamp:
        new Date()

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
app.post("/register", async (req, res) => {

  try {

    const {
      email,
      password
    } = req.body;

    if (
      !email ||
      !password
    ) {

      return res.status(400).json({

        success: false,
        error: "Missing email or password"

      });

    }

    const existingUser =
      await User.findOne({
        email
      });

    if (existingUser) {

      return res.status(400).json({

        success: false,
        error: "User already exists"

      });

    }

    const hashedPassword =
      await bcrypt.hash(
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
      message:
        "User registered successfully"

    });

  } catch (err) {

    return res.status(500).json({

      success: false,
      error: "Registration failed"

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

    if (
      !email ||
      !password
    ) {

      return res.status(400).json({

        success: false,
        error: "Missing email or password"

      });

    }

    const user =
      await User.findOne({
        email
      });

    if (!user) {

      return res.status(401).json({

        success: false,
        error: "User not found"

      });

    }

    const validPassword =
      await bcrypt.compare(
        password,
        user.password
      );

    if (!validPassword) {

      return res.status(401).json({

        success: false,
        error: "Invalid password"

      });

    }

    const token = jwt.sign(

      {
        userId: user._id,
        email: user.email
      },

      process.env.JWT_SECRET,

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

    return res.status(500).json({

      success: false,
      error: "Login failed"

    });

  }

});

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

        success: false,
        error: "Missing required contact fields"

      });

    }

    const contact = new Contact({

      userEmail,
      name,
      phone,
      relationship

    });

    await contact.save();

    return res.json({

      success: true,
      contact

    });

  } catch (err) {

    return res.status(500).json({

      success: false,
      error: "Failed to add contact"

    });

  }

});

// =====================================
// GET CONTACTS
// =====================================
app.get("/contacts/:email", async (req, res) => {

  try {

    const contacts =
      await Contact.find({

        userEmail: req.params.email

      });

    return res.json({

      success: true,
      contacts

    });

  } catch (err) {

    return res.status(500).json({

      success: false,
      error: "Failed to fetch contacts"

    });

  }

});

// =====================================
// UPDATE LOCATION
// =====================================
app.post("/update-location", async (req, res) => {

  try {

    const location =
      new Location(req.body);

    await location.save();

    io.emit(
      "live_location",
      location
    );

    return res.json({

      success: true,
      location

    });

  } catch (err) {

    return res.status(500).json({

      success: false,
      error: "Failed to update location"

    });

  }

});

// =====================================
// CREATE INCIDENT
// =====================================
app.post("/create-incident", async (req, res) => {

  try {

    const incident =
      new Incident({

        incidentId:
          "GX-" + Date.now(),

        ...req.body

      });

    await incident.save();

    io.emit(
      "new_incident",
      incident
    );

    return res.json({

      success: true,
      incident

    });

  } catch (err) {

    return res.status(500).json({

      success: false,
      error: "Failed to create incident"

    });

  }

});

// =====================================
// GET INCIDENTS
// =====================================
app.get("/incidents", async (req, res) => {

  try {

    const incidents =
      await Incident.find()
      .sort({
        createdAt: -1
      });

    return res.json({

      success: true,
      incidents

    });

  } catch (err) {

    return res.status(500).json({

      success: false,
      error: "Failed to fetch incidents"

    });

  }

});

// =====================================
// RESOLVE INCIDENT
// =====================================
app.put(
  "/resolve-incident/:id",
  verifyAdmin,
  async (req, res) => {

    try {

      const updatedIncident =
        await Incident.findByIdAndUpdate(

          req.params.id,

          {
            status: "RESOLVED"
          },

          {
            new: true
          }

        );

      return res.json({

        success: true,
        incident: updatedIncident

      });

    } catch (err) {

      return res.status(500).json({

        success: false,
        error: "Failed to resolve incident"

      });

    }

  }
);

// =====================================
// DELETE INCIDENT
// =====================================
app.delete(
  "/delete-incident/:id",
  verifyAdmin,
  async (req, res) => {

    try {

      await Incident.findByIdAndDelete(
        req.params.id
      );

      return res.json({

        success: true,
        message: "Incident deleted"

      });

    } catch (err) {

      return res.status(500).json({

        success: false,
        error: "Failed to delete incident"

      });

    }

  }
);

// =====================================
// GET ALL USERS
// =====================================
app.get(
  "/admin/users",
  verifyAdmin,
  async (req, res) => {

    try {

      const users =
        await User.find()
        .select("-password");

      return res.json({

        success: true,
        users

      });

    } catch (err) {

      return res.status(500).json({

        success: false,
        error: "Failed to fetch users"

      });

    }

  }
);

// =====================================
// UPLOAD EVIDENCE
// =====================================
app.post("/upload-evidence", async (req, res) => {

  try {

    const evidence =
      new Evidence(req.body);

    await evidence.save();

    io.emit(
      "new_evidence",
      evidence
    );

    return res.json({

      success: true,
      evidence

    });

  } catch (err) {

    return res.status(500).json({

      success: false,
      error: "Failed to upload evidence"

    });

  }

});

// =====================================
// SOS ROUTE
// =====================================
app.post("/sos", async (req, res) => {

  try {

    if (!client) {

      return res.status(500).json({

        success: false,
        error: "Twilio not configured"

      });

    }

    const {
      email,
      location
    } = req.body;

    if (
      !email ||
      !location
    ) {

      return res.status(400).json({

        success: false,
        error:
          "Missing email or location"

      });

    }

    const contacts =
      await Contact.find({
        userEmail: email
      });

    for (const contact of contacts) {

      await client.messages.create({

        body:
`🚨 GUARDIAN X SOS ALERT

${email} triggered an emergency alert.

📍 Location:
${location}`,

        from:
          process.env.TWILIO_PHONE_NUMBER,

        to:
          contact.phone

      });

    }

    return res.json({

      success: true,
      contactsAlerted:
        contacts.length

    });

  } catch (err) {

    return res.status(500).json({

      success: false,
      error: "SOS failed"

    });

  }

});

// =====================================
// 404 ROUTE HANDLER
// =====================================
app.use((req, res) => {

  return res.status(404).json({

    success: false,
    error: "Route not found"

  });

});

// =====================================
// GLOBAL ERROR HANDLER
// =====================================
app.use((
  err,
  req,
  res,
  next
) => {

  console.error(
    "❌ Server Error:",
    err
  );

  return res.status(500).json({

    success: false,
    error:
      "Internal server error"

  });

});

// =====================================
// SOCKET CONNECTION
// =====================================
io.on(
  "connection",
  (socket) => {

    console.log(
      "🔌 Client connected:",
      socket.id
    );

    socket.on(
      "disconnect",
      () => {

        console.log(
          "❌ Client disconnected:",
          socket.id
        );

      }
    );

  }
);

// =====================================
// START SERVER
// =====================================
server.listen(PORT, () => {

  console.log(
    `🚀 Guardian X backend running on port ${PORT}`
  );

});

// =====================================
// PROCESS ERROR HANDLERS
// =====================================
process.on(
  "unhandledRejection",
  (err) => {

    console.error(
      "❌ Unhandled Rejection:",
      err
    );

  }
);

process.on(
  "uncaughtException",
  (err) => {

    console.error(
      "❌ Uncaught Exception:",
      err
    );

  }
);
