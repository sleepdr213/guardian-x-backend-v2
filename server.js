// =====================================
// GUARDIAN X BACKEND
// SECURITY-HARDENED VERSION
// =====================================

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
const crypto = require("crypto");

const {
  APPROVER_ROLES,
  APPROVER_STATUS,
  createVerifiedApproval,
  verifyApprovalForSensor,
} = require("./fusion/approverPolicy");

// =====================================
// APP SETUP
// =====================================
const app = express();
const PORT = process.env.PORT || 3000;

// Render / reverse proxy support
app.set("trust proxy", 1);

// =====================================
// REQUIRED ENVIRONMENT VARIABLES
// =====================================
if (
  !process.env.JWT_SECRET ||
  !process.env.MONGODB_URI
) {
  console.error(
    "❌ Missing required JWT_SECRET or MONGODB_URI"
  );

  process.exit(1);
}

// =====================================
// HTTP SERVER
// =====================================
const server = http.createServer(app);

// =====================================
// CORS CONFIGURATION
// =====================================
const allowedOrigin =
  process.env.CLIENT_URL || "*";

const corsOptions =
  allowedOrigin === "*"
    ? {
        origin: "*",
        methods: [
          "GET",
          "POST",
          "PUT",
          "DELETE",
          "OPTIONS"
        ],
        credentials: false
      }
    : {
        origin: allowedOrigin,
        methods: [
          "GET",
          "POST",
          "PUT",
          "DELETE",
          "OPTIONS"
        ],
        credentials: true
      };

// =====================================
// SOCKET.IO
// =====================================
const io = new Server(server, {
  cors: corsOptions
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

  console.log("✅ Twilio configured");
} else {
  console.log(
    "⚠️ Twilio environment variables missing"
  );
}

// =====================================
// SECURITY MIDDLEWARE
// =====================================
app.disable("x-powered-by");

app.use(
  helmet({
    contentSecurityPolicy: false
  })
);

app.use(cors(corsOptions));

app.use(
  express.json({
    limit: "1mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "1mb"
  })
);

// =====================================
// GENERAL RATE LIMITER
// =====================================
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error:
      "Too many requests. Please try again later."
  }
});

app.use(generalLimiter);

// =====================================
// AUTH RATE LIMITER
// =====================================
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error:
      "Too many authentication attempts. Please try again later."
  }
});

// =====================================
// SOS RATE LIMITER
// =====================================
const sosLimiter = rateLimit({
  windowMs: 5 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error:
      "Too many SOS requests. Please wait before trying again."
  }
});

// =====================================
// MONGODB CONNECTION
// =====================================
mongoose
  .connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 5000,
    socketTimeoutMS: 45000
  })
  .then(() => {
    console.log("✅ MongoDB connected");
  })
  .catch((err) => {
    console.error(
      "❌ MongoDB connection error:",
      err.message
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
// HELPER FUNCTIONS
// =====================================

function normalizeEmail(email) {
  if (
    typeof email !== "string"
  ) {
    return "";
  }

  return email
    .trim()
    .toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
}

function isValidPhone(phone) {
  return (
    typeof phone === "string" &&
    /^\+?[1-9]\d{7,14}$/.test(
      phone.trim()
    )
  );
}

function isValidCoordinate(value) {
  return (
    typeof value === "number" &&
    Number.isFinite(value)
  );
}

function safeString(
  value,
  maxLength = 500
) {
  if (
    typeof value !== "string"
  ) {
    return "";
  }

  return value
    .trim()
    .slice(0, maxLength);
}

// =====================================
// USER MODEL
// =====================================
const UserSchema =
  new mongoose.Schema(
    {
      email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        index: true
      },

      password: {
        type: String,
        required: true,
        select: false
      },

      createdAt: {
        type: Date,
        default: Date.now
      }
    },
    {
      versionKey: false
    }
  );

const User = mongoose.model(
  "User",
  UserSchema
);

// =====================================
// APPROVER MODEL
// =====================================

const ApproverSchema =
  new mongoose.Schema(
    {
      approverId: {
        type: String,
        required: true,
        unique: true,
        trim: true,
        index: true,
      },

      userEmail: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        index: true,
      },

      role: {
        type: String,
        required: true,
        enum: Object.values(APPROVER_ROLES),
        index: true,
      },

      status: {
        type: String,
        required: true,
        enum: Object.values(APPROVER_STATUS),
        default: APPROVER_STATUS.ACTIVE,
        index: true,
      },

      verifiedAt: {
        type: Date,
        default: Date.now,
      },

      verifiedBy: {
        type: String,
        required: true,
        trim: true,
      },

      suspendedAt: {
        type: Date,
        default: null,
      },

      revokedAt: {
        type: Date,
        default: null,
      },

      createdAt: {
        type: Date,
        default: Date.now,
      },

      updatedAt: {
        type: Date,
        default: Date.now,
      },
    },
    {
      versionKey: false,
    }
  );

ApproverSchema.index(
  {
    userEmail: 1,
    status: 1,
  }
);

const Approver =
  mongoose.model(
    "Approver",
    ApproverSchema
  );

// =====================================
// CONTACT MODEL
// =====================================
const ContactSchema =
  new mongoose.Schema(
    {
      userEmail: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        index: true
      },

      name: {
        type: String,
        required: true,
        trim: true,
        maxlength: 100
      },

      phone: {
        type: String,
        required: true,
        trim: true,
        maxlength: 20
      },

      relationship: {
        type: String,
        default: "Contact",
        trim: true,
        maxlength: 100
      },

      createdAt: {
        type: Date,
        default: Date.now
      }
    },
    {
      versionKey: false
    }
  );

const Contact =
  mongoose.model(
    "Contact",
    ContactSchema
  );

// =====================================
// LOCATION MODEL
// =====================================
const LocationSchema =
  new mongoose.Schema(
    {
      userEmail: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        index: true
      },

      latitude: {
        type: Number,
        required: true,
        min: -90,
        max: 90
      },

      longitude: {
        type: Number,
        required: true,
        min: -180,
        max: 180
      },

      accuracy: {
        type: Number,
        default: 0,
        min: 0
      },

      timestamp: {
        type: Date,
        default: Date.now
      }
    },
    {
      versionKey: false
    }
  );

const Location =
  mongoose.model(
    "Location",
    LocationSchema
  );

// =====================================
// INCIDENT MODEL
// =====================================
const IncidentSchema =
  new mongoose.Schema(
    {
      incidentId: {
        type: String,
        required: true,
        unique: true,
        index: true
      },

      userEmail: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        index: true
      },

      type: {
        type: String,
        default: "SOS",
        maxlength: 50
      },

      severity: {
        type: String,
        default: "HIGH",
        maxlength: 30
      },

      location: {
        type: String,
        default: "Unknown",
        maxlength: 500
      },

      status: {
        type: String,
        default: "ACTIVE",
        maxlength: 30
      },

      createdAt: {
        type: Date,
        default: Date.now
      }
    },
    {
      versionKey: false
    }
  );

const Incident =
  mongoose.model(
    "Incident",
    IncidentSchema
  );

// =====================================
// EVIDENCE MODEL
// =====================================
const EvidenceSchema =
  new mongoose.Schema(
    {
      incidentId: {
        type: String,
        required: true,
        index: true
      },

      userEmail: {
        type: String,
        required: true,
        lowercase: true,
        trim: true,
        index: true
      },

      type: {
        type: String,
        default: "PHOTO",
        maxlength: 50
      },

      fileUrl: {
        type: String,
        required: true,
        maxlength: 2000
      },

      description: {
        type: String,
        default: "",
        maxlength: 1000
      },

      timestamp: {
        type: Date,
        default: Date.now
      },

      integrityHash: {
        type: String,
        default: ""
      }
    },
    {
      versionKey: false
    }
  );

const Evidence =
  mongoose.model(
    "Evidence",
    EvidenceSchema
  );

// =====================================
// SECURITY AUDIT MODEL
// =====================================
const AuditSchema =
  new mongoose.Schema(
    {
      event: {
        type: String,
        required: true,
        maxlength: 100
      },

      userEmail: {
        type: String,
        default: "",
        lowercase: true,
        trim: true,
        maxlength: 320
      },

      success: {
        type: Boolean,
        default: true
      },

      createdAt: {
        type: Date,
        default: Date.now
      }
    },
    {
      versionKey: false
    }
  );

const Audit =
  mongoose.model(
    "Audit",
    AuditSchema
  );

// =====================================
// AUDIT HELPER
// =====================================
async function recordAudit(
  event,
  userEmail = "",
  success = true
) {
  try {
    await Audit.create({
      event,
      userEmail: normalizeEmail(
        userEmail
      ),
      success
    });
  } catch (err) {
    console.error(
      "⚠️ Audit logging failed"
    );
  }
}

// =====================================
// JWT VERIFY MIDDLEWARE
// =====================================
function verifyToken(
  req,
  res,
  next
) {
  const authHeader =
    req.headers.authorization;

  if (
    !authHeader ||
    !authHeader.startsWith("Bearer ")
  ) {
    return res.status(401).json({
      success: false,
      error:
        "Authentication required"
    });
  }

  const token =
    authHeader.substring(7).trim();

  if (!token) {
    return res.status(401).json({
      success: false,
      error:
        "Authentication required"
    });
  }

  try {
    const decoded =
      jwt.verify(
        token,
        process.env.JWT_SECRET
      );

    if (
      !decoded ||
      !decoded.email ||
      !decoded.userId
    ) {
      return res.status(401).json({
        success: false,
        error:
          "Invalid authentication token"
      });
    }

    req.user = {
      userId: String(
        decoded.userId
      ),
      email: normalizeEmail(
        decoded.email
      )
    };

    next();

  } catch (err) {
    return res.status(401).json({
      success: false,
      error:
        "Invalid or expired token"
    });
  }
}

// =====================================
// ADMIN VERIFY MIDDLEWARE
// =====================================
async function verifyAdmin(
  req,
  res,
  next
) {
  try {

    if (!process.env.ADMIN_EMAIL) {
      return res.status(503).json({
        success: false,
        error:
          "Admin security is not configured"
      });
    }

    if (!process.env.ADMIN_SECRET) {
      return res.status(503).json({
        success: false,
        error:
          "Admin security is not configured"
      });
    }

    const adminSecret =
      req.headers["x-admin-secret"];

    if (
      typeof adminSecret !==
      "string"
    ) {
      await recordAudit(
        "ADMIN_ACCESS_DENIED",
        req.user?.email || "",
        false
      );

      return res.status(403).json({
        success: false,
        error:
          "Unauthorized admin access"
      });
    }

    const expected =
      Buffer.from(
        process.env.ADMIN_SECRET
      );

    const supplied =
      Buffer.from(
        adminSecret
      );

    if (
      expected.length !==
      supplied.length ||
      !crypto.timingSafeEqual(
        expected,
        supplied
      )
    ) {
      await recordAudit(
        "ADMIN_ACCESS_DENIED",
        req.user?.email || "",
        false
      );

      return res.status(403).json({
        success: false,
        error:
          "Unauthorized admin access"
      });
    }

    if (
      normalizeEmail(
        req.user.email
      ) !==
      normalizeEmail(
        process.env.ADMIN_EMAIL
      )
    ) {
      await recordAudit(
        "ADMIN_ACCESS_DENIED",
        req.user.email,
        false
      );

      return res.status(403).json({
        success: false,
        error:
          "Unauthorized admin access"
      });
    }

    await recordAudit(
      "ADMIN_ACCESS_GRANTED",
      req.user.email,
      true
    );

    next();

  } catch (err) {
    return res.status(500).json({
      success: false,
      error:
        "Admin authorization failed"
    });
  }
}

// =====================================
// ADMIN APPROVER ROUTES
// =====================================

app.post(
  "/api/admin/approvers",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const userEmail =
        normalizeEmail(req.body?.userEmail);

      const role =
        typeof req.body?.role === "string"
          ? req.body.role.trim()
          : "";

      if (!userEmail || !role) {
        return res.status(400).json({
          success: false,
          error: "userEmail and role are required",
        });
      }

      if (!Object.values(APPROVER_ROLES).includes(role)) {
        return res.status(400).json({
          success: false,
          error: "Invalid approver role",
        });
      }

      const user = await User.findOne({
        email: userEmail,
      });

      if (!user) {
        return res.status(404).json({
          success: false,
          error: "Guardian X user not found",
        });
      }

      const existingApprover =
        await Approver.findOne({
          userEmail,
        });

      if (existingApprover) {
        return res.status(409).json({
          success: false,
          error: "Approver already exists",
        });
      }

      const approver =
        await Approver.create({
          approverId: crypto.randomUUID(),
          userEmail,
          role,
          status: APPROVER_STATUS.ACTIVE,
          verifiedAt: new Date(),
          verifiedBy: normalizeEmail(req.user.email),
        });

      await recordAudit(
        "APPROVER_CREATED",
        req.user.email,
        true
      );

      return res.status(201).json({
        success: true,
        approver: {
          approverId: approver.approverId,
          userEmail: approver.userEmail,
          role: approver.role,
          status: approver.status,
          verifiedAt: approver.verifiedAt,
        },
      });
    } catch (err) {
      console.error(
        "Approver creation error:",
        err
      );

      await recordAudit(
        "APPROVER_CREATE_FAILED",
        req.user?.email || "",
        false
      );

      return res.status(500).json({
        success: false,
        error: "Unable to create approver",
      });
    }
  }
);

// =====================================
// ROOT ROUTE
// =====================================
app.get(
  "/",
  (req, res) => {
    res.send(
      "🚀 Guardian X Backend Running"
    );
  }
);

// =====================================
// HEALTH ROUTE
// =====================================
app.get(
  "/health",
  (req, res) => {
    return res.json({
      success: true,
      message:
        "Guardian X API Healthy"
    });
  }
);

// =====================================
// STATUS ROUTE
// ADMIN ONLY
// =====================================
app.get(
  "/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {

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

        system:
          "Guardian X",

        status:
          "ONLINE",

        database:
          mongoose.connection.readyState === 1
            ? "CONNECTED"
            : "DISCONNECTED",

        stats: {
          users: userCount,
          incidents:
            incidentCount,
          contacts:
            contactCount,
          evidence:
            evidenceCount,
          locations:
            locationCount
        },

        timestamp:
          new Date()
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Unable to retrieve system status"
      });
    }
  }
);

// =====================================
// REGISTER
// =====================================
app.post(
  "/register",
  authLimiter,
  async (req, res) => {

    try {

      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        typeof req.body.password ===
        "string"
          ? req.body.password
          : "";

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Email and password are required"
        });
      }

      if (
        !isValidEmail(email)
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid email address"
        });
      }

      if (
        password.length < 10
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Password must be at least 10 characters"
        });
      }

      if (
        password.length > 200
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Password is too long"
        });
      }

      const existingUser =
        await User.findOne({
          email
        });

      if (existingUser) {
        return res.status(400).json({
          success: false,
          error:
            "Unable to create account"
        });
      }

      const hashedPassword =
        await bcrypt.hash(
          password,
          12
        );

      const newUser =
        new User({
          email,
          password:
            hashedPassword
        });

      await newUser.save();

      await recordAudit(
        "ACCOUNT_CREATED",
        email,
        true
      );

      return res.status(201).json({
        success: true,
        message:
          "User registered successfully"
      });

    } catch (err) {

      console.error(
        "❌ Registration error:",
        err.message
      );

      return res.status(500).json({
        success: false,
        error:
          "Registration failed"
      });
    }
  }
);

// =====================================
// LOGIN
// =====================================
app.post(
  "/login",
  authLimiter,
  async (req, res) => {

    try {

      const email =
        normalizeEmail(
          req.body.email
        );

      const password =
        typeof req.body.password ===
        "string"
          ? req.body.password
          : "";

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Email and password are required"
        });
      }

      const user =
        await User.findOne({
          email
        }).select(
          "+password"
        );

      if (!user) {

        await recordAudit(
          "LOGIN_FAILED",
          email,
          false
        );

        return res.status(401).json({
          success: false,
          error:
            "Invalid email or password"
        });
      }

      const validPassword =
        await bcrypt.compare(
          password,
          user.password
        );

      if (!validPassword) {

        await recordAudit(
          "LOGIN_FAILED",
          email,
          false
        );

        return res.status(401).json({
          success: false,
          error:
            "Invalid email or password"
        });
      }

      const token =
        jwt.sign(
          {
            userId:
              String(user._id),
            email:
              user.email
          },
          process.env.JWT_SECRET,
          {
            expiresIn: "7d"
          }
        );

      await recordAudit(
        "LOGIN_SUCCESS",
        email,
        true
      );

      return res.json({
        success: true,
        message:
          "Login successful",
        token
      });

    } catch (err) {

      console.error(
        "❌ Login error:",
        err.message
      );

      return res.status(500).json({
        success: false,
        error:
          "Login failed"
      });
    }
  }
);

// =====================================
// PROFILE
// =====================================
app.get(
  "/api/profile",
  verifyToken,
  async (req, res) => {

    return res.json({
      success: true,
      user: {
        userId:
          req.user.userId,
        email:
          req.user.email
      }
    });
  }
);

// =====================================
// ADD CONTACT
// IMPORTANT:
// USER EMAIL COMES FROM JWT
// NOT REQUEST BODY
// =====================================
app.post(
  "/add-contact",
  verifyToken,
  async (req, res) => {

    try {

      const name =
        safeString(
          req.body.name,
          100
        );

      const phone =
        safeString(
          req.body.phone,
          20
        );

      const relationship =
        safeString(
          req.body.relationship ||
            "Contact",
          100
        );

      if (
        !name ||
        !phone
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Name and phone are required"
        });
      }

      if (
        !isValidPhone(phone)
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid phone number format"
        });
      }

      const contact =
        new Contact({
          userEmail:
            req.user.email,
          name,
          phone,
          relationship
        });

      await contact.save();

      await recordAudit(
        "CONTACT_CREATED",
        req.user.email,
        true
      );

      return res.status(201).json({
        success: true,
        contact
      });

    } catch (err) {

      console.error(
        "❌ Add contact error:",
        err.message
      );

      return res.status(500).json({
        success: false,
        error:
          "Failed to add contact"
      });
    }
  }
);

// =====================================
// GET CONTACTS
// PROTECTED
// =====================================
app.get(
  "/contacts",
  verifyToken,
  async (req, res) => {

    try {

      const contacts =
        await Contact.find({
          userEmail:
            req.user.email
        }).sort({
          createdAt: -1
        });

      return res.json({
        success: true,
        contacts
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to fetch contacts"
      });
    }
  }
);

// =====================================
// LEGACY GET CONTACTS ROUTE
// PROTECTED
// ONLY ALLOWS CURRENT USER
// =====================================
app.get(
  "/contacts/:email",
  verifyToken,
  async (req, res) => {

    try {

      const requestedEmail =
        normalizeEmail(
          req.params.email
        );

      if (
        requestedEmail !==
        req.user.email
      ) {
        await recordAudit(
          "CROSS_USER_CONTACT_ACCESS_BLOCKED",
          req.user.email,
          false
        );

        return res.status(403).json({
          success: false,
          error:
            "You cannot access another user's contacts"
        });
      }

      const contacts =
        await Contact.find({
          userEmail:
            req.user.email
        }).sort({
          createdAt: -1
        });

      return res.json({
        success: true,
        contacts
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to fetch contacts"
      });
    }
  }
);

// =====================================
// DELETE CONTACT
// PROTECTED + OWNERSHIP CHECK
// =====================================
app.delete(
  "/delete-contact/:id",
  verifyToken,
  async (req, res) => {

    try {

      if (
        !mongoose.Types.ObjectId.isValid(
          req.params.id
        )
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid contact ID"
        });
      }

      const contact =
        await Contact.findOne({
          _id: req.params.id,
          userEmail:
            req.user.email
        });

      if (!contact) {

        await recordAudit(
          "CONTACT_DELETE_BLOCKED",
          req.user.email,
          false
        );

        return res.status(404).json({
          success: false,
          error:
            "Contact not found"
        });
      }

      await Contact.deleteOne({
        _id: contact._id
      });

      await recordAudit(
        "CONTACT_DELETED",
        req.user.email,
        true
      );

      return res.json({
        success: true,
        message:
          "Contact deleted"
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to delete contact"
      });
    }
  }
);

// =====================================
// UPDATE LOCATION
// USER EMAIL COMES FROM JWT
// =====================================
app.post(
  "/update-location",
  verifyToken,
  async (req, res) => {

    try {

      const latitude =
        Number(
          req.body.latitude
        );

      const longitude =
        Number(
          req.body.longitude
        );

      const accuracy =
        req.body.accuracy ===
        undefined
          ? 0
          : Number(
              req.body.accuracy
            );

      if (
        !isValidCoordinate(
          latitude
        ) ||
        latitude < -90 ||
        latitude > 90
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid latitude"
        });
      }

      if (
        !isValidCoordinate(
          longitude
        ) ||
        longitude < -180 ||
        longitude > 180
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid longitude"
        });
      }

      if (
        !Number.isFinite(
          accuracy
        ) ||
        accuracy < 0
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid accuracy"
        });
      }

      const location =
        new Location({
          userEmail:
            req.user.email,
          latitude,
          longitude,
          accuracy
        });

      await location.save();

      // IMPORTANT:
      // Do not broadcast every user's location
      // globally without authorization.
      io.to(
        `user:${req.user.userId}`
      ).emit(
        "live_location",
        location
      );

      await recordAudit(
        "LOCATION_UPDATED",
        req.user.email,
        true
      );

      return res.json({
        success: true,
        location
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to update location"
      });
    }
  }
);

// =====================================
// GET MY LOCATIONS
// =====================================
app.get(
  "/my-locations",
  verifyToken,
  async (req, res) => {

    try {

      const locations =
        await Location.find({
          userEmail:
            req.user.email
        })
        .sort({
          timestamp: -1
        })
        .limit(100);

      return res.json({
        success: true,
        locations
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to fetch locations"
      });
    }
  }
);

// =====================================
// CREATE INCIDENT
// USER OWNS INCIDENT
// =====================================
app.post(
  "/create-incident",
  verifyToken,
  async (req, res) => {

    try {

      const type =
        safeString(
          req.body.type ||
            "SOS",
          50
        );

      const severity =
        safeString(
          req.body.severity ||
            "HIGH",
          30
        );

      const location =
        safeString(
          req.body.location ||
            "Unknown",
          500
        );

      const incident =
        new Incident({
          incidentId:
            "GX-" +
            Date.now() +
            "-" +
            crypto
              .randomBytes(4)
              .toString("hex"),

          userEmail:
            req.user.email,

          type,
          severity,
          location,

          status:
            "ACTIVE"
        });

      await incident.save();

      io.to(
        `user:${req.user.userId}`
      ).emit(
        "new_incident",
        incident
      );

      await recordAudit(
        "INCIDENT_CREATED",
        req.user.email,
        true
      );

      return res.status(201).json({
        success: true,
        incident
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to create incident"
      });
    }
  }
);

// =====================================
// GET MY INCIDENTS
// =====================================
app.get(
  "/incidents",
  verifyToken,
  async (req, res) => {

    try {

      const incidents =
        await Incident.find({
          userEmail:
            req.user.email
        })
        .sort({
          createdAt: -1
        })
        .limit(100);

      return res.json({
        success: true,
        incidents
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to fetch incidents"
      });
    }
  }
);

// =====================================
// RESOLVE INCIDENT
// ADMIN ONLY
// =====================================
app.put(
  "/resolve-incident/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {

    try {

      if (
        !mongoose.Types.ObjectId.isValid(
          req.params.id
        )
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid incident ID"
        });
      }

      const updatedIncident =
        await Incident.findByIdAndUpdate(
          req.params.id,
          {
            status:
              "RESOLVED"
          },
          {
            new: true
          }
        );

      if (
        !updatedIncident
      ) {
        return res.status(404).json({
          success: false,
          error:
            "Incident not found"
        });
      }

      await recordAudit(
        "INCIDENT_RESOLVED_BY_ADMIN",
        req.user.email,
        true
      );

      return res.json({
        success: true,
        incident:
          updatedIncident
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to resolve incident"
      });
    }
  }
);

// =====================================
// DELETE INCIDENT
// ADMIN ONLY
// =====================================
app.delete(
  "/delete-incident/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {

    try {

      if (
        !mongoose.Types.ObjectId.isValid(
          req.params.id
        )
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Invalid incident ID"
        });
      }

      const incident =
        await Incident.findById(
          req.params.id
        );

      if (!incident) {
        return res.status(404).json({
          success: false,
          error:
            "Incident not found"
        });
      }

      await Incident.deleteOne({
        _id: incident._id
      });

      await recordAudit(
        "INCIDENT_DELETED_BY_ADMIN",
        req.user.email,
        true
      );

      return res.json({
        success: true,
        message:
          "Incident deleted"
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to delete incident"
      });
    }
  }
);

// =====================================
// GET ALL USERS
// ADMIN ONLY
// =====================================
app.get(
  "/admin/users",
  verifyToken,
  verifyAdmin,
  async (req, res) => {

    try {

      const users =
        await User.find()
          .select(
            "-password"
          )
          .sort({
            createdAt: -1
          });

      return res.json({
        success: true,
        users
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to fetch users"
      });
    }
  }
);

// =====================================
// UPLOAD EVIDENCE
// PROTECTED
// =====================================
app.post(
  "/upload-evidence",
  verifyToken,
  async (req, res) => {

    try {

      const incidentId =
        safeString(
          req.body.incidentId,
          100
        );

      const type =
        safeString(
          req.body.type ||
            "PHOTO",
          50
        );

      const fileUrl =
        safeString(
          req.body.fileUrl,
          2000
        );

      const description =
        safeString(
          req.body.description ||
            "",
          1000
        );

      if (
        !incidentId ||
        !fileUrl
      ) {
        return res.status(400).json({
          success: false,
          error:
            "Incident ID and file URL are required"
        });
      }

      const incident =
        await Incident.findOne({
          incidentId,
          userEmail:
            req.user.email
        });

      if (!incident) {

        await recordAudit(
          "EVIDENCE_UPLOAD_BLOCKED",
          req.user.email,
          false
        );

        return res.status(403).json({
          success: false,
          error:
            "Unauthorized incident access"
        });
      }

      const integrityHash =
        crypto
          .createHash("sha256")
          .update(
            `${incidentId}|${req.user.email}|${fileUrl}|${Date.now()}`
          )
          .digest("hex");

      const evidence =
        new Evidence({
          incidentId,
          userEmail:
            req.user.email,
          type,
          fileUrl,
          description,
          integrityHash
        });

      await evidence.save();

      io.to(
        `user:${req.user.userId}`
      ).emit(
        "new_evidence",
        evidence
      );

      await recordAudit(
        "EVIDENCE_CREATED",
        req.user.email,
        true
      );

      return res.status(201).json({
        success: true,
        evidence
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to upload evidence"
      });
    }
  }
);

// =====================================
// GET MY EVIDENCE
// =====================================
app.get(
  "/evidence",
  verifyToken,
  async (req, res) => {

    try {

      const evidence =
        await Evidence.find({
          userEmail:
            req.user.email
        })
        .sort({
          timestamp: -1
        })
        .limit(100);

      return res.json({
        success: true,
        evidence
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to fetch evidence"
      });
    }
  }
);

// =====================================
// SOS ROUTE
// PROTECTED
// USER EMAIL COMES FROM JWT
// =====================================
app.post(
  "/sos",
  verifyToken,
  sosLimiter,
  async (req, res) => {

    try {

      const location =
        safeString(
          req.body.location,
          500
        );

      if (!location) {
        return res.status(400).json({
          success: false,
          error:
            "Location is required"
        });
      }

      if (!client) {
        return res.status(503).json({
          success: false,
          error:
            "Emergency messaging service is not configured"
        });
      }

      if (
        !process.env.TWILIO_PHONE_NUMBER
      ) {
        return res.status(503).json({
          success: false,
          error:
            "Emergency messaging number is not configured"
        });
      }

      // =====================================
      // CREATE INCIDENT FIRST
      // =====================================
      const incident =
        new Incident({
          incidentId:
            "GX-SOS-" +
            Date.now() +
            "-" +
            crypto
              .randomBytes(4)
              .toString("hex"),

          userEmail:
            req.user.email,

          type:
            "SOS",

          severity:
            "HIGH",

          location,

          status:
            "ACTIVE"
        });

      await incident.save();

      // =====================================
      // GET ONLY THIS USER'S CONTACTS
      // =====================================
      const contacts =
        await Contact.find({
          userEmail:
            req.user.email
        });

      if (
        contacts.length === 0
      ) {

        await recordAudit(
          "SOS_NO_CONTACTS",
          req.user.email,
          false
        );

        return res.status(200).json({
          success: true,
          incidentId:
            incident.incidentId,
          contactsAlerted: 0,
          message:
            "SOS recorded, but no emergency contacts are configured"
        });
      }

      // =====================================
      // SEND ALERTS
      // =====================================
      const results = [];

      for (
        const contact of contacts
      ) {

        try {

          const message =
            await client.messages.create({
              body:
`🚨 GUARDIAN X SOS ALERT

An emergency alert has been triggered.

📍 Location:
${location}

Guardian X Emergency Incident:
${incident.incidentId}`,

              from:
                process.env
                  .TWILIO_PHONE_NUMBER,

              to:
                contact.phone
            });

          results.push({
            contactId:
              String(
                contact._id
              ),
            success:
              true,
            messageSid:
              message.sid
          });

        } catch (smsError) {

          console.error(
            "⚠️ Twilio message failed for contact"
          );

          results.push({
            contactId:
              String(
                contact._id
              ),
            success:
              false
          });
        }
      }

      const successful =
        results.filter(
          (item) =>
            item.success
        ).length;

      const failed =
        results.length -
        successful;

      await recordAudit(
        "SOS_TRIGGERED",
        req.user.email,
        successful > 0
      );

      return res.status(200).json({
        success: true,

        incidentId:
          incident.incidentId,

        contactsTotal:
          contacts.length,

        contactsAlerted:
          successful,

        contactsFailed:
          failed,

        message:
          failed === 0
            ? "SOS alerts sent successfully"
            : "SOS recorded with partial notification results"
      });

    } catch (err) {

      console.error(
        "❌ SOS processing error:",
        err.message
      );

      await recordAudit(
        "SOS_FAILED",
        req.user?.email || "",
        false
      );

      return res.status(500).json({
        success: false,
        error:
          "SOS processing failed"
      });
    }
  }
);

// =====================================
// ADMIN AUDIT LOG
// =====================================
app.get(
  "/admin/audit",
  verifyToken,
  verifyAdmin,
  async (req, res) => {

    try {

      const logs =
        await Audit.find()
          .sort({
            createdAt: -1
          })
          .limit(500);

      return res.json({
        success: true,
        logs
      });

    } catch (err) {

      return res.status(500).json({
        success: false,
        error:
          "Failed to fetch audit logs"
      });
    }
  }
);

// =====================================
// SOCKET.IO AUTHENTICATION
// =====================================
io.use(
  (socket, next) => {

    try {

      const token =
        socket.handshake.auth?.token;

      if (
        !token ||
        typeof token !==
          "string"
      ) {
        return next(
          new Error(
            "Authentication required"
          )
        );
      }

      const decoded =
        jwt.verify(
          token,
          process.env.JWT_SECRET
        );

      if (
        !decoded ||
        !decoded.userId ||
        !decoded.email
      ) {
        return next(
          new Error(
            "Invalid authentication token"
          )
        );
      }

      socket.user = {
        userId:
          String(
            decoded.userId
          ),
        email:
          normalizeEmail(
            decoded.email
          )
      };

      next();

    } catch (err) {

      return next(
        new Error(
          "Invalid or expired token"
        )
      );
    }
  }
);

// =====================================
// SOCKET CONNECTION
// =====================================
io.on(
  "connection",
  (socket) => {

    console.log(
      "🔌 Authenticated client connected:",
      socket.id
    );

    // =====================================
    // PRIVATE USER ROOM
    // =====================================
    socket.join(
      `user:${socket.user.userId}`
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
// 404 ROUTE HANDLER
// =====================================
app.use(
  (req, res) => {

    return res.status(404).json({
      success: false,
      error:
        "Route not found"
    });
  }
);

// =====================================
// GLOBAL ERROR HANDLER
// =====================================
app.use(
  (
    err,
    req,
    res,
    next
  ) => {

    console.error(
      "❌ Server Error:",
      err.message
    );

    return res.status(500).json({
      success: false,
      error:
        "Internal server error"
    });
  }
);

// =====================================
// START SERVER
// =====================================
server.listen(
  PORT,
  () => {

    console.log(
      `🚀 Guardian X backend running on port ${PORT}`
    );
  }
);

// =====================================
// PROCESS ERROR HANDLERS
// =====================================
process.on(
  "unhandledRejection",
  (err) => {

    console.error(
      "❌ Unhandled Rejection:",
      err.message
    );
  }
);

process.on(
  "uncaughtException",
  (err) => {

    console.error(
      "❌ Uncaught Exception:",
      err.message
    );
  }
);
