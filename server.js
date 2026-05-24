// =====================================
// REGISTER ROUTE
// =====================================
app.post("/register", async (req, res) => {

  try {

    const { email, password } = req.body;

    if (!email || !password) {

      return res.status(400).json({
        error: "Missing email or password"
      });

    }

    const existingUser =
      await User.findOne({ email });

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
      message: "User registered successfully"
    });

  } catch (err) {

    return res.status(500).json({
      error: "Registration failed"
    });

  }

});

// =====================================
// LOGIN ROUTE
// =====================================
app.post("/login", async (req, res) => {

  try {

    const { email, password } = req.body;

    const user =
      await User.findOne({ email });

    if (!user) {

      return res.status(401).json({
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

    const contact =
      new Contact(req.body);

    await contact.save();

    return res.json({

      success: true,
      contact

    });

  } catch (err) {

    return res.status(500).json({
      error: "Failed to add contact"
    });

  }

});

// =====================================
// GET CONTACTS
// =====================================
app.get("/contacts/:email", async (req, res) => {

  const contacts =
    await Contact.find({

      userEmail:
        req.params.email

    });

  return res.json({

    success: true,
    contacts

  });

});

// =====================================
// UPDATE LOCATION
// =====================================
app.post("/update-location", async (req, res) => {

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

});

// =====================================
// CREATE INCIDENT
// =====================================
app.post("/create-incident", async (req, res) => {

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

});

// =====================================
// GET INCIDENTS
// =====================================
app.get("/incidents", async (req, res) => {

  const incidents =
    await Incident.find()
    .sort({ createdAt: -1 });

  return res.json({

    success: true,
    incidents

  });

});

// =====================================
// UPLOAD EVIDENCE
// =====================================
app.post("/upload-evidence", async (req, res) => {

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

});

// =====================================
// SEND SOS
// =====================================
app.post("/sos", async (req, res) => {

  try {

    const {
      email,
      location
    } = req.body;

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

        to: contact.phone

      });

    }

    return res.json({

      success: true,
      contactsAlerted:
        contacts.length

    });

  } catch (err) {

    return res.status(500).json({
      error: "SOS failed"
    });

  }

});
