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
