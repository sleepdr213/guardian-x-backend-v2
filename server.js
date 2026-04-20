const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

// ✅ Test route
app.get("/", (req, res) => {
  res.send("Guardian X backend is running 🚀");
});

// ✅ Status check
app.get("/status", (req, res) => {
  res.json({ status: "ok", system: "Guardian X" });
});

// 🚨 Health check (add this)
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    system: "guardian-x",
    uptime: process.uptime()
  });
});

// 🚨 Alert endpoint
app.post("/alert", (req, res) => {
  const data = req.body;
  console.log("ALERT RECEIVED:", data);

  res.json({
    success: true,
    message: "Alert received",
    data: data
  });
});

// 📷 Camera event (future use)
app.post("/camera", (req, res) => {
  console.log("Camera event:", req.body);

  res.json({
    success: true,
    message: "Camera data received"
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server running on port", PORT));
