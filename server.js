// PhishInbox — Backend Server
// Proxy between Chrome extension and Claude API
// Deploy on Render.com — set ANTHROPIC_API_KEY in environment variables

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const { requestRateLimiter } = require("./middleware/rateLimit");
const analyzeRouter = require("./routes/analyze");

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.ANTHROPIC_API_KEY) {
  console.error("FATAL: ANTHROPIC_API_KEY environment variable is not set.");
  process.exit(1);
}

// ── CORS — allow Chrome extensions and local testing only ─────────────────
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (server-to-server, curl, health checks)
    if (!origin) return callback(null, true);
    // Allow any Chrome extension origin
    if (origin.startsWith("chrome-extension://")) return callback(null, true);
    // Allow local development
    if (origin === "http://localhost:3000" || origin === "http://127.0.0.1:3000") return callback(null, true);
    // Block everything else
    console.warn(`[PhishInbox] Blocked CORS request from origin: ${origin}`);
    return callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"]
}));

// ── Body parsing ──────────────────────────────────────────────────────────
app.use(express.json({ limit: "50kb" }));

// ── Request logging ───────────────────────────────────────────────────────
app.use((req, res, next) => {
  const ts = new Date().toISOString();
  console.log(`[${ts}] ${req.method} ${req.path} — origin: ${req.get("origin") || "none"}`);
  next();
});

// ── Health check ──────────────────────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok", service: "PhishInbox API", timestamp: new Date().toISOString() });
});

// ── Analysis endpoint ─────────────────────────────────────────────────────
app.post("/analyze", requestRateLimiter, analyzeRouter);

// ── 404 handler ───────────────────────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: "NOT_FOUND" });
});

// ── Global error handler ──────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error("[PhishInbox] Unhandled error:", err.message);
  if (err.message === "Not allowed by CORS") {
    return res.status(403).json({ error: "FORBIDDEN" });
  }
  res.status(500).json({
    error: "SERVER_ERROR",
    message: "Something went wrong on our end. Please try again in a moment."
  });
});

// ── Start ─────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[PhishInbox] Server running on port ${PORT}`);
  console.log(`[PhishInbox] Environment: ${process.env.NODE_ENV || "development"}`);
  console.log(`[PhishInbox] Health check: http://localhost:${PORT}/health`);
});
