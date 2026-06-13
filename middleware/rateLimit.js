// PhishInbox — Rate Limiting Middleware
// Limits requests per installId to prevent abuse

const rateLimit = require("express-rate-limit");

// Hard request-rate limiter: max 10 requests per minute per IP
// This is the first line of defence against bots/scrapers.
const requestRateLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Prefer installId over IP so NAT users aren't blocked together
    return req.body?.installId || req.ip;
  },
  handler: (req, res) => {
    console.warn(`[PhishInbox] Rate limit hit for installId: ${req.body?.installId || req.ip}`);
    res.status(429).json({
      error: "RATE_LIMITED",
      message: "Too many requests. Please wait a moment and try again."
    });
  }
});

module.exports = { requestRateLimiter };
