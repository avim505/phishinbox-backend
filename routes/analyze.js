// PhishInbox — Analysis Route
// Validates request, enforces free-tier limit, calls Claude, returns verdict

const express = require("express");
const Anthropic = require("@anthropic-ai/sdk");
const router = express.Router();

const client = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });

const CLAUDE_MODEL = "claude-sonnet-4-20250514";
const MAX_TOKENS = 1024;
const FREE_TIER_MONTHLY_LIMIT = 5;

const SYSTEM_PROMPT = `You are an expert cybersecurity analyst specializing in phishing email detection. You will analyze emails and identify phishing attempts with high accuracy.

Analyze the provided email for these phishing indicators:
1. Sender address legitimacy — does domain match claimed organization
2. Urgency and pressure tactics — creating panic or time pressure
3. Suspicious links or requests to click links
4. Requests for personal information, passwords, or payment details
5. Impersonation of trusted brands like banks, PayPal, Amazon, Microsoft, Google, Apple
6. Grammar and spelling inconsistencies unusual for the claimed sender
7. Mismatched or suspicious email domains
8. Too good to be true offers or unexpected prizes
9. Threats or consequences if user does not act
10. Requests to bypass normal security procedures

Respond ONLY with raw JSON. No markdown. No code fences. No explanation outside the JSON. Start your response directly with { and end with }

The JSON must follow this exact structure:
{
  "verdict": "SAFE" or "SUSPICIOUS" or "LIKELY_PHISHING" or "DANGEROUS",
  "confidence": number 0-100,
  "risk_score": number 0-100,
  "summary": "one sentence plain English summary",
  "red_flags": ["flag 1", "flag 2"] or [],
  "safe_signals": ["signal 1"] or [],
  "explanation": "2-3 sentence plain English explanation a grandparent could understand",
  "recommended_action": "what the user should do right now in plain English",
  "sender_analysis": "analysis of the sender email address",
  "urgency_detected": true or false,
  "impersonation_detected": true or false,
  "suspicious_links_mentioned": true or false
}`;

// In-memory monthly usage store — keyed by "installId|YYYY-M"
// No database needed for MVP. Resets naturally when server restarts or month changes.
const usageStore = new Map();

function getMonthKey(installId) {
  const now = new Date();
  return `${installId}|${now.getFullYear()}-${now.getMonth()}`;
}

function getUsageCount(installId) {
  const key = getMonthKey(installId);
  return usageStore.get(key) || 0;
}

function incrementUsage(installId) {
  const key = getMonthKey(installId);
  const current = usageStore.get(key) || 0;
  usageStore.set(key, current + 1);
  return current + 1;
}

function safeParseJSON(text) {
  try {
    return JSON.parse(text);
  } catch (_) {
    let cleaned = text.trim();
    cleaned = cleaned.replace(/^```json\s*/i, "").replace(/\s*```$/i, "");
    cleaned = cleaned.replace(/^```\s*/, "").replace(/\s*```$/, "");
    cleaned = cleaned.trim();
    const match = cleaned.match(/\{[\s\S]*\}/);
    if (match) {
      try { return JSON.parse(match[0]); } catch (_) { return null; }
    }
    return null;
  }
}

// POST /analyze
router.post("/", async (req, res) => {
  const timestamp = new Date().toISOString();
  const { emailText, installId } = req.body;

  console.log(`[${timestamp}] /analyze — installId: ${installId || "MISSING"} — emailText length: ${emailText?.length || 0}`);

  // ── Validation ────────────────────────────────────────────────────────────
  if (!installId || typeof installId !== "string" || installId.trim().length === 0) {
    return res.status(400).json({
      error: "MISSING_INSTALL_ID",
      message: "Something went wrong. Please try reinstalling the extension."
    });
  }

  if (!emailText || typeof emailText !== "string") {
    return res.status(400).json({
      error: "MISSING_EMAIL_TEXT",
      message: "This email does not have enough text to analyze."
    });
  }

  const trimmedText = emailText.trim();
  if (trimmedText.length < 50) {
    return res.status(400).json({
      error: "EMAIL_TOO_SHORT",
      message: "This email does not have enough text to analyze. Please make sure the email is fully loaded."
    });
  }

  // ── Free Tier Check ───────────────────────────────────────────────────────
  const currentCount = getUsageCount(installId);
  if (currentCount >= FREE_TIER_MONTHLY_LIMIT) {
    console.log(`[${timestamp}] LIMIT_REACHED — installId: ${installId}, count: ${currentCount}`);
    return res.status(429).json({
      error: "LIMIT_REACHED",
      message: "You have used all 5 free checks this month. Upgrade to Pro for unlimited protection.",
      usage: {
        checksThisMonth: currentCount,
        remaining: 0,
        limit: FREE_TIER_MONTHLY_LIMIT
      }
    });
  }

  // ── Truncate email body to keep token usage reasonable ───────────────────
  const truncatedText = trimmedText.length > 3000 ? trimmedText.substring(0, 3000) + "..." : trimmedText;

  // ── Call Claude ───────────────────────────────────────────────────────────
  let rawText = "";
  try {
    console.log(`[${timestamp}] Calling Claude for installId: ${installId}`);
    const response = await client.messages.create({
      model: CLAUDE_MODEL,
      max_tokens: MAX_TOKENS,
      system: SYSTEM_PROMPT,
      messages: [
        {
          role: "user",
          content: `Please analyze this email for phishing:\n\n${truncatedText}`
        }
      ]
    });

    rawText = response.content?.[0]?.text || "";
    console.log(`[${timestamp}] Claude responded — preview: ${rawText.substring(0, 80)}`);
  } catch (claudeError) {
    console.error(`[${timestamp}] Claude API error:`, claudeError.message);

    if (claudeError.status === 401) {
      return res.status(500).json({
        error: "SERVER_ERROR",
        message: "Something went wrong on our end. Please try again in a moment."
      });
    }
    if (claudeError.status === 429) {
      return res.status(503).json({
        error: "SERVER_BUSY",
        message: "Our servers are busy right now. Please try again in a moment."
      });
    }
    return res.status(500).json({
      error: "SERVER_ERROR",
      message: "Something went wrong on our end. Please try again in a moment."
    });
  }

  // ── Parse and Normalize JSON ──────────────────────────────────────────────
  const parsed = safeParseJSON(rawText);
  if (!parsed) {
    console.error(`[${timestamp}] Failed to parse Claude response as JSON`);
    return res.status(500).json({
      error: "PARSE_ERROR",
      message: "Something went wrong on our end. Please try again in a moment."
    });
  }

  // Normalize verdict
  const validVerdicts = ["SAFE", "SUSPICIOUS", "LIKELY_PHISHING", "DANGEROUS"];
  if (!validVerdicts.includes(parsed.verdict)) parsed.verdict = "SUSPICIOUS";

  // Normalize arrays
  parsed.red_flags = Array.isArray(parsed.red_flags) ? parsed.red_flags : [];
  parsed.safe_signals = Array.isArray(parsed.safe_signals) ? parsed.safe_signals : [];

  // Normalize numbers
  parsed.confidence = Math.min(100, Math.max(0, Number(parsed.confidence) || 50));
  parsed.risk_score = Math.min(100, Math.max(0, Number(parsed.risk_score) || 50));

  // Normalize booleans
  parsed.urgency_detected = Boolean(parsed.urgency_detected);
  parsed.impersonation_detected = Boolean(parsed.impersonation_detected);
  parsed.suspicious_links_mentioned = Boolean(parsed.suspicious_links_mentioned);

  // ── Increment Usage AFTER successful analysis ─────────────────────────────
  const newCount = incrementUsage(installId);
  const remaining = Math.max(0, FREE_TIER_MONTHLY_LIMIT - newCount);

  console.log(`[${timestamp}] Analysis complete — installId: ${installId}, verdict: ${parsed.verdict}, usageThisMonth: ${newCount}/${FREE_TIER_MONTHLY_LIMIT}`);

  return res.status(200).json({
    result: parsed,
    usage: {
      checksThisMonth: newCount,
      remaining,
      limit: FREE_TIER_MONTHLY_LIMIT
    }
  });
});

module.exports = router;
