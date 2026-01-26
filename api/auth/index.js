import express from "express";
import { requireAuth } from "../../middleware/auth.js";
import passport from "passport";
import jwt from "jsonwebtoken";
import { User } from "../../models.js";

const router = express.Router();

// Helper function to refresh Google access token using refresh token
async function refreshGoogleToken(refreshToken) {
  try {
    // Create form data properly
    const formData = new URLSearchParams();
    formData.append("client_id", process.env.GOOGLE_CLIENT_ID);
    formData.append("client_secret", process.env.GOOGLE_CLIENT_SECRET);
    formData.append("refresh_token", refreshToken);
    formData.append("grant_type", "refresh_token");

    const response = await fetch("https://oauth2.googleapis.com/token", {
      method: "POST",
      headers: { 
        "Content-Type": "application/x-www-form-urlencoded" 
      },
      body: formData,
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error("Token refresh failed:", errorText);
      // Try to parse as JSON for better error details
      try {
        const errorJson = JSON.parse(errorText);
        console.error("Detailed error:", errorJson);
      } catch (e) {
        // If it's not JSON, just log the raw text
        console.error("Raw error response:", errorText);
      }
      return null;
    }

    const data = await response.json();
    // Google returns: { access_token, expires_in (seconds), scope, token_type }
    return {
      accessToken: data.access_token,
      expiresIn: data.expires_in, // seconds from now
    };
  } catch (err) {
    console.error("Error refreshing Google token:", err);
    return null;
  }
}


// Endpoint login locale
router.post("/auth/login", async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username, password });
  if (!user) return res.status(401).json({ error: "Invalid credentials" });
  const token = jwt.sign(
    { id: user._id, username: user.username, role: user.role },
    process.env.JWT_SECRET || "jwtsecret",
    { expiresIn: "1d" },
  );
  res.json({
    token,
    user: { id: user._id, username: user.username, role: user.role },
  });
});

// OAuth2 endpoints
router.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: [
      "profile",
      "email",
      "https://www.googleapis.com/auth/documents.readonly",
      "https://www.googleapis.com/auth/calendar.readonly",
      "https://www.googleapis.com/auth/calendar.events",
    ],
    accessType: "offline",
    prompt: "consent",
  }),
);
router.get(
  "/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    const user = req.user;
    const token = jwt.sign(
      {
        id: user._id,
        email: user.email,
        role: user.role,
        googleAccessToken: user.googleAccessToken,
      },
      process.env.JWT_SECRET || "jwtsecret",
      { expiresIn: "1d" },
    );
    res.redirect(
      `${process.env.FRONTEND_ORIGIN || "http://localhost:3000"}?token=${token}`,
    );
  },
);

// Endpoint per ottenere l'utente corrente
router.get("/auth/user", (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.json(null);
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || "jwtsecret");
    res.json(decoded);
  } catch (err) {
    res.status(401).json({ error: "Invalid token" });
  }
});

// Check Google token status for the authenticated user
router.get("/auth/google-token-status", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    const hasRefreshToken = !!user.googleRefreshToken;
    const hasAccessToken = !!user.googleAccessToken;
    const isExpired = user.googleTokenExpiry
      ? user.googleTokenExpiry < new Date()
      : true;

    res.json({
      connected: hasRefreshToken && hasAccessToken,
      expired: isExpired,
      tokenExpiry: user.googleTokenExpiry,
      needsReauth: !hasRefreshToken,
    });
  } catch (err) {
    console.error("Error checking Google token status:", err);
    res.status(500).json({ error: "Failed to check token status" });
  }
});

// Refresh Google access token using stored refresh token
router.post("/auth/refresh-google-token", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ error: "User not found" });

    if (!user.googleRefreshToken) {
      return res.status(400).json({
        error:
          "No refresh token available. Please reconnect your Google account.",
        needsReauth: true,
      });
    }

    const refreshed = await refreshGoogleToken(user.googleRefreshToken);
    if (!refreshed) {
      return res.status(500).json({
        error: "Failed to refresh token. Please reconnect your Google account.",
        needsReauth: true,
      });
    }

    // Update user with new access token and expiry
    user.googleAccessToken = refreshed.accessToken;
    user.googleTokenExpiry = new Date(Date.now() + refreshed.expiresIn * 1000);
    await user.save();

    // Generate new JWT with updated access token
    const newJwt = jwt.sign(
      {
        id: user._id,
        email: user.email,
        role: user.role,
        googleAccessToken: refreshed.accessToken,
      },
      process.env.JWT_SECRET || "jwtsecret",
      { expiresIn: "1d" },
    );

    res.json({
      token: newJwt,
      googleAccessToken: refreshed.accessToken,
      tokenExpiry: user.googleTokenExpiry,
    });
  } catch (err) {
    console.error("Error refreshing Google token:", err);
    res.status(500).json({ error: "Failed to refresh token" });
  }
});

// Logout
router.post("/auth/logout", (req, res) => {
  req.logout && req.logout();
  res.json({ success: true });
});

export default router;
export { refreshGoogleToken };