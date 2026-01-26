import "dotenv/config";
import express from "express";
import cors from "cors";
import bodyParser from "body-parser";
import session from "express-session";
import "./config/passport.js"; // Ensure Passport strategies are registered
import passport from "passport";
import fs from "fs";
import mongoose from "mongoose";
import { UPLOADS_PATH } from "./utils/uploads.js";
import { requireDM } from "./middleware/auth.js";
import apiRouter from "./api/index.js";
// Add this debug code to your lightRag.js file temporarily:

// Carica variabili d'ambiente con valori di default
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "";
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3001;
const SESSION_SECRET = process.env.SESSION_SECRET || "supersecret";

// MongoDB connection options - allow self-signed certificates on public/free WiFi
const mongoOptions = {
  tls: true,
  tlsAllowInvalidCertificates:
    process.env.NODE_ENV === "development" ||
    process.env.ALLOW_INVALID_CERTS === "true",
  tlsAllowInvalidHostnames:
    process.env.NODE_ENV === "development" ||
    process.env.ALLOW_INVALID_CERTS === "true",
};

// Connessione a MongoDB
const MONGO_URI = process.env.MONGO_URI;

if (MONGO_URI) {
  mongoose
    .connect(MONGO_URI, mongoOptions)
    .then(() => console.log("Connected to MongoDB"))
    .catch((err) => console.error("MongoDB connection error", err));
} else {
  console.warn("MONGO_URI not set; skipping MongoDB connection");
}

const app = express();

// Health check endpoint for Docker
app.get("/health", (req, res) => {
  res.status(200).json({ status: "ok" });
});

// Abilita CORS
app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
  }),
);
app.use(
  bodyParser.json({
    limit: process.env.REQUEST_LIMIT || "25mb",
  }),
);
app.use(
  bodyParser.urlencoded({
    extended: true,
    limit: process.env.REQUEST_LIMIT || "25mb",
  }),
);

// Configurazione sessione (necessaria per Passport)
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
    },
  }),
);

// Inizializza Passport
app.use(passport.initialize());
app.use(passport.session());

app.use("/api", (req, res, next) => {
  console.log("DEBUG: API route hit:", req.method, req.path);
  next();
});


// Gestione uploads
fs.mkdirSync(UPLOADS_PATH, { recursive: true });
app.use("/api/uploads", requireDM, express.static(UPLOADS_PATH));

// Register API routes under /api prefix
app.use("/api", apiRouter);

app.all("/api/*", (req, res, next) => {
  console.log("DEBUG: API route pattern matched:", req.path);
  next();
});

// Avvio server
app.listen(PORT, async () => {
  console.log(`Backend listening on port ${PORT}`);
});

export { app };
