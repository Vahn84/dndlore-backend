import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bodyParser from 'body-parser';
import session from 'express-session';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import sharp from 'sharp';
import fs from 'fs';
import path from 'path';
import mongoose from 'mongoose';

// Carica variabili d'ambiente con valori di default
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || 'http://localhost:3000';
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3001;
const SESSION_SECRET = process.env.SESSION_SECRET || 'supersecret';
const JWT_SECRET = process.env.JWT_SECRET || 'jwtsecret';

// MongoDB connection options - allow self-signed certificates on public/free WiFi
const mongoOptions = {
  tls: true,
  tlsAllowInvalidCertificates:
    process.env.NODE_ENV === 'development' ||
    process.env.ALLOW_INVALID_CERTS === 'true',
  tlsAllowInvalidHostnames:
    process.env.NODE_ENV === 'development' ||
    process.env.ALLOW_INVALID_CERTS === 'true',
};

// Connessione a MongoDB
const MONGO_URI = process.env.MONGO_URI;

mongoose
  .connect(MONGO_URI, mongoOptions)
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('MongoDB connection error', err));

const app = express();

// Health check endpoint for Docker
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

// Abilita CORS
app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true,
  })
);
app.use(
  bodyParser.json({
    limit: process.env.REQUEST_LIMIT || '25mb',
  })
);
app.use(
  bodyParser.urlencoded({
    extended: true,
    limit: process.env.REQUEST_LIMIT || '25mb',
  })
);

// Configurazione sessione (necessaria per Passport)
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
    },
  })
);

// Inizializza Passport
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => {
  done(null, user);
});
passport.deserializeUser((user, done) => {
  done(null, user);
});

// Gestione uploads
const UPLOADS_PATH = process.env.UPLOADS_PATH || path.resolve('.', 'uploads');
fs.mkdirSync(UPLOADS_PATH, { recursive: true });
app.use('/uploads', express.static(UPLOADS_PATH));

// Middleware per autenticazione JWT
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ error: 'Missing Authorization header' });
  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// Middleware per richiedere il ruolo DM
function requireDM(req, res, next) {
  requireAuth(req, res, () => {
    if (!req.user || req.user.role !== 'DM') {
      return res
        .status(403)
        .json({ error: 'Forbidden: DM role required' });
    }
    next();
  });
}

// Avvio server
app.listen(PORT, async () => {
  console.log(`Backend listening on port ${PORT}`);
});

export { app, requireAuth, requireDM, MONGO_URI, UPLOADS_PATH };