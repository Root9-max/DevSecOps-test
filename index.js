/*
 * This code was adapted from the following YouTube tutorials:
 * - Traversy Media, "Node.js & Express From Scratch", available at: https://www.youtube.com/watch?v=0-S5a0eXPoc&t=353s
 * - CodeAcademy, "Build a RESTful API with Node.js, Express, and MongoDB", available at: https://www.youtube.com/watch?v=ZBCUegTZF7M
 */
import './config.js'; // Load environment variables first
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import helmet from 'helmet';
import https from 'https';
import fs from 'fs';
import morgan from 'morgan';
import connectDB from './db/conn.js';
import authRoutes from './Routes/auth.js';
import paymentRoutes from './Routes/paymentRoutes.js';
import LoginAttemptLogger from './middleware/LoginAttemptLogger.js';
import adminRoutes from './Routes/adminlogin.js';
import inputValidator from './middleware/inputValidator.js';
import userRoutes from './Routes/userRoute.js';
import session from 'express-session';
import rateLimit from 'express-rate-limit'; // Add rate-limiting module

const app = express();
const PORT = process.env.PORT || 3005;
const whitelistPattern = /^[a-zA-Z0-9\s@.\-_]+$/;

// Connect to database
connectDB();

// **DDoS Prevention: Rate Limiting**
// Define rate-limiting middleware (max 100 requests per 15 minutes)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again after 15 minutes',
});

// Apply rate limiting to all routes
app.use(limiter);

// **IP Blocking** - Example of blocking specific IPs
const blockedIps = ['192.168.1.1'];  // Add blocked IPs to this array

app.use((req, res, next) => {
  if (blockedIps.includes(req.ip)) {
    return res.status(403).send('Access Denied');
  }
  next();
});

// General middleware for CORS, JSON parsing, and request logging
app.use(cors());
app.use(express.json());
app.use(morgan('combined'));

// Security headers with Helmet
app.use(helmet());

// Clickjacking Protection
app.use(helmet.frameguard({ action: 'deny' }));
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});

// HTTPS Strict Transport Security (HSTS)
app.use(
  helmet.hsts({
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true,
  })
);

// Content Security Policy (CSP)
app.use(
  helmet.contentSecurityPolicy({
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      objectSrc: ["'none'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:"],
      fontSrc: ["'self'"],
      connectSrc: ["'self'"],
      frameAncestors: ["'none'"],
    },
  })
);

// Session Hijacking Protection
app.use(
  session({
    secret: 'your-secret-key', // Replace with a strong secret
    resave: false,
    saveUninitialized: true,
    cookie: {
      secure: process.env.NODE_ENV === 'production',
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24, // Session expiry set to 1 day
    },
  })
);

// Middleware to enforce HTTPS
app.use((req, res, next) => {
  if (req.protocol === 'http') {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// Custom middleware for logging login attempts (e.g., for brute-force protection)
app.use(LoginAttemptLogger);

// Routes with Input Validation for SQL Injection Prevention
app.use('/api/auth', inputValidator(whitelistPattern), authRoutes);
app.use('/api/payment', inputValidator(whitelistPattern), paymentRoutes);
app.use('/api/admin', inputValidator(whitelistPattern), adminRoutes);
app.use('/api/users', inputValidator(whitelistPattern), userRoutes);

// SSL Certificate and key for HTTPS
const options = {
  key: fs.readFileSync('keys/key.pem'),
  cert: fs.readFileSync('keys/cert.pem'),
};

// Start the HTTPS server
https.createServer(options, app).listen(PORT, () => {
  console.log(`Server is running securely on https://localhost:${PORT}`);
});
