// server.js
import "dotenv/config";
import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import authRoutes from "./routes/auth.js";
import { transport } from "./lib/email.js";

const app = express();
app.set("trust proxy", 1); // correct IPs behind Render/Proxy

/* ================== CORS ================== */
/**
 * Allow explicit origins from CORS_ORIGIN env (comma-separated)
 * and any *.vercel.app previews. Handles preflight cleanly.
 */
const explicitAllowed = (process.env.CORS_ORIGIN || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean);

function isAllowedOrigin(origin) {
  if (!origin) return true; // allow non-browser clients (Postman/cURL)
  try {
    const { hostname } = new URL(origin);
    if (hostname.endsWith(".vercel.app")) return true; // preview deploys
    return explicitAllowed.includes(origin);
  } catch {
    return false;
  }
}

// Help caches vary by Origin (important for proxies/CDNs)
app.use((req, res, next) => {
  res.header("Vary", "Origin");
  next();
});

app.use(
  cors({
    origin(origin, cb) {
      if (isAllowedOrigin(origin)) return cb(null, true);
      console.error("CORS blocked origin:", origin);
      return cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
  })
);
app.use((req, res) => res.status(404).json({ error: "Not found" }));

/* =============== Core middleware =============== */
app.use(express.json());
app.use(helmet());
app.use(morgan("dev"));
app.use(
  rateLimit({
    windowMs: 60_000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
  })
);

/* =============== Routes =============== */
app.get("/", (_req, res) => res.json({ ok: true, service: "auth-backend" }));
app.get("/health", (_req, res) => res.status(200).json({ ok: true }));

// All auth endpoints mounted under /api/auth/*
app.use("/api/auth", authRoutes);

/* =============== SMTP check (non-blocking) =============== */
(async () => {
  try {
    await transport.verify();
    console.log("📧 Gmail SMTP ready");
  } catch (e) {
    console.error("❌ Gmail SMTP error:", e.message);
  }
})();

/* =============== DB connect & start (listen ONCE) =============== */
const PORT = Number(process.env.PORT) || 5000;
const MONGO_URI = process.env.MONGO_URI;

if (!MONGO_URI) {
  console.error("❌ MONGO_URI is missing");
  process.exit(1);
}

mongoose
  .connect(MONGO_URI, {
    serverSelectionTimeoutMS: 10_000,
    socketTimeoutMS: 45_000,
    maxPoolSize: 10,
  })
  .then(() => {
    console.log("✅ MongoDB connected");
    app.listen(PORT, "0.0.0.0", () => {
      console.log(`API listening on ${PORT}`);
      if (process.env.PORT)
        console.log(`Render assigned PORT = ${process.env.PORT}`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });
