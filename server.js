import express from "express";
import mongoose from "mongoose";
import cors from "cors";
import helmet from "helmet";
import morgan from "morgan";
import rateLimit from "express-rate-limit";
import authRoutes from "./routes/auth.js";
import dotenv from "dotenv";

dotenv.config();
import { transport } from "./lib/email.js";

import cors from "cors";

const allowed = process.env.CORS_ORIGIN?.split(",").map((s) => s.trim()) || [];
app.use(
  cors({
    origin: (origin, cb) => {
      if (!origin || allowed.includes(origin)) return cb(null, true);
      cb(new Error("Not allowed by CORS"));
    },
    credentials: true,
  })
);

(async () => {
  try {
    await transport.verify();
    console.log("📧 Gmail SMTP ready");
  } catch (e) {
    console.error("❌ Gmail SMTP error:", e.message);
  }
})();

const app = express();
app.use(express.json());
app.use(cors({ origin: true, credentials: true }));
app.use(helmet());
app.use(morgan("dev"));
app.use(rateLimit({ windowMs: 60_000, max: 100 }));

app.use("/api/auth", authRoutes);

const PORT = process.env.PORT || 5000;
const uri = process.env.MONGO_URI;

if (!uri) {
  console.error("❌ MONGO_URI is missing in backend/.env");
  process.exit(1);
}

mongoose
  .connect(uri, {
    serverSelectionTimeoutMS: 10000,
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
  })
  .then(() => {
    console.log("✅ MongoDB connected");
    app.listen(PORT, () => console.log(`API running on port ${PORT}`));
  })
  .catch((err) => {
    console.error("❌ MongoDB connection error:", err.message);
    process.exit(1);
  });
