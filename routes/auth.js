// routes/auth.js
import { Router } from "express";
import { z } from "zod";
import bcrypt from "bcrypt";
import crypto from "crypto";
import jwt from "jsonwebtoken";

import { verifyTurnstile } from "../middleware/verifyTurnstile.js"; // keep this import
import User from "../models/User.js";
import { transport } from "../lib/email.js";

import {
  loginLimiter,
  startRegisterLimiter,
  verifyOtpLimiter,
  forgotLimiter,
} from "../middleware/rate.js";

/* ========= Zod validators ========= */
const emailSchema = z.string().email("Invalid email format");
const passwordSchema = z
  .string()
  .min(8, "Password must be at least 8 characters")
  .regex(/[A-Z]/, "Must contain an uppercase letter")
  .regex(/[a-z]/, "Must contain a lowercase letter")
  .regex(/[0-9]/, "Must contain a number")
  .regex(/[^A-Za-z0-9]/, "Must contain a special character");

// Token is verified by middleware; keep optional here to avoid double-failing
const completeRegisterSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  cf_turnstile_token: z.string().min(1).optional(),
});

/* ========= Helpers ========= */
const router = Router();
const normEmail = (raw) => emailSchema.parse(raw).toLowerCase();

const signToken = (id) =>
  jwt.sign({ sub: id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES || "7d",
  });

async function sendOtpEmail(to, subject, code) {
  await transport.sendMail({
    from: process.env.GMAIL_USER,
    to,
    subject,
    text: `Your OTP code is ${code}. It expires in 10 minutes.`,
  });
}

/* ========= 1) START REGISTER ========= */
router.post("/start-register", startRegisterLimiter, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email);

    let user = await User.findOne({ email });

    // Fully registered user → block
    if (user && user.isVerified && user.passwordHash) {
      return res.status(409).json({ error: "Email already registered" });
    }

    // Create pending user if doesn't exist
    if (!user) {
      user = await User.create({ email, isVerified: false });
    }

    // Throttle OTP sending (1 per 60 seconds)
    if (
      user.lastOtpSentAt &&
      Date.now() - user.lastOtpSentAt.getTime() < 60_000
    ) {
      return res
        .status(429)
        .json({ error: "Please wait before requesting another code" });
    }

    // Generate and store OTP
    const code = crypto.randomInt(100000, 999999).toString();
    user.otpCode = code;
    user.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 mins
    user.lastOtpSentAt = new Date();
    user.otpVerified = false;
    await user.save();

    // Send OTP via email
    await sendOtpEmail(email, "Verify your email", code);

    res.json({ message: "OTP sent to email", step: "otp" });
  } catch (e) {
    next(e);
  }
});

/* ========= 2) VERIFY OTP ========= */
router.post("/verify-otp", verifyOtpLimiter, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email);
    const { code } = req.body;

    if (!/^\d{6}$/.test(code || "")) {
      return res.status(400).json({ error: "Invalid code format" });
    }

    const user = await User.findOne({ email });
    if (!user || !user.otpCode || !user.otpExpiresAt) {
      return res.status(400).json({ error: "Invalid or expired code" });
    }

    if (user.otpCode !== code || user.otpExpiresAt < new Date()) {
      return res.status(400).json({ error: "Invalid or expired code" });
    }

    // Mark OTP verified
    user.otpCode = null;
    user.otpExpiresAt = null;
    user.otpVerified = true;
    await user.save();

    res.json({ message: "OTP verified", step: "password" });
  } catch (e) {
    next(e);
  }
});

/* ========= 3) COMPLETE REGISTER ========= */
router.post("/complete-register", verifyTurnstile, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email);
    const { password } = completeRegisterSchema.parse({ ...req.body, email });

    const user = await User.findOne({ email });
    if (!user) {
      return res
        .status(404)
        .json({ error: "User not found. Please register again." });
    }
    if (!user.otpVerified) {
      return res.status(403).json({ error: "Please verify OTP first" });
    }
    if (user.passwordHash) {
      return res.status(409).json({ error: "Account already completed" });
    }

    // Save password & mark fully verified
    user.passwordHash = await bcrypt.hash(password, 12);
    user.isVerified = true;
    user.otpVerified = false;
    await user.save();

    const token = signToken(user._id);
    res.json({ message: "Account created successfully", token });
  } catch (e) {
    next(e);
  }
});

/* ========= LOGIN ========= */
router.post("/login", loginLimiter, verifyTurnstile, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email);
    const { password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: "Email and password required" });
    }

    const user = await User.findOne({ email });
    if (!user || !user.passwordHash) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    if (!user.isVerified) {
      return res
        .status(403)
        .json({ error: "Please complete registration first" });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = signToken(user._id);
    res.json({ message: "Logged in", token });
  } catch (e) {
    next(e);
  }
});

/* ========= FORGOT PASSWORD (send OTP) ========= */
router.post(
  "/forgot-password",
  forgotLimiter,
  verifyTurnstile,
  async (req, res, next) => {
    try {
      const email = normEmail(req.body.email);

      const user = await User.findOne({ email });
      if (!user || !user.passwordHash) {
        return res.status(404).json({ error: "Account not found" });
      }

      // Throttle OTP sends
      if (
        user.lastOtpSentAt &&
        Date.now() - user.lastOtpSentAt.getTime() < 60_000
      ) {
        return res
          .status(429)
          .json({ error: "Please wait before requesting another code" });
      }

      const code = crypto.randomInt(100000, 999999).toString();
      user.otpCode = code;
      user.otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 min
      user.lastOtpSentAt = new Date();
      user.otpVerified = false;
      await user.save();

      await sendOtpEmail(email, "Reset your password", code);

      res.json({ message: "OTP sent to email", step: "otp" });
    } catch (e) {
      next(e);
    }
  }
);

/* ========= VERIFY FORGOT PASSWORD OTP ========= */
router.post("/verify-reset-otp", verifyOtpLimiter, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email);
    const { code } = req.body;

    if (!/^\d{6}$/.test(code || "")) {
      return res.status(400).json({ error: "Invalid code format" });
    }

    const user = await User.findOne({ email });
    if (!user || !user.otpCode || !user.otpExpiresAt) {
      return res.status(400).json({ error: "Invalid or expired code" });
    }

    if (user.otpCode !== code || user.otpExpiresAt < new Date()) {
      return res.status(400).json({ error: "Invalid or expired code" });
    }

    user.otpCode = null;
    user.otpExpiresAt = null;
    user.otpVerified = true;
    await user.save();

    res.json({ message: "OTP verified", step: "reset-password" });
  } catch (e) {
    next(e);
  }
});

/* ========= RESET PASSWORD ========= */
router.post("/reset-password", verifyTurnstile, async (req, res, next) => {
  try {
    const email = normEmail(req.body.email);
    const { password } = completeRegisterSchema.parse({ ...req.body, email });

    const user = await User.findOne({ email });
    if (!user || !user.passwordHash) {
      return res.status(404).json({ error: "Account not found" });
    }
    if (!user.otpVerified) {
      return res.status(403).json({ error: "Please verify OTP first" });
    }

    user.passwordHash = await bcrypt.hash(password, 12);
    user.otpVerified = false;
    await user.save();

    res.json({ message: "Password reset successful" });
  } catch (e) {
    next(e);
  }
});

export default router;
