import rateLimit from "express-rate-limit";

// IP limiter
export const ipLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 100, // generic ceiling
  standardHeaders: true,
  legacyHeaders: false,
});

// Strict login limiter (per IP)
export const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 10, // 10 attempts / 10 min / IP
  message: { error: "Too many login attempts. Try again in a few minutes." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Start-register limiter (per IP)
export const startRegisterLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 12, // email discovery limited
  message: { error: "Too many requests. Try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Verify-OTP limiter (per IP)
export const verifyOtpLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  message: { error: "Too many code attempts. Try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

// Forgot/reset throttles
export const forgotLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 8,
  message: { error: "Too many reset requests. Try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});
