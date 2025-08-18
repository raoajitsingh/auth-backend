import { z } from "zod";

export const emailSchema = z.string().email("Invalid email");

export const passwordSchema = z
  .string()
  .min(8, "At least 8 chars")
  .regex(/[A-Z]/, "1 uppercase required")
  .regex(/[a-z]/, "1 lowercase required")
  .regex(/[0-9]/, "1 number required")
  .regex(/[^A-Za-z0-9]/, "1 special char required");

export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1),
});

export const otpRequestSchema = z.object({
  email: emailSchema,
});

export const otpVerifySchema = z.object({
  email: emailSchema,
  code: z.string().length(6, "OTP must be 6 digits"),
});

export const resetPasswordSchema = z.object({
  email: emailSchema,
  code: z.string().length(6),
  newPassword: passwordSchema,
});
