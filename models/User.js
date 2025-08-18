import mongoose from "mongoose";

const userSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      lowercase: true,
      unique: true,
      trim: true,
    },
    passwordHash: {
      type: String,
      default: null,
    },
    isVerified: {
      type: Boolean,
      default: false, // Full account verification
    },
    otpVerified: {
      type: Boolean,
      default: false, // Only OTP verification done
    },
    otpCode: {
      type: String,
      default: null,
    },
    otpExpiresAt: {
      type: Date,
      default: null,
    },
    lastOtpSentAt: {
      type: Date,
      default: null,
    },
  },
  { timestamps: true }
);

export default mongoose.model("User", userSchema);
