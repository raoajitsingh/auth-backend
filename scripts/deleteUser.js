import mongoose from "mongoose";
import dotenv from "dotenv";
import User from "../models/User.js";

dotenv.config({ path: "../.env" });

async function deleteUser() {
  await mongoose.connect(process.env.MONGO_URI);

  const email = "ajju64@gmail.com"; // <-- change to the email you want to remove
  const result = await User.deleteOne({ email });

  console.log(`Deleted: ${result.deletedCount} user(s)`);
  await mongoose.disconnect();
}

deleteUser();
