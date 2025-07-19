const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  verified: { type: Boolean, default: false },
  otp: { type: String },
  otpExpires: { type: Date },
  name: { type: String },
  profilePic: { type: String },
  // NEW FIELDS FOR BMR/TDEE CALCULATION
  gender: { type: String, enum: ['male', 'female', 'other'], lowercase: true },
  age: { type: Number, min: 0 },
  height: { type: Number, min: 0 }, // in cm
  weight: { type: Number, min: 0 }, // in kg
  activityLevel: {
    type: String,
    enum: [
      'sedentary',        // Little to no exercise
      'lightly_active',   // Light exercise/sports 1-3 days/week
      'moderately_active',// Moderate exercise/sports 3-5 days/week
      'very_active',      // Hard exercise/sports 6-7 days/week
      'extra_active'      // Very hard exercise/physical job/training twice a day
    ],
    lowercase: true
  }
});

module.exports = mongoose.model("User", userSchema);