const express = require("express");
const multer = require("multer");
const path = require("path");
const User = require("../models/user");
const router = express.Router();

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});
const upload = multer({ storage });

router.post("/save-profile", upload.single("profilePic"), async (req, res) => {
  try {
    const { email, name } = req.body;
    const profilePicPath = req.file ? `/uploads/${req.file.filename}` : undefined;

    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });

    user.name = name;
    if (profilePicPath) user.profilePic = profilePicPath;
    await user.save();

    res.json({ success: true, message: "Profile updated", profile: user });
  } catch (err) {
    console.error(err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

module.exports = router;
