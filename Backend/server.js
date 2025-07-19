// 📌 Load environment variables
require("dotenv").config();

const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");
const multer = require("multer");
const path = require("path");
const fs = require("fs").promises; // Use fs.promises for async operations
const axios = require("axios");

// Import your Mongoose models
const User = require("./models/user");
const Food = require("./models/food");
const DailyLog = require("./models/dailyLog");

const app = express();
app.use(cors());
app.use(express.json());

// ✅ Serve static profile images (ONLY for local development or for pre-existing default images)
// For user-uploaded images in production on Vercel, you need cloud storage.
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

// ✅ Ensure uploads folder exists (primarily for local dev, Vercel functions don't persist locally)
fs.access(path.join(__dirname, "uploads"), fs.constants.F_OK)
  .catch(async (e) => {
    if (e.code === 'ENOENT') {
      console.log('uploads directory does not exist, creating it...');
      try {
        await fs.mkdir(path.join(__dirname, "uploads"));
        console.log('uploads directory created successfully.');
      } catch (err) {
        console.error('Failed to create uploads directory:', err);
      }
    } else {
      console.error('Error checking uploads directory:', e);
    }
  });


// ✅ Connect to MongoDB
mongoose
  .connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.error("❌ MongoDB Error:", err));

// Function to calculate TDEE using Mifflin-St Jeor Equation
function calculateTDEE(gender, age, heightCm, weightKg, activityLevel) {
    let bmr;

    if (age === null || heightCm === null || weightKg === null || age === undefined || heightCm === undefined || weightKg === undefined) {
      return null;
    }

    if (gender === 'male') {
        bmr = (10 * weightKg) + (6.25 * heightCm) - (5 * age) + 5;
    } else if (gender === 'female') {
        bmr = (10 * weightKg) + (6.25 * heightCm) - (5 * age) - 161;
    } else {
        return null;
    }

    let activityMultiplier;
    switch (activityLevel) {
        case 'sedentary':
            activityMultiplier = 1.2;
            break;
        case 'lightly_active':
            activityMultiplier = 1.375;
            break;
        case 'moderately_active':
            activityMultiplier = 1.55;
            break;
        case 'very_active':
            activityMultiplier = 1.725;
            break;
        case 'extra_active':
            activityMultiplier = 1.9;
            break;
        default:
            return null;
    }

    return Math.round(bmr * activityMultiplier);
}

// 📌 JWT Authentication Middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};


// 📌 Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// 📌 Multer setup for profile picture uploads
// Multer will still save to local /uploads temporarily for Vercel Serverless.
// However, THIS LOCAL FILE WILL NOT PERSIST after the function ends.
// For persistent storage, REPLACE THIS WITH CLOUD STORAGE UPLOAD LOGIC.
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // In Vercel, this is a temporary /tmp directory, not persistent
    cb(null, "/tmp/"); // Use /tmp for serverless functions
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + "-" + Math.round(Math.random() * 1e9);
    cb(null, uniqueSuffix + path.extname(file.originalname));
  },
});
const upload = multer({ storage });


// ➡️ SIGNUP: store email+password, send OTP
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.json({ success: false, message: "Email already registered" });

    const hashed = await bcrypt.hash(password, 10);
    const otp = Math.floor(100000 + Math.round(Math.random() * 900000)).toString();
    const otpExpires = new Date(Date.now() + 10 * 60 * 1000);

    await User.create({ email, password: hashed, verified: false, otp, otpExpires });

    console.log("Generated OTP:", otp);

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Verify your account",
      text: `Your OTP is ${otp}`,
    });

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Signup error:", err);
    res.json({ success: false, message: "Server error" });
  }
});

// ➡️ VERIFY OTP
app.post("/verify-otp", async (req, res) => {
  const { email, otp } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });

    if (user.otp === otp && user.otpExpires > new Date()) {
      user.verified = true;
      user.otp = undefined;
      user.otpExpires = undefined;
      await user.save();
      res.json({ success: true });
    } else {
      res.json({ success: false, message: "Invalid or expired OTP" });
    }
  } catch (err) {
    console.error("❌ Verify error:", err);
    res.json({ success: false, message: "Server error" });
  }
});

// ➡️ LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });
    if (!user.verified) return res.json({ success: false, message: "Account not verified. Please verify your email." });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.json({ success: false, message: "Invalid password" });

    const token = jwt.sign({ id: user._id, email: user.email }, process.env.JWT_SECRET, { expiresIn: "1d" });
    res.json({ success: true, token, email: user.email, name: user.name });
  } catch (err) {
    console.error("❌ Login error:", err);
    res.json({ success: false, message: "Server error" });
  }
});

// ➡️ SEND RESET OTP
app.post("/send-reset-otp", async (req, res) => {
  const { email } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });

    const otp = Math.floor(100000 + Math.round(Math.random() * 900000)).toString();
    user.otp = otp;
    user.otpExpires = new Date(Date.now() + 10 * 60 * 1000);
    await user.save();

    console.log("Generated OTP for reset:", otp);

    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP is ${otp}`,
    });

    res.json({ success: true });
  } catch (err) {
    console.error("❌ Reset OTP error:", err);
    res.json({ success: false, message: "Server error" });
  }
});

// ➡️ RESET PASSWORD
app.post("/reset-password", async (req, res) => {
  const { email, otp, newPass } = req.body;
  try {
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });

    if (user.otp === otp && user.otpExpires > new Date()) {
      const hashed = await bcrypt.hash(newPass, 10);
      user.password = hashed;
      user.otp = undefined;
      user.otpExpires = undefined;
      await user.save();
      res.json({ success: true });
    } else {
      res.json({ success: false, message: "Invalid or expired OTP" });
    }
  } catch (err) {
    console.error("❌ Reset error:", err);
    res.json({ success: false, message: "Server error" });
  }
});

// ➡️ SAVE PROFILE (name, profilePic, gender, age, height, weight, activityLevel)
app.post("/save-profile", upload.single("profilePic"), async (req, res) => {
  try {
    console.log('--- Backend /save-profile Request ---');
    console.log('Request Body:', req.body);
    console.log('Received File (req.file):', req.file);
    console.log('-----------------------------------');

    const { email, name, gender, age, height, weight, activityLevel, removeProfilePic } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: false, message: "User not found" });

    user.name = name;
    user.gender = gender;
    user.age = age ? parseInt(age) : undefined;
    user.height = height ? parseInt(height) : undefined;
    user.weight = weight ? parseFloat(weight) : undefined;
    user.activityLevel = activityLevel;

    // --- IMPORTANT: CLOUD STORAGE INTEGRATION HERE FOR PROFILE PICS ---
    if (req.file) {
        // STEP 1: UPLOAD THE FILE TO CLOUD STORAGE (e.g., Cloudinary, AWS S3)
        // Example with a placeholder for Cloudinary:
        // const uploadResult = await cloudinary.uploader.upload(req.file.path);
        // const newProfilePicUrl = uploadResult.secure_url; // Get URL from cloud service

        const newProfilePicUrl = `/uploads/${req.file.filename}`; // FOR LOCAL TESTING ONLY (WILL NOT PERSIST ON VERCEL)

        // STEP 2: DELETE THE TEMPORARY LOCAL FILE (after uploading to cloud)
        try {
            await fs.unlink(req.file.path); // Delete file from /tmp
            console.log(`Deleted temporary local file: ${req.file.path}`);
        } catch (err) {
            console.error(`Error deleting temporary local file ${req.file.path}:`, err.message);
        }

        // STEP 3: If there was an old profile pic URL, delete it from cloud storage too
        if (user.profilePic && user.profilePic.startsWith('http')) { // Assuming cloud URLs start with http
            // const publicId = getPublicIdFromCloudinaryUrl(user.profilePic); // Implement this helper
            // await cloudinary.uploader.destroy(publicId);
            console.log(`Placeholder: Deleted old profile pic from cloud storage: ${user.profilePic}`);
        }
        user.profilePic = newProfilePicUrl; // Save the cloud URL (or temporary local URL)
        console.log('Saving new profilePic URL to DB:', user.profilePic);

    } else if (removeProfilePic === 'true') {
        // If there's a profile pic URL in DB, delete it from cloud storage
        if (user.profilePic && user.profilePic.startsWith('http')) {
            // const publicId = getPublicIdFromCloudinaryUrl(user.profilePic);
            // await cloudinary.uploader.destroy(publicId);
            console.log(`Placeholder: Deleted profile pic from cloud storage on explicit removal request: ${user.profilePic}`);
        }
        user.profilePic = undefined; // Set to undefined to remove from DB
        console.log('Profile pic explicitly removed from DB.');
    } else {
      console.log('No new file and no remove flag. user.profilePic state remains unchanged in DB.');
    }
    // --- END CLOUD STORAGE INTEGRATION NOTES ---

    await user.save();
    console.log('User saved to DB:', user);

    res.json({ success: true, message: "Profile saved", profile: user });
  } catch (err) {
    console.error("❌ Profile save error:", err);
    res.json({ success: false, message: "Server error" });
  }
});

// ✅ GET USER PROFILE BY EMAIL
app.get('/api/user/profile', async (req, res) => {
  const userEmail = req.query.email;

  if (!userEmail) {
    return res.status(400).json({ success: false, message: "Email parameter is required." });
  }

  try {
    const user = await User.findOne({ email: userEmail }).select('-password -otp -otpExpires');

    if (!user) {
      return res.json({ success: false, message: "User not found." });
    }
    console.log('Fetched user for profile:', user);

    res.json({ success: true, user: user });
  } catch (err) {
    console.error("❌ Error fetching user profile:", err);
    res.status(500).json({ success: false, message: "Server error while fetching profile." });
  }
});


// ✅ GET USER DAILY CALORIE NEEDS (TDEE)
app.get('/api/user/calorie-needs', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  
  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.json({ success: false, message: "User not found." });
    }

    if (user.gender === undefined || user.age === undefined || user.height === undefined || user.weight === undefined || user.activityLevel === undefined) {
      return res.json({ success: false, message: "Please complete your profile (gender, age, height, weight, activity level) to calculate daily calorie needs." });
    }

    const dailyCalorieNeeds = calculateTDEE(user.gender, user.age, user.height, user.weight, user.activityLevel);

    if (dailyCalorieNeeds === null) {
      return res.json({ success: false, message: "Could not calculate calorie needs. Ensure all profile fields are valid." });
    }

    res.json({ success: true, dailyCalorieNeeds: dailyCalorieNeeds, message: "Daily calorie needs calculated." });

  } catch (err) {
    console.error("❌ Error calculating calorie needs:", err);
    res.status(500).json({ success: false, message: "Server error." });
  }
});

// ✅ GET CALORIES ENDPOINT (for chatbot, using MongoDB and Open Food Facts API)
app.post('/get-calories', async (req, res) => {
  const { foodName } = req.body;
  const normalizedFoodName = foodName.toLowerCase().trim();

  console.log(`[GET_CALORIES] Request for food: "${foodName}"`);

  try {
    let foundFood = await Food.findOne({ name: normalizedFoodName });
    console.log(`[GET_CALORIES] Found in local DB: ${foundFood ? foundFood.name : 'No'}`);

    if (foundFood) {
      return res.json({ success: true, message: `${foundFood.name} has approximately ${foundFood.calories} calories.` });
    }

    console.log(`[GET_CALORIES] Searching Open Food Facts for: "${normalizedFoodName}"`);
    const openFoodFactsApiUrl = `https://world.openfoodfacts.org/api/v2/search?search_terms=${encodeURIComponent(normalizedFoodName)}&fields=product_name,nutriments,brands,categories&page_size=20`;
    
    console.log(`[GET_CALORIES] Calling Open Food Facts API: ${openFoodFactsApiUrl}`);
    const apiResponse = await axios.get(openFoodFactsApiUrl);
    
    console.log(`[GET_CALORIES] Open Food Facts API Response Status: ${apiResponse.status}`);
    const products = apiResponse.data.products;
    console.log(`[GET_CALORIES] Products found from OFF: ${products ? products.length : 0}`);

    let bestMatch = null;

    if (products && products.length > 0) {
        for (const product of products) {
            const productNameLower = product.product_name ? product.product_name.toLowerCase() : '';
            const categoriesLower = product.categories ? product.categories.toLowerCase() : '';

            const isRelevant = productNameLower.includes(normalizedFoodName) || categoriesLower.includes(normalizedFoodName);
            const isWater = categoriesLower.includes('water') || productNameLower.includes('water');

            if (isRelevant && !isWater) {
                bestMatch = product;
                break;
            }
            if (!bestMatch && !isWater) {
                 bestMatch = product;
            }
        }
        if (!bestMatch && products.length > 0) {
            bestMatch = products[0];
        }
    }

    if (bestMatch) {
        const product = bestMatch;
        let caloriesKcal = product.nutriments && product.nutriments['energy-kcal_value_computed'];
        if (!caloriesKcal || caloriesKcal === 0) {
            caloriesKcal = product.nutriments && product.nutriments['energy-kcal_100g'];
        }
        
        console.log(`[GET_CALORIES] Best match Product Name from OFF: ${product.product_name}`);
        console.log(`[GET_CALORIES] Raw Calories from OFF (either computed or 100g): ${caloriesKcal}`);

        if (caloriesKcal && caloriesKcal > 0) {
            const roundedCalories = Math.round(caloriesKcal);
            const category = product.categories || 'Uncategorized';

            const newFood = new Food({
              name: normalizedFoodName,
              calories: roundedCalories,
              category: category.split(',')[0].trim(),
              region: 'Open Food Facts Source',
              typicalServingSize: '100g',
              protein: product.nutriments && product.nutriments.proteins_100g ? Math.round(product.nutriments.proteins_100g) : 0,
              carbohydrates: product.nutriments && product.nutriments.carbohydrates_100g ? Math.round(product.nutriments.carbohydrates_100g) : 0,
              fats: product.nutriments && product.nutriments.fat_100g ? Math.round(product.nutriments.fat_100g) : 0
            });
            await newFood.save();
            console.log(`[GET_CALORIES] Cached new food from OFF: ${newFood.name} with ${newFood.calories} calories.`);

            return res.json({ success: true, message: `${product.product_name} has approximately ${roundedCalories} calories per 100g (source: Open Food Facts).` });
        } else {
            console.log(`[GET_CALORIES] No valid calorie data found in nutriments for ${product.product_name}. (CaloriesKcal: ${caloriesKcal})`);
        }
    }

    res.json({ success: false, message: `Sorry, I don't have calorie information for "${foodName}".` });

  } catch (err) {
    console.error("❌ Error fetching calories or connecting to Open Food Facts:", err.message);
    if (err.response) {
            console.error("❌ OFF API Response Data:", err.response.data);
            console.error("❌ OFF API Response Status:", err.response.status);
    } else if (err.request) {
            console.error("❌ OFF API Request (no response):", err.request);
    } else {
            console.error('❌ Error Message:', err.message);
    }
    res.status(500).json({ success: false, message: "Server error while fetching calorie information." });
  }
});

// ✅ Endpoint to log food for a user
app.post('/api/log-food', authenticateToken, async (req, res) => {
  const { foodId, quantity, date } = req.body;
  const userId = req.user.id;

  if (!foodId || !quantity || quantity <= 0) {
    return res.status(400).json({ success: false, message: "Food ID and valid quantity are required." });
  }

  try {
    const food = await Food.findById(foodId);
    if (!food) {
      return res.status(404).json({ success: false, message: "Food item not found." });
    }

    const logDate = date ? new Date(date) : new Date();
    logDate.setHours(0, 0, 0, 0);

    let dailyLog = await DailyLog.findOne({ userId, date: logDate });

    if (!dailyLog) {
      dailyLog = new DailyLog({
        userId,
        date: logDate,
        foods: []
      });
    }

    const existingFoodEntryIndex = dailyLog.foods.findIndex(f => f.foodId.toString() === foodId);
    if (existingFoodEntryIndex > -1) {
      dailyLog.foods[existingFoodEntryIndex].quantity = parseFloat(dailyLog.foods[existingFoodEntryIndex].quantity) + parseFloat(quantity);
    } else {
      dailyLog.foods.push({
        foodId: food._id,
        name: food.name,
        caloriesPerServing: food.calories,
        quantity: quantity,
        proteinPerServing: food.protein, // Include macros from food document
        carbohydratesPerServing: food.carbohydrates,
        fatsPerServing: food.fats
      });
    }

    await dailyLog.save();
    res.json({ success: true, message: "Food logged successfully!", dailyLog });

  } catch (err) {
    console.error("❌ Error logging food:", err);
    if (err.code === 11000) {
      return res.status(409).json({ success: false, message: "A log for this date already exists. Update it instead of creating a new one." });
    }
    res.status(500).json({ success: false, message: "Server error while logging food." });
  }
});

// ✅ Endpoint to delete a food entry from a daily log
app.delete('/api/daily-log/:logId/foods/:foodEntryId', authenticateToken, async (req, res) => {
  const { logId, foodEntryId } = req.params;
  const userId = req.user.id;

  try {
    const dailyLog = await DailyLog.findOne({ _id: logId, userId: userId });

    if (!dailyLog) {
      return res.status(404).json({ success: false, message: "Daily log not found or not authorized." });
    }

    const initialFoodCount = dailyLog.foods.length;
    dailyLog.foods.pull({ _id: foodEntryId });

    if (dailyLog.foods.length === initialFoodCount) {
      return res.status(404).json({ success: false, message: "Food entry not found in this log." });
    }

    await dailyLog.save();
    res.json({ success: true, message: "Food entry deleted successfully!", dailyLog });

  } catch (err) {
    console.error("❌ Error deleting food entry:", err);
    res.status(500).json({ success: false, message: "Server error while deleting food entry." });
  }
});


// ✅ Endpoint to get daily food log for a user
app.get('/api/daily-log', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const dateParam = req.query.date;

  let queryDate = new Date();
  if (dateParam) {
    queryDate = new Date(dateParam);
  }
  queryDate.setHours(0, 0, 0, 0);

  try {
    const dailyLog = await DailyLog.findOne({ userId, date: queryDate });

    if (!dailyLog) {
      return res.json({ success: true, dailyLog: null, message: "No food logged for this date." });
    }

    let totalProtein = 0;
    let totalCarbohydrates = 0;
    let totalFats = 0;

    // Use the stored macros in the foodEntry sub-document
    dailyLog.foods.forEach(entry => {
        totalProtein += (entry.proteinPerServing || 0) * entry.quantity;
        totalCarbohydrates += (entry.carbohydratesPerServing || 0) * entry.quantity;
        totalFats += (entry.fatsPerServing || 0) * entry.quantity;
    });

    res.json({ success: true, dailyLog: {
        ...dailyLog.toObject(),
        totalProtein: Math.round(totalProtein),
        totalCarbohydrates: Math.round(totalCarbohydrates),
        totalFats: Math.round(totalFats)
    }, message: "Daily log fetched." });

  } catch (err) {
    console.error("❌ Error fetching daily log:", err);
    res.status(500).json({ success: false, message: "Server error while fetching daily log." });
  }
});

// ✅ Endpoint to get daily log history for a user
app.get('/api/daily-log/history', authenticateToken, async (req, res) => {
    const userId = req.user.id;
    const days = parseInt(req.query.days || '7');

    const endDate = new Date();
    endDate.setHours(0, 0, 0, 0);

    const startDate = new Date();
    startDate.setDate(endDate.getDate() - days);
    startDate.setHours(0, 0, 0, 0);

    try {
        const historyLogs = await DailyLog.find({
            userId,
            date: { $gte: startDate, $lte: endDate }
        }).sort({ date: 1 });

        const formattedHistory = historyLogs.map(log => ({
            date: log.date.toISOString().split('T')[0],
            totalCalories: log.totalCalories,
            totalProtein: Math.round(log.totalProtein),
            totalCarbohydrates: Math.round(log.totalCarbohydrates),
            totalFats: Math.round(log.totalFats)
        }));

        res.json({ success: true, history: formattedHistory, message: `Daily log history for last ${days} days.` });

    } catch (err) {
        console.error("❌ Error fetching daily log history:", err);
        res.status(500).json({ success: false, message: "Server error while fetching log history." });
    }
});


// ✅ GET ALL FOODS ENDPOINT (for Browse/searching food list)
app.get('/api/foods', async (req, res) => {
  const searchTerm = req.query.search;
  try {
    let query = {};
    if (searchTerm) {
      query.name = { $regex: searchTerm, $options: 'i' };
    }
    const foods = await Food.find(query).limit(50);
    res.json({ success: true, foods });
  } catch (err) {
    console.error("❌ Error fetching food list:", err);
    res.status(500).json({ success: false, message: "Server error while fetching food list." });
  }
});

// ✅ Start server
app.listen(process.env.PORT || 5000, () =>
  console.log(`🚀 Server running on port ${process.env.PORT || 5000}`)
);