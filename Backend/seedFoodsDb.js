require("dotenv").config();
const mongoose = require("mongoose");
const Food = require("./models/food"); // Adjust path if your models directory is different
const fs = require('fs');
const path = require('path');

// Make sure your foods.json is in the root of your backend directory or adjust path
const foodsData = JSON.parse(fs.readFileSync(path.join(__dirname, 'foods.json'), 'utf8'));

mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(async () => {
    console.log("MongoDB Connected for seeding Food Data");
    try {
      // Clear existing food data before seeding to avoid duplicates on re-run
      // Only do this if you are sure you want to reset your food data each time
      await Food.deleteMany({});
      console.log("Existing food data cleared (if any).");

      // Insert foods from JSON
      await Food.insertMany(foodsData.map(food => ({
        name: food.name.toLowerCase().trim(), // Ensure consistency
        calories: food.calories,
        // You can add more fields from your JSON if you updated it with category, etc.
      })));
      console.log("Food data successfully imported from foods.json to MongoDB!");

    } catch (err) {
      console.error("Error importing food data:", err);
    } finally {
      mongoose.disconnect();
      console.log("MongoDB Disconnected.");
    }
  })
  .catch((err) => console.error("MongoDB Connection Error:", err));