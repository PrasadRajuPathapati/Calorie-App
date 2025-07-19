const mongoose = require("mongoose");

const foodSchema = new mongoose.Schema({
  name: { type: String, required: true, unique: true, lowercase: true, trim: true },
  calories: { type: Number, required: true },
  category: { type: String, default: 'Other' },
  region: { type: String },
  typicalServingSize: { type: String },
  protein: { type: Number, default: 0 },
  carbohydrates: { type: Number, default: 0 },
  fats: { type: Number, default: 0 }
});

module.exports = mongoose.model("Food", foodSchema);