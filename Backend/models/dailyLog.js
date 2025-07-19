
const mongoose = require("mongoose");

const dailyLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  date: {
    type: Date,
    required: true,
    default: Date.now,
    set: function(date) {
      const d = new Date(date);
      d.setHours(0, 0, 0, 0); // Set to start of the day UTC
      return d;
    }
  },
  foods: [
    {
      foodId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'Food',
        required: true
      },
      name: { type: String, required: true },
      caloriesPerServing: { type: Number, required: true },
      quantity: { type: Number, required: true, min: 0.1 },
      // NEW: Store macros per serving in the sub-document when logged
      proteinPerServing: { type: Number, default: 0 },
      carbohydratesPerServing: { type: Number, default: 0 },
      fatsPerServing: { type: Number, default: 0 }
    }
  ],
  totalCalories: {
    type: Number,
    default: 0
  },
  totalProtein: {
    type: Number,
    default: 0
  },
  totalCarbohydrates: {
    type: Number,
    default: 0
  },
  totalFats: {
    type: Number,
    default: 0
  }
}, {
  timestamps: true
});

dailyLogSchema.index({ userId: 1, date: 1 }, { unique: true });

// Pre-save hook to calculate totalCalories and NEW total macros
dailyLogSchema.pre('save', function(next) {
  let sumCalories = 0;
  let sumProtein = 0;
  let sumCarbs = 0;
  let sumFats = 0;

  this.foods.forEach(foodEntry => {
    sumCalories += foodEntry.caloriesPerServing * foodEntry.quantity;
    sumProtein += (foodEntry.proteinPerServing || 0) * foodEntry.quantity; // Use 0 if not defined
    sumCarbs += (foodEntry.carbohydratesPerServing || 0) * foodEntry.quantity;
    sumFats += (foodEntry.fatsPerServing || 0) * foodEntry.quantity;
  });
  this.totalCalories = sumCalories;
  this.totalProtein = sumProtein;
  this.totalCarbohydrates = sumCarbs;
  this.totalFats = sumFats;
  next();
});

module.exports = mongoose.model("DailyLog", dailyLogSchema);