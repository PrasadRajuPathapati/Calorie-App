import React, { useEffect, useState } from "react";
import { Link } from "react-router-dom"; // Removed useNavigate
import { motion } from "framer-motion";
import { Utensils, Calculator, Heart } from "lucide-react"; // Removed PlusCircle
// Removed: import logo from "../assets/logo.png"; // Not directly used in Home.js
import axios from 'axios';
// Removed: import { clearAuthData } from "../utils/authUtils"; // Not used directly in Home.js

// Removed: const DEFAULT_PROFILE_PIC_FALLBACK = logo; // Not used here

const Home = () => {
  // Removed: const navigate = useNavigate(); // Not used
  const [userName, setUserName] = useState("");
  const [dailyCalorieNeeds, setDailyCalorieNeeds] = useState(null);
  const [calorieMessage, setCalorieMessage] = useState("");

  useEffect(() => {
    const savedName = localStorage.getItem("name");
    if (savedName) {
      setUserName(savedName);
    }

    const fetchDailyCalorieNeeds = async () => {
      const email = localStorage.getItem("email");
      if (!email) {
        setCalorieMessage("Please login to see your calorie needs.");
        return;
      }
      try {
        const token = localStorage.getItem('token');
        const res = await axios.get(`https://calorie-app-backend.onrender.com//api/user/calorie-needs`, {
             headers: { Authorization: `Bearer ${token}` }
        });
        if (res.data.success) {
          setDailyCalorieNeeds(res.data.dailyCalorieNeeds || 0);
          setCalorieMessage(res.data.message);
        } else {
          setCalorieMessage(res.data.message || "Failed to fetch calorie needs.");
        }
      } catch (err) {
        console.error("Error fetching daily calorie needs:", err);
        setCalorieMessage("Error fetching calorie needs. Please ensure your profile is complete.");
      }
    };
    
    fetchDailyCalorieNeeds();
  }, []);

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-100 via-green-200 to-green-300 flex flex-col items-center justify-between px-4 py-2">
      {/* Navbar is handled globally by App.js */}

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col items-center justify-center w-full max-w-4xl py-4">
        {/* Hero / Welcome Section */}
        <motion.div
          initial={{ opacity: 0, y: -50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="text-center mb-8"
        >
          <h2 className="text-4xl md:text-5xl font-extrabold text-green-900 drop-shadow-md mb-2">
            Welcome, {userName || "User"}!
          </h2>
          {dailyCalorieNeeds && (
            <p className="text-2xl md:text-3xl font-bold text-green-700 mb-4">
              Daily Calorie Goal: {dailyCalorieNeeds} Kcal
            </p>
          )}
          {calorieMessage && !dailyCalorieNeeds && (
            <p className="text-base text-red-600 italic mb-4">{calorieMessage}</p>
          )}
          <p className="text-base md:text-lg text-green-800/80 max-w-xl mx-auto">
            Your health journey starts here. Log your meals and track your progress daily!
          </p>
        </motion.div>

        {/* Primary Action: Log Your Meals */}
        <motion.div
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.3, duration: 0.6, ease: "easeOut" }}
          className="w-full max-w-md bg-green-600 rounded-3xl shadow-xl hover:shadow-2xl transition-all duration-300 transform hover:scale-105 mb-6"
        >
          <Link to="/log-food" className="block p-6 flex flex-col items-center text-white">
            <Utensils className="w-20 h-20 mb-4" />
            <h3 className="text-3xl font-bold mb-2">Log Your Meals</h3>
            <p className="text-lg opacity-90">Quickly add what you’ve eaten today.</p>
          </Link>
        </motion.div>

        {/* Secondary Actions: Calculate Calories & Stay Healthy */}
        <div className="w-full max-w-md grid grid-cols-1 sm:grid-cols-2 gap-4">
          <motion.div
            initial={{ opacity: 0, x: -50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.5, duration: 0.6, ease: "easeOut" }}
            className="bg-white/70 backdrop-blur-md rounded-2xl shadow-lg hover:shadow-xl hover:scale-[1.02] transition-all duration-300 cursor-pointer"
          >
            <Link to="/calorie-insights" className="block p-4 flex flex-col items-center text-center">
              <Calculator className="w-12 h-12 text-green-700 mb-2" />
              <h3 className="text-xl font-bold text-green-900 mb-1">Calorie Insights</h3>
              <p className="text-sm text-green-800/80">View daily totals & progress.</p>
            </Link>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, x: 50 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.6, duration: 0.6, ease: "easeOut" }}
            className="bg-white/70 backdrop-blur-md rounded-2xl shadow-lg hover:shadow-xl hover:scale-[1.02] transition-all duration-300 cursor-pointer"
          >
            <Link to="#" className="block p-4 flex flex-col items-center text-center">
              <Heart className="w-12 h-12 text-green-700 mb-2" />
              <h3 className="text-xl font-bold text-green-900 mb-1">Stay Healthy</h3>
              <p className="text-sm text-green-800/80">Track your progress & goals.</p>
            </Link>
          </motion.div>
        </div>
      </div>

      {/* Footer */}
      <footer className="text-center py-2 text-green-900/70 text-sm border-t border-white/40 bg-green-200/30 backdrop-blur-md w-full mt-4">
        © {new Date().getFullYear()} CalorieApp. All rights reserved.
      </footer>
    </div>
  );
};

export default Home;