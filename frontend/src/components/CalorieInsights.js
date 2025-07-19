import React, { useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import CircularProgressBar from './CircularProgressBar';
import { motion } from "framer-motion";

export default function CalorieInsights() {
  const navigate = useNavigate();
  const [dailyCalorieGoal, setDailyCalorieGoal] = useState(0);
  const [todayLog, setTodayLog] = useState(null);
  const [historyLogs, setHistoryLogs] = useState([]);
  const [message, setMessage] = useState({ type: '', text: '' });

  const token = localStorage.getItem('token');
  const userEmail = localStorage.getItem('email');

  useEffect(() => {
    if (!token || !userEmail) {
      navigate('/login');
    }
  }, [token, userEmail, navigate]);

  const fetchInsightsData = useCallback(async () => {
    if (!token || !userEmail) return;

    try {
      const goalRes = await axios.get(`https://calorie-app-backend.onrender.com//api/user/calorie-needs`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (goalRes.data.success) {
        setDailyCalorieGoal(goalRes.data.dailyCalorieNeeds || 0);
      } else {
        setMessage({ type: 'error', text: goalRes.data.message || 'Failed to fetch calorie goal.' });
      }

      const todayLogRes = await axios.get(`https://calorie-app-backend.onrender.com//api/daily-log`, {
        headers: { Authorization: `Bearer ${token}` },
        params: { date: new Date().toISOString() }
      });
      if (todayLogRes.data.success && todayLogRes.data.dailyLog) {
        setTodayLog(todayLogRes.data.dailyLog);
      } else {
        setTodayLog(null);
      }

      const historyRes = await axios.get(`https://calorie-app-backend.onrender.com//api/daily-log/history?days=7`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (historyRes.data.success && historyRes.data.history) {
        setHistoryLogs(historyRes.data.history);
      } else {
        setHistoryLogs([]);
      }

    } catch (err) {
      console.error("Error fetching insights data:", err);
      setMessage({ type: 'error', text: 'Error loading calorie insights.' });
    }
  }, [token, userEmail]);

  useEffect(() => {
    fetchInsightsData();
  }, [fetchInsightsData]);

  const totalCaloriesToday = todayLog ? todayLog.totalCalories : 0;
  const totalProteinToday = todayLog ? todayLog.totalProtein : 0;
  const totalCarbohydratesToday = todayLog ? todayLog.totalCarbohydrates : 0;
  const totalFatsToday = todayLog ? todayLog.totalFats : 0;

  const getDailyStatusMessage = () => {
    if (dailyCalorieGoal === 0) {
      return "Please complete your profile to set a daily calorie goal.";
    }
    if (totalCaloriesToday === 0) {
      return "Log your first meal to start tracking!";
    }
    const diff = totalCaloriesToday - dailyCalorieGoal;
    if (diff > 200) {
      return `You are ${diff} Kcal over your goal today. Consider lighter meals ahead.`;
    } else if (diff > 0) {
      return `You are slightly over your goal by ${diff} Kcal today.`;
    } else if (diff < -200) {
      return `You are ${Math.abs(diff)} Kcal under your goal. Make sure you're fueling enough!`;
    } else if (diff < 0) {
      return `You are slightly under your goal by ${Math.abs(diff)} Kcal today.`;
    } else {
      return "You're right on track with your calorie goal today! Great job!";
    }
  };


  return (
    <div className="min-h-screen bg-gradient-to-br from-green-100 via-green-200 to-green-300 flex flex-col">
      {/* Main Content Area */}
      <div className="flex-1 flex flex-col items-center p-4">
        {message.text && (
          <p className={`mb-4 text-center font-medium ${message.type === 'error' ? 'text-red-600' : 'text-green-700'}`}>
            {message.text}
          </p>
        )}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="w-full max-w-4xl mt-6 p-6 bg-white/40 backdrop-blur-md rounded-xl shadow-xl border border-white/50 grid grid-cols-1 md:grid-cols-2 gap-6"
        >
          {/* Daily Calorie Summary Card */}
          <div className="flex flex-col items-center justify-center p-4 bg-green-50/50 rounded-lg border border-green-200 shadow-sm">
            <h2 className="text-xl font-bold text-green-800 mb-4">Today's Calorie Overview</h2>
            <CircularProgressBar
              progress={totalCaloriesToday}
              target={dailyCalorieGoal}
              size={180}
              strokeWidth={15}
            />
            <p className="mt-4 text-center text-green-700 text-lg">
              Consumed: <span className="font-semibold">{totalCaloriesToday}</span> Kcal <br/>
              Goal: <span className="font-semibold">{dailyCalorieGoal}</span> Kcal
            </p>
            <p className="mt-2 text-center text-green-800 font-medium">{getDailyStatusMessage()}</p>
          </div>

          {/* Today's Macronutrients Breakdown Card */}
          <div className="p-4 bg-green-50/50 rounded-lg border border-green-200 shadow-sm">
            <h2 className="text-xl font-bold text-green-800 mb-4">Today's Macronutrients</h2>
            <div className="space-y-3">
              <div className="flex justify-between items-center text-lg">
                <span className="text-green-700 font-medium">Protein:</span>
                <span className="text-green-900 font-semibold">{totalProteinToday} g</span>
              </div>
              <div className="flex justify-between items-center text-lg">
                <span className="text-green-700 font-medium">Carbohydrates:</span>
                <span className="text-green-900 font-semibold">{totalCarbohydratesToday} g</span>
              </div>
              <div className="flex justify-between items-center text-lg">
                <span className="text-green-700 font-medium">Fats:</span>
                <span className="text-green-900 font-semibold">{totalFatsToday} g</span>
              </div>
            </div>
            {todayLog && todayLog.foods.length === 0 && (
              <p className="text-gray-500 text-sm mt-4 text-center">Log some food to see your macro breakdown!</p>
            )}
          </div>

        </motion.div>

        {/* Historical Data Section */}
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, delay: 0.2, ease: "easeOut" }}
          className="w-full max-w-4xl mt-6 p-6 bg-white/40 backdrop-blur-md rounded-xl shadow-xl border border-white/50"
        >
          <h2 className="text-2xl font-bold text-green-800 mb-4 text-center">Last 7 Days Calorie History</h2>
          {historyLogs.length > 0 ? (
            <div className="overflow-x-auto">
              <table className="min-w-full bg-white rounded-lg overflow-hidden text-sm">
                <thead className="bg-green-100">
                  <tr>
                    <th className="py-2 px-3 text-left text-green-800">Date</th>
                    <th className="py-2 px-3 text-left text-green-800">Calories (Kcal)</th>
                    <th className="py-2 px-3 text-left text-green-800">Protein (g)</th>
                    <th className="py-2 px-3 text-left text-green-800">Carbs (g)</th>
                    <th className="py-2 px-3 text-left text-green-800">Fats (g)</th>
                  </tr>
                </thead>
                <tbody>
                  {historyLogs.map(log => (
                    <tr key={log.date} className="border-b border-green-100 last:border-b-0">
                      <td className="py-2 px-3 text-green-700">{new Date(log.date).toLocaleDateString()}</td>
                      <td className="py-2 px-3 text-green-900 font-semibold">{log.totalCalories}</td>
                      <td className="py-2 px-3">{log.totalProtein}</td>
                      <td className="py-2 px-3">{log.totalCarbohydrates}</td>
                      <td className="py-2 px-3">{log.totalFats}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="text-gray-500 text-center py-4">No historical data available yet. Log more meals!</p>
          )}
        </motion.div>
      </div>

      {/* Footer */}
      <footer className="text-center py-4 mt-8 text-green-900/70 text-sm border-t border-white/40 bg-green-200/30 backdrop-blur-md">
        © {new Date().getFullYear()} CalorieApp. All rights reserved.
      </footer>
    </div>
  );
}