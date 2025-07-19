import React, { useState, useEffect, useCallback, useRef } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import CircularProgressBar from './CircularProgressBar';
import { PlusCircle, Utensils, Trash2 } from 'lucide-react';

export default function LogFood() {
  const navigate = useNavigate();
  const [searchTerm, setSearchTerm] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [selectedFoodId, setSelectedFoodId] = useState('');
  const [selectedFoodName, setSelectedFoodName] = useState('');
  const [selectedFoodCalories, setSelectedFoodCalories] = useState(0);
  const [quantity, setQuantity] = useState(1);
  const [dailyLog, setDailyLog] = useState(null);
  const [totalCaloriesToday, setTotalCaloriesToday] = useState(0);
  const [dailyCalorieGoal, setDailyCalorieGoal] = useState(0);
  const [message, setMessage] = useState({ type: '', text: '' });

  const [confirmDeleteId, setConfirmDeleteId] = useState(null);

  const [showDropdown, setShowDropdown] = useState(false);
  const searchInputRef = useRef(null);

  const token = localStorage.getItem('token');
  const userEmail = localStorage.getItem('email');
  // Removed: const userName = localStorage.getItem("name"); // Not used in this component

  useEffect(() => {
    if (!token || !userEmail) {
      navigate('/login');
    }
  }, [token, userEmail, navigate]);

  useEffect(() => {
    const handleClickOutside = (event) => {
      if (searchInputRef.current && !searchInputRef.current.contains(event.target)) {
        setShowDropdown(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => {
      document.removeEventListener('mousedown', handleClickOutside);
    };
  }, [searchInputRef]);

  const fetchDailyData = useCallback(async () => {
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

      const logRes = await axios.get(`https://calorie-app-backend.onrender.com//api/daily-log`, {
        headers: { Authorization: `Bearer ${token}` },
        params: { date: new Date().toISOString() }
      });

      if (logRes.data.success && logRes.data.dailyLog) {
        setDailyLog(logRes.data.dailyLog);
        setTotalCaloriesToday(logRes.data.dailyLog.totalCalories);
      } else {
        setDailyLog(null);
        setTotalCaloriesToday(0);
      }
    } catch (err) {
      console.error("Error fetching daily data:", err);
      setMessage({ type: 'error', text: 'Error loading daily log or calorie goal.' });
    }
  }, [token, userEmail]);

  useEffect(() => {
    fetchDailyData();
  }, [fetchDailyData]);

  const handleSearch = async (e) => {
    const term = e.target.value;
    setSearchTerm(term);
    setSelectedFoodId('');
    setSelectedFoodName('');
    setSelectedFoodCalories(0);

    if (term.length >= 1) {
      try {
        const res = await axios.get(`https://calorie-app-backend.onrender.com//api/foods?search=${term}`);
        if (res.data.success) {
          setSearchResults(res.data.foods);
          setShowDropdown(true);
        } else {
          setSearchResults([]);
          setShowDropdown(false);
        }
      } catch (err) {
        console.error("Error searching foods:", err);
        setSearchResults([]);
        setShowDropdown(false);
      }
    } else {
      setSearchResults([]);
      setShowDropdown(false);
    }
  };

  const handleFoodSelectFromDropdown = (food) => {
    setSelectedFoodId(food._id);
    setSelectedFoodName(food.name);
    setSelectedFoodCalories(food.calories);
    setSearchTerm(food.name);
    setSearchResults([]);
    setShowDropdown(false);
  };

  const handleLogFood = async () => {
    if (!selectedFoodId || quantity <= 0) {
      setMessage({ type: 'error', text: 'Please select a food and enter a valid quantity.' });
      return;
    }

    try {
      const res = await axios.post(
        `https://calorie-app-backend.onrender.com//api/log-food`,
        { foodId: selectedFoodId, quantity: quantity, date: new Date().toISOString() },
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (res.data.success) {
        setMessage({ type: 'success', text: res.data.message });
        await fetchDailyData();
        setSearchTerm('');
        setSearchResults([]);
        setSelectedFoodId('');
        setSelectedFoodName('');
        setSelectedFoodCalories(0);
        setQuantity(1);
        setShowDropdown(false);
      } else {
        setMessage({ type: 'error', text: res.data.message });
      }
    } catch (err) {
      console.error("Error logging food:", err);
      setMessage({ type: 'error', text: err.response?.data?.message || 'Server error logging food.' });
    }
  };

  const confirmDelete = (foodEntryId) => {
    setConfirmDeleteId(foodEntryId);
    setMessage({ type: 'info', text: 'Click "Confirm Delete" next to the item to remove it, or "Cancel" to keep it.' });
  };

  const executeDelete = async (foodEntryId) => {
    if (!dailyLog || !dailyLog._id) {
      setMessage({ type: 'error', text: 'No daily log to delete from.' });
      setConfirmDeleteId(null);
      return;
    }

    try {
      const res = await axios.delete(
        `https://calorie-app-backend.onrender.com//api/daily-log/${dailyLog._id}/foods/${foodEntryId}`,
        { headers: { Authorization: `Bearer ${token}` } }
      );

      if (res.data.success) {
        setMessage({ type: 'success', text: res.data.message });
        await fetchDailyData();
      } else {
        setMessage({ type: 'error', text: res.data.message || 'Failed to delete food item.' });
      }
    } catch (err) {
      console.error("Error deleting food item:", err);
      setMessage({ type: 'error', text: err.response?.data?.message || 'Server error deleting food item.' });
    } finally {
      setConfirmDeleteId(null);
    }
  };

  const cancelDelete = () => {
    setConfirmDeleteId(null);
    setMessage({ type: '', text: '' });
  };


  return (
    <div className="min-h-screen bg-gradient-to-br from-green-100 via-green-200 to-green-300 flex flex-col items-center p-4">
      {/* Main Content Area */}
      <div className="flex-1 flex flex-col items-center p-4">
        <div className="w-full max-w-4xl grid grid-cols-1 md:grid-cols-2 gap-6">

          {/* Calorie Progress Section (Left Column on larger screens) */}
          <div className="p-6 bg-white/40 backdrop-blur-md rounded-xl shadow-xl flex flex-col items-center justify-center border border-white/50">
            <h2 className="text-xl font-bold text-green-800 mb-4">Daily Calorie Summary</h2>
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
            {dailyCalorieGoal > 0 && totalCaloriesToday > dailyCalorieGoal && (
              <p className="text-sm text-red-600 mt-2 font-medium">You've exceeded your daily calorie goal!</p>
            )}
          </div>

          {/* Food Logging Section (Right Column on larger screens) */}
          <div className="p-6 bg-white/40 backdrop-blur-md rounded-xl shadow-xl flex flex-col border border-white/50">
            <h2 className="text-xl font-bold text-green-800 mb-4 flex items-center space-x-2">
              <Utensils className="inline-block" size={24} /> <span>Log a Meal</span>
            </h2>
            {message.text && (
              <p className={`mb-4 text-center font-medium ${message.type === 'error' ? 'text-red-600' : (message.type === 'info' ? 'text-blue-600' : 'text-green-700')}`}>
                {message.text}
              </p>
            )}

            <div className="relative mb-3" ref={searchInputRef}>
              <input
                type="text"
                placeholder="Search for a food (e.g., dosa, rice)"
                value={searchTerm}
                onChange={handleSearch}
                onFocus={() => { if (searchResults.length > 0) setShowDropdown(true); }}
                className="w-full p-3 rounded-lg border border-green-300 focus:outline-none focus:ring-2 focus:ring-green-400 text-green-800 placeholder-green-500"
              />

              {(showDropdown && searchResults.length > 0) ? (
                <ul className="absolute z-10 w-full bg-white border border-green-300 rounded-lg shadow-lg mt-1 max-h-60 overflow-y-auto">
                  {searchResults.map(food => (
                    <li
                      key={food._id}
                      className="p-3 cursor-pointer hover:bg-green-100 text-green-800 border-b border-green-100 last:border-b-0"
                      onClick={() => handleFoodSelectFromDropdown(food)}
                    >
                      {food.name} ({food.calories} Kcal / serving)
                    </li>
                  ))}
                </ul>
              ) : (
                searchTerm.length >= 1 ? (
                  <p className="text-sm text-gray-500 mt-2">No foods found for "{searchTerm}". Try another search term or ensure your backend has data.</p>
                ) : (
                  <p className="text-sm text-gray-500 mt-2">Start typing to search for food items.</p>
                )
              )}

            </div>

            {selectedFoodId && (
              <div className="mb-3 p-2 bg-green-50 rounded-md border border-green-200">
                <p className="text-green-700 font-semibold">Selected: <span className="capitalize">{selectedFoodName}</span> ({selectedFoodCalories} Kcal)</p>
              </div>
            )}

            <input
              type="number"
              placeholder="Quantity (e.g., 1 or 0.5)"
              value={quantity}
              onChange={(e) => setQuantity(e.target.value)}
              min="0.1"
              step="0.1"
              className="w-full p-3 rounded-lg border border-green-300 focus:outline-none focus:ring-2 focus:ring-green-400 mb-4 text-green-800 placeholder-green-500"
            />

            <button
              onClick={handleLogFood}
              className="w-full bg-green-600 hover:bg-green-700 text-white py-3 rounded-lg font-semibold shadow-md transition-transform hover:scale-[1.02] flex items-center justify-center space-x-2"
            >
              <PlusCircle size={20} /> <span>Add to Log</span>
            </button>
          </div>
        </div>

        {/* Daily Log Display Section */}
        <div className="mt-8 w-full max-w-4xl p-6 bg-white/40 backdrop-blur-md rounded-xl shadow-xl border border-white/50">
          <h2 className="text-2xl font-bold text-green-800 mb-4">Today's Log: {new Date().toLocaleDateString('en-IN', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</h2>
          {dailyLog && dailyLog.foods.length > 0 ? (
            <ul>
              {dailyLog.foods.map((entry) => (
                <li key={entry._id} className="flex justify-between items-center py-3 border-b border-green-200 last:border-b-0">
                  <span className="text-green-800 font-medium text-lg capitalize">{entry.name}</span>
                  <span className="text-green-600">{entry.quantity} servings</span>
                  <span className="text-green-900 font-semibold text-lg">{Math.round(entry.caloriesPerServing * entry.quantity)} Kcal</span>
                  {confirmDeleteId === entry._id ? (
                    <div className="flex space-x-2">
                      <button
                        onClick={() => executeDelete(entry._id)}
                        className="p-1 bg-red-500 text-white rounded-md hover:bg-red-600 text-sm"
                        title="Confirm Delete"
                      >
                        Confirm
                      </button>
                      <button
                        onClick={cancelDelete}
                        className="p-1 bg-gray-300 text-gray-800 rounded-md hover:bg-gray-400 text-sm"
                        title="Cancel Delete"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={() => confirmDelete(entry._id)}
                      className="p-1 text-red-500 hover:text-red-700 transition-colors"
                      title="Delete food item"
                    >
                      <Trash2 size={20} />
                    </button>
                  )}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-gray-500 text-center text-lg py-4">No food logged for today. Start adding meals!</p>
          )}
        </div>
      </div>

      {/* Footer */}
      <footer className="text-center py-4 mt-8 text-green-900/70 text-sm border-t border-white/40 bg-green-200/30 backdrop-blur-md w-full">
        © {new Date().getFullYear()} CalorieApp. All rights reserved.
      </footer>
    </div>
  );
}