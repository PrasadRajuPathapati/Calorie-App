import React, { useState, useEffect } from "react"; // NEW: Import useEffect
import { BrowserRouter as Router, Routes, Route, Navigate } from "react-router-dom";
import Login from "./components/Login";
import Signup from "./components/Signup";
import Home from "./components/Home";
import Profile from "./components/Profile";
import LogFood from "./components/LogFood";
import CalorieInsights from "./components/CalorieInsights";
import Navbar from "./components/Navbar";
import SplashScreen from "./components/SplashScreen"; // NEW: Import SplashScreen
import { isAuthenticated } from "./utils/authUtils";

function App() {
  const [showSplash, setShowSplash] = useState(true);

  useEffect(() => {
    // This ensures the splash screen is shown for a minimum duration
    // even if onAnimationComplete from SplashScreen is called earlier.
    const minimumDisplayTime = setTimeout(() => {
      setShowSplash(false);
    }, 2500); // Match this with SplashScreen's internal timer if possible

    return () => clearTimeout(minimumDisplayTime);
  }, []);

  if (showSplash) {
    return <SplashScreen onAnimationComplete={() => setShowSplash(false)} />;
  }

  return (
    <Router>
      {/* Render Navbar on all pages (except login/signup/splash) */}
      {isAuthenticated() && <Navbar />} 
      
      <Routes>
        <Route
          path="/"
          element={isAuthenticated() ? <Navigate to="/home" /> : <Login />}
        />
        <Route
          path="/login"
          element={isAuthenticated() ? <Navigate to="/home" /> : <Login />}
        />
        <Route
          path="/signup"
          element={isAuthenticated() ? <Navigate to="/home" /> : <Signup />}
        />
        <Route path="/home" element={<Home />} />
        <Route path="/profile" element={<Profile />} />
        <Route path="/log-food" element={<LogFood />} />
        <Route path="/calorie-insights" element={<CalorieInsights />} />
      </Routes>
    </Router>
  );
}
export default App;