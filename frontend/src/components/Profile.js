import React, { useState, useEffect, useRef } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import logo from "../assets/logo.png";
import { UserCircle, Save, XCircle } from "lucide-react";
import { motion } from "framer-motion";

const DEFAULT_PROFILE_PIC_FALLBACK = logo;

export default function Profile() {
  const [name, setName] = useState("");
  const [image, setImage] = useState(null);
  const [preview, setPreview] = useState(null);
  const [message, setMessage] = useState({ type: "", text: "" });

  const [currentDbProfilePicPath, setCurrentDbProfilePicPath] = useState(null);

  const [gender, setGender] = useState("");
  const [age, setAge] = useState("");
  const [height, setHeight] = useState("");
  const [weight, setWeight] = useState("");
  const [activityLevel, setActivityLevel] = useState("");

  const navigate = useNavigate();

  const email = localStorage.getItem("email") || "";

  const fileInputRef = useRef(null);

  useEffect(() => {
    const fetchUserProfile = async () => {
      if (!email) {
        setMessage({ type: "error", text: "Email not found. Please log in." });
        return;
      }

      try {
        const token = localStorage.getItem('token');
        const res = await axios.get(`https://calorie-app-backend.onrender.com//api/user/profile?email=${email}`, {
            headers: { Authorization: `Bearer ${token}` }
        });

        if (res.data.success && res.data.user) {
          const user = res.data.user;
          setName(user.name || "");
          setGender(user.gender || "");
          setAge(user.age || "");
          setHeight(user.height || "");
          setWeight(user.weight || "");
          setActivityLevel(user.activityLevel || "");

          if (user.profilePic) {
            const fullProfilePicUrl = `https://calorie-app-backend.onrender.com${user.profilePic}`;
            setPreview(fullProfilePicUrl);
            setCurrentDbProfilePicPath(user.profilePic);
          } else {
            setPreview(DEFAULT_PROFILE_PIC_FALLBACK);
            setCurrentDbProfilePicPath(null);
          }
          setMessage({ type: "success", text: "Profile loaded successfully!" });
        } else {
          setPreview(DEFAULT_PROFILE_PIC_FALLBACK);
          setCurrentDbProfilePicPath(null);
          setMessage({ type: "error", text: res.data.message || "Failed to load profile." });
        }
      } catch (err) {
        console.error("Error fetching user profile:", err);
        setPreview(DEFAULT_PROFILE_PIC_FALLBACK);
        setCurrentDbProfilePicPath(null);
        setMessage({ type: "error", text: "Server error while loading profile." });
      }
    };

    fetchUserProfile();
  }, [email]);

  const handleImageChange = (e) => {
    const file = e.target.files[0];
    if (file) {
      setImage(file);
      setPreview(URL.createObjectURL(file));
    } else {
      setImage(null);
      setPreview(currentDbProfilePicPath ? `https://calorie-app-backend.onrender.com${currentDbProfilePicPath}` : DEFAULT_PROFILE_PIC_FALLBACK);
    }
  };

  const handleRemovePhoto = () => {
    if (fileInputRef.current) {
      fileInputRef.current.value = "";
    }
    setImage(null);
    setPreview(DEFAULT_PROFILE_PIC_FALLBACK);
    setCurrentDbProfilePicPath(null);
    setMessage({type: "info", text: "Photo marked for removal. Click 'Save Profile' to confirm."});
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!name) {
      setMessage({ type: "error", text: "❌ Please enter your name." });
      return;
    }
    if (!gender || !age || !height || !weight || !activityLevel) {
      setMessage({ type: "error", text: "❌ Please fill in all required profile details (gender, age, height, weight, activity level)." });
      return;
    }

    const formData = new FormData();
    formData.append("name", name);
    formData.append("email", email);
    
    if (image) {
        formData.append("profilePic", image);
    } else if (currentDbProfilePicPath === null && preview === DEFAULT_PROFILE_PIC_FALLBACK) { 
        formData.append("removeProfilePic", "true"); 
    }


    formData.append("gender", gender);
    formData.append("age", age);
    formData.append("height", height);
    formData.append("weight", weight);
    formData.append("activityLevel", activityLevel);

    try {
      const res = await axios.post("https://calorie-app-backend.onrender.com/save-profile", formData, {
        headers: { "Content-Type": "multipart/form-data" },
      });
      if (res.data.success) {
        localStorage.setItem("name", res.data.profile.name || "");
        setMessage({ type: "success", text: "✅ Profile saved successfully! Redirecting..." });
        if (fileInputRef.current) {
            fileInputRef.current.value = "";
        }
        setImage(null);
        setTimeout(() => navigate("/home"), 1200);
      } else {
        setMessage({ type: "error", text: res.data.message });
      }
    } catch (err) {
      console.error("❌ Profile save error:", err);
      setMessage({ type: "error", text: "❌ Server error." });
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-100 via-green-200 to-green-300 flex flex-col">
      {/* REMOVED: Navbar code from here */}

      {/* Main Content Area - Centered and Spaced */}
      <div className="flex-1 flex flex-col items-center py-4">
        <motion.div
          initial={{ opacity: 0, y: 40 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className="w-full max-w-4xl mt-4 p-3 bg-white/40 backdrop-blur-md rounded-xl shadow-xl border border-white/50"
        >
          <h1 className="text-3xl font-bold text-green-800 mb-2 text-center">Your Profile</h1>
          <p className="text-green-600 mb-4 text-center">
            Complete your details below. This helps us personalize your experience.
          </p>

          {message.text && (
            <p
              className={`mb-4 text-center font-medium ${
                message.type === "error" ? "text-red-600" : (message.type === "info" ? "text-blue-600" : "text-green-700")
              }`}
            >
              {message.text}
            </p>
          )}

          {/* Centralized Profile Picture Section */}
          <div className="flex flex-col items-center mb-6">
              <div className="relative w-36 h-36 rounded-full border-4 border-green-300 shadow-lg overflow-hidden group hover:border-green-500 transition-all duration-300 mb-3">
                <label htmlFor="profilePicInput" className="cursor-pointer block w-full h-full">
                  {preview ? (
                    <img
                      src={preview}
                      alt="Profile Preview"
                      className="w-full h-full object-cover"
                    />
                  ) : (
                    <div className="flex items-center justify-center w-full h-full bg-green-100 text-green-700">
                      <UserCircle size={48} />
                    </div>
                  )}
                  <div className="absolute inset-0 bg-black bg-opacity-50 flex items-center justify-center text-white opacity-0 group-hover:opacity-100 transition-opacity text-sm font-semibold">
                    Change Photo
                  </div>
                </label>
                <input
                  id="profilePicInput"
                  type="file"
                  accept="image/*"
                  onChange={handleImageChange}
                  className="hidden"
                  ref={fileInputRef}
                />
              </div>
              {(preview && preview !== DEFAULT_PROFILE_PIC_FALLBACK) && (
                <button
                  type="button"
                  onClick={handleRemovePhoto}
                  className="px-4 py-2 text-sm text-red-600 bg-red-100 rounded-lg hover:bg-red-200 transition-colors flex items-center space-x-1"
                >
                  <XCircle size={16} /> <span>Remove Photo</span>
                </button>
              )}
            </div>


          {/* Profile Details Fields - Now a direct two-column grid */}
          <form onSubmit={handleSubmit} className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-3 items-start">
            <div>
              <label className="block text-green-900 font-medium mb-1">Name</label>
              <input
                type="text"
                placeholder="Enter your name"
                value={name}
                onChange={(e) => setName(e.target.value)}
                className="w-full p-2.5 rounded-lg border border-green-300 focus:outline-none focus:ring-2 focus:ring-green-400"
                required
              />
            </div>

            <div>
              <label className="block text-green-900 font-medium mb-1">Email</label>
              <input
                type="email"
                value={email}
                disabled
                className="w-full p-2.5 rounded-lg border border-green-300 bg-gray-100 text-gray-500"
              />
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-green-900 font-medium mb-1">Gender</label>
                <select
                  value={gender}
                  onChange={(e) => setGender(e.target.value)}
                  className="w-full p-2.5 rounded-lg border border-green-300 focus:outline-none focus:ring-2 focus:ring-green-400"
                  required
                >
                  <option value="">Select Gender</option>
                  <option value="male">Male</option>
                  <option value="female">Female</option>
                  <option value="other">Other</option>
                </select>
              </div>

              <div>
                <label className="block text-green-900 font-medium mb-1">Age (years)</label>
                <input
                  type="number"
                  placeholder="Age"
                  value={age}
                  onChange={(e) => setAge(e.target.value)}
                  className="w-full p-2.5 rounded-lg border border-green-300 focus:outline-none focus:ring-2 focus:ring-green-400"
                  min="0"
                  required
                />
              </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <label className="block text-green-900 font-medium mb-1">Height (cm)</label>
                <input
                  type="number"
                  placeholder="Height"
                  value={height}
                  onChange={(e) => setHeight(e.target.value)}
                  className="w-full p-2.5 rounded-lg border border-green-300 focus:outline-none focus:ring-2 focus:ring-green-400"
                  min="0"
                  required
                />
              </div>

              <div>
                <label className="block text-green-900 font-medium mb-1">Weight (kg)</label>
                <input
                  type="number"
                  placeholder="Weight"
                  value={weight}
                  onChange={(e) => setWeight(e.target.value)}
                  className="w-full p-2.5 rounded-lg border border-green-300 focus:outline-none focus:ring-2 focus:ring-green-400"
                  min="0"
                  step="0.1"
                  required
                />
              </div>
            </div>

            <div className="md:col-span-2">
              <label className="block text-green-900 font-medium mb-1">Activity Level</label>
              <select
                value={activityLevel}
                onChange={(e) => setActivityLevel(e.target.value)}
                className="w-full p-2.5 rounded-lg border border-green-300 focus:outline-none focus:ring-2 focus:ring-green-400"
                required
              >
                <option value="">Select Activity Level</option>
                <option value="sedentary">Sedentary (little to no exercise)</option>
                <option value="lightly_active">Lightly Active (light exercise 1-3 days/week)</option>
                <option value="moderately_active">Moderately Active (moderate exercise 3-5 days/week)</option>
                <option value="very_active">Very Active (hard exercise 6-7 days/week)</option>
                <option value="extra_active">Extra Active (very hard exercise/physical job/training twice a day)</option>
              </select>
            </div>

            {/* Save Button */}
            <button
              type="submit"
              className="w-full bg-green-600 hover:bg-green-700 text-white py-3 rounded-lg font-semibold shadow-md transition-transform hover:scale-[1.02] flex items-center justify-center space-x-2 md:col-span-2"
            >
              <Save size={20} /> <span>Save Profile</span>
            </button>
          </form>
        </motion.div>
      </div>

      {/* Footer */}
      <footer className="text-center py-4 mt-4 text-green-700/70 text-sm border-t border-white/40 bg-green-200/30 backdrop-blur-md">
        © {new Date().getFullYear()} CalorieApp. All rights reserved.
      </footer>
    </div>
  );
}