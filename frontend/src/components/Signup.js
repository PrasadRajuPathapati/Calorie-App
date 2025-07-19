import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

export default function Signup() {
  const [step, setStep] = useState("signup");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [message, setMessage] = useState(""); // ✅ inline message
  const [messageType, setMessageType] = useState(""); // success / error
  const navigate = useNavigate();

  // handle initial signup (send OTP)
  const handleSignup = async (e) => {
    e.preventDefault();
    setMessage("");
    if (password !== confirmPassword) {
      setMessageType("error");
      setMessage("❌ Passwords do not match!");
      return;
    }
    try {
      const res = await axios.post("https://calorie-app-backend.onrender.com/signup", {
        email,
        password,
      });
      if (res.data.success) {
        setMessageType("success");
        setMessage("📩 OTP sent to your email");
        setStep("verify");
      } else {
        setMessageType("error");
        setMessage(res.data.message || "Signup failed");
      }
    } catch (err) {
      console.error(err);
      setMessageType("error");
      setMessage("❌ Server error");
    }
  };

  // handle OTP verification
  const handleVerifyOtp = async (e) => {
    e.preventDefault();
    setMessage("");
    try {
      const res = await axios.post("https://calorie-app-backend.onrender.com/verify-otp", {
        email,
        otp,
      });
      if (res.data.success) {
        setMessageType("success");
        setMessage("✅ Account created successfully! Redirecting to login...");
        setTimeout(() => navigate("/login"), 1500); // redirect after 1.5s
      } else {
        setMessageType("error");
        setMessage(res.data.message || "Invalid OTP");
      }
    } catch (err) {
      console.error(err);
      setMessageType("error");
      setMessage("❌ Server error");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-green-100 via-green-200 to-green-300 px-4">
      {step === "signup" && (
        <form
          onSubmit={handleSignup}
          className="bg-white/40 backdrop-blur-md p-8 rounded-xl shadow-xl w-full max-w-md"
        >
          <h2 className="text-3xl font-bold text-green-800 mb-6 text-center">
            Create Account
          </h2>
          {message && (
            <p
              className={`mb-4 text-center font-medium ${
                messageType === "error" ? "text-red-600" : "text-green-700"
              }`}
            >
              {message}
            </p>
          )}
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full mb-4 p-3 rounded-lg border border-green-300 focus:outline-none"
            required
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            className="w-full mb-4 p-3 rounded-lg border border-green-300 focus:outline-none"
            required
          />
          <input
            type="password"
            placeholder="Confirm Password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className="w-full mb-4 p-3 rounded-lg border border-green-300 focus:outline-none"
            required
          />
          <button
            type="submit"
            className="w-full bg-green-600 hover:bg-green-700 text-white py-3 rounded-lg font-medium mb-4"
          >
            Send OTP
          </button>
          <p className="text-center">
            Already have an account?{" "}
            <span
              onClick={() => navigate("/login")}
              className="text-green-800 font-semibold underline cursor-pointer"
            >
              Login
            </span>
          </p>
        </form>
      )}

      {step === "verify" && (
        <form
          onSubmit={handleVerifyOtp}
          className="bg-white/40 backdrop-blur-md p-8 rounded-xl shadow-xl w-full max-w-md"
        >
          <h2 className="text-3xl font-bold text-green-800 mb-6 text-center">
            Verify OTP
          </h2>
          {message && (
            <p
              className={`mb-4 text-center font-medium ${
                messageType === "error" ? "text-red-600" : "text-green-700"
              }`}
            >
              {message}
            </p>
          )}
          <input
            type="text"
            placeholder="Enter OTP"
            value={otp}
            onChange={(e) => setOtp(e.target.value)}
            className="w-full mb-4 p-3 rounded-lg border border-green-300 focus:outline-none"
            required
          />
          <button
            type="submit"
            className="w-full bg-green-600 hover:bg-green-700 text-white py-3 rounded-lg font-medium"
          >
            Verify & Create Account
          </button>
        </form>
      )}
    </div>
  );
}
