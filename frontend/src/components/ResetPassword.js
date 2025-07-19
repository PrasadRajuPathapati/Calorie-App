import React, { useState } from "react";
import { motion } from "framer-motion";

export default function ResetPassword() {
  const [step, setStep] = useState(1); // 1=email, 2=otp, 3=new password
  const [email, setEmail] = useState("");
  const [otp, setOtp] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [message, setMessage] = useState("");

  const handleRequestOTP = async () => {
    const res = await fetch("https://calorie-app-backend.onrender.com/api/request-reset", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    if (res.ok) setStep(2);
    setMessage(data.message);
  };

  const handleVerifyOTP = async () => {
    const res = await fetch("https://calorie-app-backend.onrender.com/api/verify-otp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, otp }),
    });
    const data = await res.json();
    if (res.ok) setStep(3);
    setMessage(data.message);
  };

  const handleResetPassword = async () => {
    if (password !== confirm) {
      setMessage("Passwords do not match");
      return;
    }
    const res = await fetch("https://calorie-app-backend.onrender.com/api/reset-password", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    setMessage(data.message);
    if (res.ok) {
      setStep(1);
      setEmail("");
      setOtp("");
      setPassword("");
      setConfirm("");
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-green-50 p-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.9 }}
        animate={{ opacity: 1, scale: 1 }}
        transition={{ duration: 0.4 }}
        className="bg-white p-6 rounded-2xl shadow-lg w-full max-w-sm"
      >
        <h1 className="text-2xl font-bold text-green-700 mb-4 text-center">
          Reset Password
        </h1>
        {step === 1 && (
          <>
            <input
              className="w-full border p-2 mb-4 rounded focus:outline-none focus:ring-2 focus:ring-green-400"
              type="email"
              placeholder="Enter your email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
            <button
              onClick={handleRequestOTP}
              className="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-2 rounded"
            >
              Send OTP
            </button>
          </>
        )}

        {step === 2 && (
          <>
            <input
              className="w-full border p-2 mb-4 rounded focus:outline-none focus:ring-2 focus:ring-green-400"
              type="text"
              placeholder="Enter OTP"
              value={otp}
              onChange={(e) => setOtp(e.target.value)}
            />
            <button
              onClick={handleVerifyOTP}
              className="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-2 rounded"
            >
              Verify OTP
            </button>
          </>
        )}

        {step === 3 && (
          <>
            <input
              className="w-full border p-2 mb-2 rounded focus:outline-none focus:ring-2 focus:ring-green-400"
              type="password"
              placeholder="New Password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
            />
            <input
              className="w-full border p-2 mb-4 rounded focus:outline-none focus:ring-2 focus:ring-green-400"
              type="password"
              placeholder="Confirm Password"
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
            />
            <button
              onClick={handleResetPassword}
              className="w-full bg-green-500 hover:bg-green-600 text-white font-semibold py-2 rounded"
            >
              Update Password
            </button>
          </>
        )}

        {message && <p className="mt-4 text-center text-sm text-gray-600">{message}</p>}
      </motion.div>
    </div>
  );
}
