import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";

export default function Login() {
  const [step, setStep] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [otp, setOtp] = useState("");
  const [newPass, setNewPass] = useState("");
  const [confirmPass, setConfirmPass] = useState("");
  const [message, setMessage] = useState({ type: "", text: "" });
  const [rememberMe, setRememberMe] = useState(false); // NEW: State for remember me checkbox

  const navigate = useNavigate();

  // handle login
  const handleLogin = async (e) => {
  e.preventDefault();
  setMessage({ type: "", text: "" });
  try {
    const res = await axios.post("https://calorie-app-backend.onrender.com//login", { email, password });
    if (res.data.success) {
      setMessage({ type: "success", text: "✅ Login successful! Redirecting..." });

      // NEW: Store token, email, and name based on rememberMe state
      const storage = rememberMe ? localStorage : sessionStorage;
      storage.setItem("token", res.data.token);
      storage.setItem("email", res.data.email);
      storage.setItem("name", res.data.name || "");

      setTimeout(() => navigate("/profile"), 1000);
    } else {
      setMessage({ type: "error", text: res.data.message });
    }
  } catch (err) {
    console.error(err);
    setMessage({ type: "error", text: "❌ Server error" });
  }
};


  // send reset OTP
  const handleSendResetOtp = async (e) => {
    e.preventDefault();
    setMessage({ type: "", text: "" });
    try {
      const res = await axios.post("https://calorie-app-backend.onrender.com//send-reset-otp", { email });
      if (res.data.success) {
        setMessage({ type: "success", text: "📩 OTP sent to your email" });
        setStep("verifyReset");
      } else {
        setMessage({ type: "error", text: res.data.message });
      }
    } catch (err) {
      console.error(err);
      setMessage({ type: "error", text: "❌ Server error" });
    }
  };

  // verify OTP and reset password
  const handleResetPassword = async (e) => {
    e.preventDefault();
    setMessage({ type: "", text: "" });
    if (newPass !== confirmPass) {
      setMessage({ type: "error", text: "❌ Passwords do not match!" });
      return;
    }
    try {
      const res = await axios.post("https://calorie-app-backend.onrender.com//reset-password", {
        email,
        otp,
        newPass,
      });
      if (res.data.success) {
        setMessage({ type: "success", text: "✅ Password reset successfully! You can login now." });
        setStep("login");
      } else {
        setMessage({ type: "error", text: res.data.message });
      }
    } catch (err) {
      console.error(err);
      setMessage({ type: "error", text: "❌ Server error" });
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-green-100 via-green-200 to-green-300 px-4">
      {step === "login" && (
        <form
          onSubmit={handleLogin}
          className="bg-white/40 backdrop-blur-md p-8 rounded-xl shadow-xl w-full max-w-md"
        >
          <h2 className="text-3xl font-bold text-green-800 mb-6 text-center">Login</h2>
          {message.text && (
            <p
              className={`mb-4 text-center text-sm ${
                message.type === "error" ? "text-red-600" : "text-green-700"
              }`}
            >
              {message.text}
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

          {/* NEW: Remember Me checkbox */}
          <div className="flex items-center mb-4">
            <input
              id="remember-me"
              name="remember-me"
              type="checkbox"
              checked={rememberMe}
              onChange={(e) => setRememberMe(e.target.checked)}
              className="h-4 w-4 text-green-600 focus:ring-green-500 border-gray-300 rounded"
            />
            <label htmlFor="remember-me" className="ml-2 block text-sm text-gray-900">
              Remember me
            </label>
          </div>

          <button
            type="submit"
            className="w-full bg-green-600 hover:bg-green-700 text-white py-3 rounded-lg font-medium mb-4"
          >
            Login
          </button>
          <p
            onClick={() => setStep("reset")}
            className="text-green-700 underline cursor-pointer mb-4 text-center"
          >
            Forgot Password?
          </p>
          <p className="text-center">
            Don’t have an account?{" "}
            <span
              onClick={() => navigate("/signup")}
              className="text-green-800 font-semibold underline cursor-pointer"
            >
              Sign Up
            </span>
          </p>
        </form>
      )}

      {/* reset password form */}
      {step === "reset" && (
        <form
          onSubmit={handleSendResetOtp}
          className="bg-white/40 backdrop-blur-md p-8 rounded-xl shadow-xl w-full max-w-md"
        >
          <h2 className="text-3xl font-bold text-green-800 mb-6 text-center">Reset Password</h2>
          {message.text && (
            <p
              className={`mb-4 text-center text-sm ${
                message.type === "error" ? "text-red-600" : "text-green-700"
              }`}
            >
              {message.text}
            </p>
          )}
          <input
            type="email"
            placeholder="Enter your email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full mb-4 p-3 rounded-lg border border-green-300 focus:outline-none"
            required
          />
          <button
            type="submit"
            className="w-full bg-green-600 hover:bg-green-700 text-white py-3 rounded-lg font-medium"
          >
            Send OTP
          </button>
        </form>
      )}

      {/* verify reset */}
      {step === "verifyReset" && (
        <form
          onSubmit={handleResetPassword}
          className="bg-white/40 backdrop-blur-md p-8 rounded-xl shadow-xl w-full max-w-md"
        >
          <h2 className="text-3xl font-bold text-green-800 mb-6 text-center">Verify OTP</h2>
          {message.text && (
            <p
              className={`mb-4 text-center text-sm ${
                message.type === "error" ? "text-red-600" : "text-green-700"
              }`}
            >
              {message.text}
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
          <input
            type="password"
            placeholder="New Password"
            value={newPass}
            onChange={(e) => setNewPass(e.target.value)}
            className="w-full mb-4 p-3 rounded-lg border border-green-300 focus:outline-none"
            required
          />
          <input
            type="password"
            placeholder="Confirm Password"
            value={confirmPass}
            onChange={(e) => setConfirmPass(e.target.value)}
            className="w-full mb-4 p-3 rounded-lg border border-green-300 focus:outline-none"
            required
          />
          <button
            type="submit"
            className="w-full bg-green-600 hover:bg-green-700 text-white py-3 rounded-lg font-medium"
          >
            Reset Password
          </button>
        </form>
      )}
    </div>
  );
}