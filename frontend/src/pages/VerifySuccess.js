import React from "react";
import { CheckCircleIcon } from "@heroicons/react/24/solid";
import { useNavigate } from "react-router-dom";
import logo from "../assets/logo.png";

const VerifySuccess = () => {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-100 to-green-50 flex items-center justify-center p-4">
      <div className="bg-white rounded-3xl shadow-xl p-10 max-w-md w-full flex flex-col items-center space-y-6 text-center">
        {/* App Branding */}
        <img src={logo} alt="Calorie App Logo" className="h-20 w-20" />
        <h1 className="text-3xl font-bold text-green-600">Calorie App</h1>
        <p className="text-sm text-gray-500">Your health companion</p>

        {/* Success Icon */}
        <CheckCircleIcon className="h-20 w-20 text-green-500 animate-bounce" />

        {/* Heading */}
        <h2 className="text-2xl font-semibold text-gray-700">
          Email Verified!
        </h2>
        <p className="text-gray-500">
          🎉 Your email has been successfully verified. You can now log in and start tracking your calories effortlessly!
        </p>

        {/* Call to action */}
        <button
          onClick={() => navigate("/login")}
          className="mt-4 bg-green-600 text-white px-6 py-3 rounded-lg font-medium hover:bg-green-700 transition-transform transform hover:scale-105"
        >
          Go to Login
        </button>
      </div>
    </div>
  );
};

export default VerifySuccess;
