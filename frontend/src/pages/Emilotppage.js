import React, { useState } from 'react';
import axios from 'axios';

export default function EmailOtpPage() {
  const [email, setEmail] = useState('');
  const [otp, setOtp] = useState('');
  const [step, setStep] = useState('enterEmail'); // enterEmail or enterOtp

  const sendOtp = async () => {
    try {
      await axios.post('http://localhost:5000/send-email-otp', { email });
      alert('OTP sent! Check your email.');
      setStep('enterOtp');
    } catch (err) {
      alert(err.response?.data?.error || 'Error sending OTP');
    }
  };

  const verifyOtp = async () => {
    try {
      await axios.post('http://localhost:5000/verify-email-otp', { email, otp });
      alert('✅ OTP Verified! Proceeding...');
      // navigate to signup or login success page
    } catch (err) {
      alert(err.response?.data?.error || 'Invalid OTP');
    }
  };

  return (
    <div className="auth-container">
      {step === 'enterEmail' && (
        <>
          <h2>Verify Email</h2>
          <input placeholder="Enter your email" value={email} onChange={e => setEmail(e.target.value)} />
          <button onClick={sendOtp}>Send OTP</button>
        </>
      )}
      {step === 'enterOtp' && (
        <>
          <h2>Enter OTP</h2>
          <input placeholder="Enter OTP" value={otp} onChange={e => setOtp(e.target.value)} />
          <button onClick={verifyOtp}>Verify OTP</button>
        </>
      )}
    </div>
  );
}
