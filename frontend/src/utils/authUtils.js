// src/utils/authUtils.js

export const isAuthenticated = () => {
  // Check localStorage first (for "Remember Me")
  const token = localStorage.getItem('token');
  if (token) {
    // You could add token verification here (e.g., decode JWT and check expiry)
    // For simplicity, we just check for its existence.
    return true;
  }

  // Check sessionStorage next (for regular logins)
  const sessionToken = sessionStorage.getItem('token');
  if (sessionToken) {
    return true;
  }

  return false;
};

// Optional: Function to clear all auth data
export const clearAuthData = () => {
  localStorage.removeItem('token');
  localStorage.removeItem('email');
  localStorage.removeItem('name');
  sessionStorage.removeItem('token');
  sessionStorage.removeItem('email');
  sessionStorage.removeItem('name');
};