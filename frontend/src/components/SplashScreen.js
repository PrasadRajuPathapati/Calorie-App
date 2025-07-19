import React, { useEffect } from 'react';
import { motion } from 'framer-motion';
// Removed: import logo from '../assets/logo.png';

export default function SplashScreen({ onAnimationComplete }) {
  useEffect(() => {
    const timer = setTimeout(() => {
      onAnimationComplete();
    }, 4000); // Display for 4 seconds

    return () => clearTimeout(timer);
  }, [onAnimationComplete]);

  const containerVariants = {
    hidden: { opacity: 0 },
    visible: {
      opacity: 1,
      transition: {
        staggerChildren: 0.2
      }
    },
    exit: {
      opacity: 0,
      transition: {
        duration: 0.5,
        ease: "easeOut"
      }
    }
  };

  const itemVariants = {
    // UPDATED: Start from higher up and slightly scaled down, then spring into place
    hidden: { opacity: 0, y: -80, scale: 0.9 },
    visible: {
      opacity: 1,
      y: 0,
      scale: 1,
      transition: {
        type: "spring", // Use spring for the "peak" effect
        damping: 8,     // Lower damping for more bounce
        stiffness: 120, // Adjust stiffness for speed
        duration: 0.8   // Overall duration of the individual item's animation
      }
    }
  };

  const taglineVariants = { // Separate variant for the tagline to have a different animation
    hidden: { opacity: 0, y: 30 },
    visible: {
      opacity: 1,
      y: 0,
      transition: {
        delay: 0.3, // Delay this slightly after the main title
        duration: 0.6
      }
    }
  };


  return (
    <motion.div
      className="fixed inset-0 bg-gradient-to-br from-green-100 to-green-50 flex flex-col items-center justify-center z-50"
      variants={containerVariants}
      initial="hidden"
      animate="visible"
      exit="exit"
    >
      {/* REMOVED: img tag for logo */}
      {/* <motion.img
        src={logo}
        alt="CalorieApp Logo"
        className="w-32 h-32 md:w-48 md:h-48 mb-6 drop-shadow-lg"
        variants={itemVariants}
      /> */}
      <motion.h1
        className="text-5xl md:text-7xl font-extrabold text-green-800 drop-shadow-md tracking-wide"
        variants={itemVariants} // Apply the peak animation variant here
      >
        CalorieApp
      </motion.h1>
      <motion.p
        className="text-lg md:text-xl text-green-700 mt-4"
        variants={taglineVariants} // Use separate variant for different animation
      >
        Your Health Journey Starts Here
      </motion.p>
    </motion.div>
  );
}