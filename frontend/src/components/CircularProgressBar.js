import React from 'react';

const CircularProgressBar = ({ progress, size = 120, strokeWidth = 10, target }) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = radius * 2 * Math.PI;

  // Calculate the percentage of the goal achieved
  let percentage = 0;
  if (target > 0) {
    percentage = Math.min(100, (progress / target) * 100);
  }

  // CORRECTED CALCULATION for strokeDashoffset:
  // The dashoffset needs to be calculated based on the *unfilled* portion
  // As progress increases, the offset decreases, revealing more of the stroke.
  const offset = circumference - (percentage / 100) * circumference;


  // Determine color based on progress vs target
  let strokeColor = 'hsl(142, 70%, 50%)'; // Green for good
  if (target > 0 && progress > target) {
    strokeColor = 'hsl(0, 70%, 60%)'; // Red if over target
  } else if (target > 0 && percentage > 80) {
    strokeColor = 'hsl(40, 70%, 60%)'; // Orange if approaching target
  }

  return (
    <div className="flex flex-col items-center justify-center">
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        className="-rotate-90" // Rotate to start from top
      >
        {/* Background circle */}
        <circle
          stroke="#e6e6e6"
          fill="transparent"
          strokeWidth={strokeWidth}
          r={radius}
          cx={size / 2}
          cy={size / 2}
        />
        {/* Progress circle */}
        <circle
          stroke={strokeColor}
          fill="transparent"
          strokeWidth={strokeWidth}
          strokeDasharray={circumference + ' ' + circumference}
          style={{ strokeDashoffset: offset }}
          r={radius}
          cx={size / 2}
          cy={size / 2}
          strokeLinecap="round"
        />
        <text
          x="50%"
          y="50%"
          dominantBaseline="middle"
          textAnchor="middle"
          className="text-lg font-bold"
          fill="#333"
          transform="rotate(90, 60, 60)" // Counter-rotate text
        >
          {`${progress} / ${target || 0}`}
        </text>
        <text
          x="50%"
          y="70%"
          dominantBaseline="middle"
          textAnchor="middle"
          className="text-xs"
          fill="#555"
          transform="rotate(90, 60, 60)" // Counter-rotate text
        >
          Kcal
        </text>
      </svg>
      {target > 0 && (
        <p className="mt-2 text-sm text-gray-700">
          {Math.round(percentage)}% of goal {/* Round percentage for display */}
        </p>
      )}
    </div>
  );
};

export default CircularProgressBar;