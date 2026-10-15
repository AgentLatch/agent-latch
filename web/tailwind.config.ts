import type { Config } from "tailwindcss";

/**
 * Invicti design tokens (AL-101).
 * Semantic names map to the enterprise cybersecurity palette so pages stay consistent.
 */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        // Dark base
        base: "#080C14", // slate-950-ish, the app background
        // Glass surface for cards (used with backdrop blur)
        surface: "rgba(19, 28, 49, 0.6)",
        "surface-solid": "#131C31",
        // Primary accent — violet
        accent: {
          DEFAULT: "#8B5CF6",
          deep: "#7C3AED",
          // Secondary accent — cyan
          cyan: "#06B6D4",
          "cyan-bright": "#22D3EE",
        },
        // Alert / risk levels
        risk: {
          high: "#F43F5E",
          medium: "#F59E0B",
          low: "#10B981",
        },
      },
      boxShadow: {
        neon: "0 0 20px rgba(139, 92, 246, 0.45)",
        "neon-strong": "0 0 28px rgba(139, 92, 246, 0.7)",
        "neon-cyan": "0 0 20px rgba(6, 182, 212, 0.45)",
      },
      backdropBlur: {
        xs: "2px",
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "-apple-system", "Segoe UI", "sans-serif"],
      },
    },
  },
  plugins: [],
} satisfies Config;
