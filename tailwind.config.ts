import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: "class",
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
    "./lib/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        // SentinelAI palette — terminal/security aesthetic
        sentinel: {
          bg: "#0a0f1e",
          panel: "#0d1526",
          border: "#1a2744",
          accent: "#22c55e",       // healthy agent green
          warning: "#eab308",      // investigating yellow
          danger: "#ef4444",       // compromised red
          info: "#3b82f6",         // info blue
          muted: "#6b7280",
        },
      },
      fontFamily: {
        mono: ["JetBrains Mono", "Fira Code", "Consolas", "monospace"],
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "blink": "blink 1s step-end infinite",
      },
      keyframes: {
        blink: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0" },
        },
      },
    },
  },
  plugins: [],
};

export default config;
