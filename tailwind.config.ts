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
          accent: "#22c55e",
          warning: "#eab308",
          danger: "#ef4444",
          info: "#3b82f6",
          muted: "#6b7280",
        },
        // Design tokens used across components
        bg: {
          panel: "#0d1526",
          elev:  "#111827",
        },
        line: "#1a2744",
        ink: {
          DEFAULT: "#d6deeb",
          dim:     "#8b9bb4",
          faint:   "#4b5563",
        },
        agent: {
          detective:  "#60a5fa",
          forensics:  "#a78bfa",
          remediation:"#34d399",
          validator:  "#fb923c",
          reporter:   "#22d3ee",
          meta:       "#f87171",
        },
        sev: {
          crit: "#ef4444",
          high: "#f97316",
          warn: "#eab308",
          med:  "#eab308",
          ok:   "#22c55e",
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
