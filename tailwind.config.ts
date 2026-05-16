import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      fontFamily: {
        mono: ["var(--font-mono)", "JetBrains Mono", "Menlo", "monospace"],
        sans: ["var(--font-sans)", "Inter", "system-ui", "sans-serif"],
      },
      colors: {
        bg: { DEFAULT: "#0a0e14", elev: "#0f141b", panel: "#141a23" },
        line: "#1f2937",
        ink: { DEFAULT: "#d6deeb", dim: "#8b9bb4", faint: "#5a6a82" },
        sev: {
          ok: "#22c55e",
          info: "#3b82f6",
          warn: "#eab308",
          high: "#f97316",
          crit: "#ef4444",
        },
        agent: {
          detective: "#60a5fa",
          forensics: "#a78bfa",
          remediation: "#34d399",
          validator: "#fb923c",
          reporter: "#22d3ee",
          meta: "#f87171",
        },
      },
      animation: {
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "blink": "blink 1.1s steps(2) infinite",
      },
      keyframes: {
        blink: { "0%,100%": { opacity: "1" }, "50%": { opacity: "0" } },
      },
    },
  },
  plugins: [],
};

export default config;
