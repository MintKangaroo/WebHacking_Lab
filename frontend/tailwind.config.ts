import type { Config } from "tailwindcss";

export default {
  darkMode: ["class"],
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        canvas: "#080b10",
        panel: "#0d1219",
        elevated: "#111923",
        line: "#202b38",
        cyan: {
          300: "#67e8f9",
          400: "#22d3ee",
          500: "#06b6d4",
        },
      },
      boxShadow: {
        panel: "0 14px 44px rgba(0, 0, 0, 0.22)",
        focus: "0 0 0 3px rgba(34, 211, 238, 0.18)",
      },
      fontFamily: {
        sans: ["Inter", "Pretendard", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },
      keyframes: {
        "fade-up": {
          "0%": { opacity: "0", transform: "translateY(6px)" },
          "100%": { opacity: "1", transform: "translateY(0)" },
        },
      },
      animation: {
        "fade-up": "fade-up 420ms ease-out both",
      },
    },
  },
  plugins: [],
} satisfies Config;
