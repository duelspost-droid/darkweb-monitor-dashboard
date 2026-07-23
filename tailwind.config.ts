import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Pretendard Variable"', "Pretendard", '"Apple SD Gothic Neo"', '"Malgun Gothic"', "Arial", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "Consolas", "monospace"]
      },
      colors: {
        ink: "#e9eef7",
        panel: "#10151f",
        line: "rgba(148,163,184,0.10)",
        muted: "#94a0b3",
        teal: {
          DEFAULT: "#0f766e",
          50: "#f0fdfa",
          100: "#ccfbf1",
          200: "#99f6e4",
          300: "#5eead4",
          400: "#2dd4bf",
          500: "#14b8a6",
          600: "#0d9488",
          700: "#0f766e",
          800: "#115e59",
          900: "#134e4a",
          950: "#042f2e"
        },
        berry: "#fb7185",
        amber: {
          DEFAULT: "#b45309",
          50: "#fffbeb",
          100: "#fef3c7",
          200: "#fde68a",
          300: "#fcd34d",
          400: "#fbbf24",
          500: "#f59e0b",
          600: "#d97706",
          700: "#b45309",
          800: "#92400e",
          900: "#78350f",
          950: "#451a03"
        },
        cobalt: "#60a5fa"
      },
      boxShadow: {
        soft: "0 1px 2px rgba(16, 24, 40, 0.06), 0 8px 24px rgba(16, 24, 40, 0.05)"
      }
    }
  },
  plugins: []
};

export default config;
