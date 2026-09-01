/** @type {import('tailwindcss').Config} */

// Allow any integer opacity modifier (e.g. text-white/45, border-white/12)
const fineOpacity = Object.fromEntries(
  Array.from({ length: 101 }, (_, i) => [i, (i / 100).toString()])
);

export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      opacity: fineOpacity,
      fontFamily: {
        sans: ["'Plus Jakarta Sans'", 'system-ui', '-apple-system', 'sans-serif'],
        mono: ["'JetBrains Mono'", 'ui-monospace', 'monospace'],
      },
    },
  },
  plugins: [],
}
