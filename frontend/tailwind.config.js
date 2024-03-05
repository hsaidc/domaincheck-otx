/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        primary: {
          100: "#C9DFF2",
          200: "#789EBF",
          300: "#3C678C",
          400: "#153959",
          500: "#011526",
        },
        tones: {
          1: "#808080",
          2: "#6d6f72",
          3: "#5b5f65",
          4: "#494f58",
          5: "#373f4b",
          6: "#26313e",
          7: "#152232",
          8: "#011526",
        },
      },
      fontFamily: {
        inter: ["Inter", "sans-serif"],
      },
    },
  },
  plugins: [],
};
