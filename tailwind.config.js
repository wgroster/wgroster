/** Tailwind build config for wgroster.
 *  Rebuild the embedded CSS after changing template classes:
 *    tailwindcss -i tailwind.input.css -o internal/web/static/app.css --minify
 */
module.exports = {
  darkMode: "class",
  content: ["./internal/web/templates/**/*.html"],
  theme: { extend: {} },
  plugins: [],
};
