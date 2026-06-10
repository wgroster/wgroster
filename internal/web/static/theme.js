// Theme bootstrap. Loaded as a blocking <script> in <head> so the chosen theme
// is applied before first paint (no flash). External file to satisfy a strict
// Content-Security-Policy (no inline scripts).
(function () {
  "use strict";
  var KEY = "wg-theme";
  var media = window.matchMedia("(prefers-color-scheme: dark)");

  function resolveDark(pref) {
    return pref === "dark" || (pref !== "light" && media.matches);
  }
  function apply(pref) {
    document.documentElement.classList.toggle("dark", resolveDark(pref));
  }
  function current() {
    return localStorage.getItem(KEY) || "system";
  }

  apply(current());

  window.WGTheme = {
    get: current,
    set: function (pref) {
      localStorage.setItem(KEY, pref);
      apply(pref);
    },
  };

  // Follow the OS setting live while in "system" mode.
  try {
    media.addEventListener("change", function () {
      if (current() === "system") apply("system");
    });
  } catch (e) { /* older browsers */ }
})();
