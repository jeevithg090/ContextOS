// Applies the saved colour theme before first paint so a light-theme user never sees a dark flash.
// Loaded as a blocking same-origin script (the CSP forbids inline scripts); src/lib/theme.ts keeps
// the theme in sync after the app starts.
(function () {
  try {
    var p = localStorage.getItem("contextos.theme") || "dark";
    var light = p === "light" || (p === "system" && window.matchMedia("(prefers-color-scheme: light)").matches);
    var t = light ? "light" : "dark";
    var r = document.documentElement;
    r.dataset.theme = t;
    r.classList.toggle("dark", t === "dark");
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", light ? "#f6f7f9" : "#090b0e");
  } catch (e) {
    /* storage blocked: keep the default dark theme */
  }
})();
