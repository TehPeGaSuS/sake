// sake webadmin: theme switch, mobile menu and delete confirmations. Pages
// work without it; the theme itself is applied early by layout.html.
(function () {
  "use strict";

  function storedTheme() {
    try {
      return localStorage.getItem("sake-theme") || "auto";
    } catch (e) {
      return "auto";
    }
  }

  function applyTheme(theme) {
    if (theme === "light" || theme === "dark") {
      document.documentElement.setAttribute("data-theme", theme);
    } else {
      document.documentElement.removeAttribute("data-theme");
    }
  }

  document.querySelectorAll('.theme-switch input[name="theme"]').forEach(function (input) {
    input.checked = input.value === storedTheme();
    input.addEventListener("change", function () {
      try {
        localStorage.setItem("sake-theme", input.value);
      } catch (e) {}
      applyTheme(input.value);
    });
  });

  var sidebar = document.querySelector(".sidebar");
  var toggle = document.querySelector(".menu-toggle");
  if (sidebar && toggle) {
    toggle.addEventListener("click", function () {
      var open = sidebar.classList.toggle("open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
  }

  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (ev) {
      if (!window.confirm(form.getAttribute("data-confirm"))) {
        ev.preventDefault();
      }
    });
  });
})();
