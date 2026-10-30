/* threattrove — small progressive enhancements, no dependencies */
(function () {
  "use strict";

  // Fill the search box from "try:" chips and submit.
  document.querySelectorAll(".chip[data-fill]").forEach(function (chip) {
    chip.addEventListener("click", function () {
      var value = chip.getAttribute("data-fill");
      var input = document.querySelector(".hero .searchbar input") ||
                  document.getElementById("q");
      if (!input) return;
      input.value = value;
      input.focus();
      if (chip.dataset.submit !== "0" && input.form) input.form.submit();
    });
  });

  // Copy-to-clipboard buttons.
  document.querySelectorAll("[data-copy]").forEach(function (btn) {
    btn.addEventListener("click", async function () {
      var sel = btn.getAttribute("data-copy");
      var node = document.querySelector(sel);
      if (!node) return;
      var text = node.textContent.trim();
      var label = btn.textContent;
      try {
        await navigator.clipboard.writeText(text);
      } catch (e) {
        var ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand("copy");
        document.body.removeChild(ta);
      }
      btn.textContent = "Copied";
      setTimeout(function () { btn.textContent = label; }, 1400);
    });
  });

  // Autofocus the lookup box on the home page only.
  var hero = document.querySelector(".hero .searchbar input");
  if (hero && window.matchMedia("(min-width: 720px)").matches) {
    hero.focus({ preventScroll: true });
  }

  // Paste a hash/URL anywhere on the page and it goes in the search box.
  var q = document.getElementById("q");
  if (q) {
    document.addEventListener("paste", function (ev) {
      if (document.activeElement === q) return;
      var text = (ev.clipboardData || window.clipboardData);
      if (!text) return;
      var value = text.getData("text").trim();
      if (!value || /\s/.test(value)) return;
      q.value = value;
      q.focus();
    });
  }

  // Show a friendly message when an upload is too large.
  var form = document.getElementById("bulk-form");
  if (form) {
    form.addEventListener("submit", function (ev) {
      var file = document.getElementById("file");
      if (file && file.files.length && file.files[0].size > 2 * 1024 * 1024) {
        ev.preventDefault();
        alert("That file is larger than the 2 MB upload limit. Split it or use the API.");
        return;
      }
      var btn = form.querySelector("button[type=submit]");
      if (btn) { btn.disabled = true; btn.textContent = "Queueing…"; }
    });
  }
})();
