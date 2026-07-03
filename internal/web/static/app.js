// Portal UI behaviour. Loaded as an external script so the page can ship a
// strict Content-Security-Policy (no inline scripts or event handlers).
(function () {
  "use strict";

  var PLACEHOLDER = "<YOUR_PRIVATE_KEY>";
  var pendingForm = null; // form awaiting confirmation in the styled dialog

  function flash(btn, text) {
    var old = btn.textContent;
    btn.textContent = text;
    setTimeout(function () { btn.textContent = old; }, 1200);
  }

  // copyText copies to the clipboard, using the async Clipboard API in a secure
  // context and falling back to a hidden-textarea execCommand otherwise (the
  // Clipboard API is unavailable over plain HTTP, e.g. in development).
  function copyText(text, btn) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(
        function () { flash(btn, "copied!"); },
        function () { fallbackCopy(text, btn); }
      );
      return;
    }
    fallbackCopy(text, btn);
  }

  function fallbackCopy(text, btn) {
    var ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.top = "-1000px";
    document.body.appendChild(ta);
    ta.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(ta);
    flash(btn, ok ? "copied!" : "copy failed");
  }

  // buildConfig returns the configuration with the placeholder replaced by the
  // private key typed in the (browser-only) field, or null if not available.
  function buildConfig() {
    var conf = document.getElementById("conf");
    var pk = document.getElementById("privkey");
    if (!conf || !pk) return null;
    var v = pk.value.trim();
    if (!v) return null;
    return conf.textContent.replace(PLACEHOLDER, v);
  }

  function showMsg(text) {
    var el = document.getElementById("qrmsg");
    if (!el) return;
    el.textContent = text || "";
    el.classList.toggle("hidden", !text);
  }

  function base64(bytes) {
    var s = "";
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }

  function closeMenus() {
    document.querySelectorAll("details[data-menu][open]").forEach(function (d) {
      d.removeAttribute("open");
    });
  }

  function markTheme() {
    var cur = (window.WGTheme && window.WGTheme.get()) || "system";
    document.querySelectorAll("[data-theme]").forEach(function (b) {
      var on = b.getAttribute("data-theme") === cur;
      b.classList.toggle("bg-emerald-600", on);
      b.classList.toggle("text-white", on);
      b.classList.toggle("border-emerald-600", on);
    });
  }

  document.addEventListener("click", function (e) {
    // Close any open dropdown when the click lands outside it.
    document.querySelectorAll("details[data-menu][open]").forEach(function (d) {
      if (!d.contains(e.target)) d.removeAttribute("open");
    });

    // Clicking the backdrop of a <dialog> closes it (target is the dialog itself).
    if (e.target.tagName === "DIALOG") { e.target.close(); return; }

    var t = e.target.closest ? e.target.closest("[data-copy],[data-action],[data-dialog],[data-close],[data-flash-close],[data-theme],[data-confirm-ok]") : null;
    if (!t) return;

    if (t.hasAttribute("data-confirm-ok")) {
      var pf = pendingForm;
      pendingForm = null;
      var pd = t.closest("dialog");
      if (pd) pd.close();
      if (pf) pf.submit();
      return;
    }
    if (t.hasAttribute("data-theme")) {
      if (window.WGTheme) window.WGTheme.set(t.getAttribute("data-theme"));
      markTheme();
      return;
    }
    if (t.hasAttribute("data-dialog")) {
      closeMenus();
      var dlg = document.getElementById(t.getAttribute("data-dialog"));
      if (dlg && dlg.showModal) dlg.showModal();
      return;
    }
    if (t.hasAttribute("data-close")) {
      var open = t.closest("dialog");
      if (open) open.close();
      return;
    }
    if (t.hasAttribute("data-flash-close")) {
      var fl = t.closest("[data-flash]");
      if (fl) dismissFlash(fl);
      return;
    }

    if (t.hasAttribute("data-copy")) {
      var el = document.querySelector(t.getAttribute("data-copy"));
      if (el) copyText(el.textContent, t);
      return;
    }

    var action = t.getAttribute("data-action");
    if (action === "qr") {
      var conf = buildConfig();
      if (!conf) { showMsg("Enter your private key first."); return; }
      if (typeof QRCode === "undefined") { showMsg("QR library could not be loaded."); return; }
      showMsg("");
      var target = document.getElementById("qr");
      target.innerHTML = "";
      new QRCode(target, { text: conf, width: 240, height: 240, correctLevel: QRCode.CorrectLevel.L });
    } else if (action === "download-complete") {
      var c = buildConfig();
      if (!c) { showMsg("Enter your private key first."); return; }
      showMsg("");
      var fname = (t.getAttribute("data-fname") || "wg").replace(/[^A-Za-z0-9_-]/g, "_");
      var blob = new Blob([c], { type: "text/plain" });
      var a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = fname + ".conf";
      a.click();
      URL.revokeObjectURL(a.href);
    } else if (action === "genkey") {
      // Generate a WireGuard (Curve25519) keypair entirely in the browser.
      if (typeof nacl === "undefined") { window.alert("Key generation library not loaded."); return; }
      var kp = nacl.box.keyPair();
      var pkInput = document.getElementById("public_key");
      if (pkInput) pkInput.value = base64(kp.publicKey);
      var out = document.getElementById("privkey-out");
      if (out) out.textContent = base64(kp.secretKey);
      var box = document.getElementById("keypair-out");
      if (box) box.classList.remove("hidden");
    } else if (action === "download-el") {
      var src = document.querySelector(t.getAttribute("data-target"));
      if (!src) return;
      var dn = (t.getAttribute("data-fname") || "wg").replace(/[^A-Za-z0-9_-]/g, "_");
      var b = new Blob([src.textContent], { type: "text/plain" });
      var dl = document.createElement("a");
      dl.href = URL.createObjectURL(b);
      dl.download = dn + ".conf";
      dl.click();
      URL.revokeObjectURL(dl.href);
    } else if (action === "enroll") {
      enroll(t);
    }
  });

  // Self-enrollment: generate keys in the browser, reserve an IP server-side,
  // and assemble the full config locally for a scan-once mobile setup.
  function enrollMsg(text) {
    var el = document.getElementById("enroll-msg");
    if (!el) return;
    el.textContent = text || "";
    el.classList.toggle("hidden", !text);
  }

  function enroll(btn) {
    if (typeof nacl === "undefined") { enrollMsg("Key generation library not loaded."); return; }
    var nameEl = document.getElementById("enroll-name");
    var name = nameEl ? nameEl.value.trim() : "";
    if (!name) { enrollMsg("Enter a device name first."); return; }
    enrollMsg("");

    var kp = nacl.box.keyPair();
    var priv = base64(kp.secretKey);
    var body = "csrf=" + encodeURIComponent(btn.getAttribute("data-csrf")) +
      "&name=" + encodeURIComponent(name) +
      "&public_key=" + encodeURIComponent(base64(kp.publicKey));

    fetch("/machines/enroll", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body,
    }).then(function (r) {
      if (!r.ok) return r.text().then(function (tx) { throw new Error(tx.trim() || ("HTTP " + r.status)); });
      return r.json();
    }).then(function (d) {
      var conf = "[Interface]\nPrivateKey = " + priv + "\nAddress = " + d.address + "\n";
      if (d.dns) conf += "DNS = " + d.dns + "\n";
      if (d.mtu) conf += "MTU = " + d.mtu + "\n";
      conf += "\n[Peer]\nPublicKey = " + d.peer.public_key + "\nEndpoint = " + d.peer.endpoint +
        "\nAllowedIPs = " + d.peer.allowed_ips + "\n";
      if (d.peer.persistent_keepalive) conf += "PersistentKeepalive = " + d.peer.persistent_keepalive + "\n";

      var pre = document.getElementById("enroll-conf");
      if (pre) pre.textContent = conf;
      var qr = document.getElementById("enroll-qr");
      if (qr && typeof QRCode !== "undefined") { qr.innerHTML = ""; new QRCode(qr, { text: conf, width: 220, height: 220, correctLevel: QRCode.CorrectLevel.L }); }
      var dl = document.querySelector('[data-action="download-el"][data-target="#enroll-conf"]');
      if (dl) dl.setAttribute("data-fname", name);
      var res = document.getElementById("enroll-result");
      if (res) res.classList.remove("hidden");
    }).catch(function (e) { enrollMsg("Enrollment failed: " + e.message); });
  }

  // Confirmation prompts for destructive forms — styled modal, with a native
  // confirm() fallback if the dialog is unavailable.
  document.addEventListener("submit", function (e) {
    var f = e.target;
    if (!f || !f.hasAttribute || !f.hasAttribute("data-confirm")) return;
    e.preventDefault();
    var dlg = document.getElementById("confirm-dialog");
    var msg = document.getElementById("confirm-message");
    if (!dlg || !dlg.showModal || !msg) {
      if (window.confirm(f.getAttribute("data-confirm"))) f.submit();
      return;
    }
    pendingForm = f;
    msg.textContent = f.getAttribute("data-confirm");
    dlg.showModal();
  });

  // Escape closes open dropdown menus (native <dialog> already handles Escape).
  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") closeMenus();
  });

  markTheme();

  // Flash/error banners: fade out on dismiss, auto-hide after a few seconds, and
  // strip the ok/err query params so a reload does not re-show a stale message.
  function dismissFlash(el) {
    el.style.transition = "opacity .3s";
    el.style.opacity = "0";
    setTimeout(function () { if (el.parentNode) el.parentNode.removeChild(el); }, 300);
  }

  function cleanFlashURL() {
    if (!window.history || !window.history.replaceState) return;
    var u = new URL(window.location.href);
    if (!u.searchParams.has("ok") && !u.searchParams.has("err")) return;
    u.searchParams.delete("ok");
    u.searchParams.delete("err");
    window.history.replaceState({}, "", u.pathname + u.search + u.hash);
  }

  function initFlash() {
    var flashes = document.querySelectorAll("[data-flash]");
    if (!flashes.length) return;
    cleanFlashURL();
    flashes.forEach(function (el) {
      setTimeout(function () { dismissFlash(el); }, 6000);
    });
  }

  initFlash();

  // Generic client-side filtering: a search input plus optional status chips.
  // Items carry data-haystack/data-status/data-online; groups (data-group)
  // collapse when they hold no visible item.
  function initFilter(searchId, chipAttr, itemSel, groupSel) {
    var items = document.querySelectorAll(itemSel);
    if (!items.length) return;
    var search = document.getElementById(searchId);
    var emptyEl = document.getElementById(searchId + "-empty");
    var filter = "all";

    function apply() {
      var q = (search && search.value || "").trim().toLowerCase();
      var visibleCount = 0;
      items.forEach(function (el) {
        var hay = el.getAttribute("data-haystack") || "";
        var st = el.getAttribute("data-status");
        var on = el.getAttribute("data-online") === "1";
        var okText = !q || hay.indexOf(q) >= 0;
        var okFilter = filter === "all" ||
          (filter === "pending" && st === "pending") ||
          (filter === "online" && on) ||
          (filter === "offline" && st === "active" && !on);
        var show = okText && okFilter;
        el.style.display = show ? "" : "none";
        if (show) visibleCount++;
      });
      if (emptyEl) emptyEl.classList.toggle("hidden", visibleCount > 0);
      if (groupSel) {
        document.querySelectorAll(groupSel).forEach(function (g) {
          var visible = Array.prototype.some.call(g.querySelectorAll(itemSel), function (el) {
            return el.style.display !== "none";
          });
          g.style.display = visible ? "" : "none";
        });
      }
    }

    if (search) search.addEventListener("input", apply);
    document.querySelectorAll("[" + chipAttr + "]").forEach(function (b) {
      b.addEventListener("click", function () {
        filter = b.getAttribute(chipAttr);
        document.querySelectorAll("[" + chipAttr + "]").forEach(function (x) {
          x.classList.remove("bg-slate-900", "text-white");
          x.classList.add("bg-slate-100", "text-slate-700");
        });
        b.classList.add("bg-slate-900", "text-white");
        b.classList.remove("bg-slate-100", "text-slate-700");
        apply();
      });
    });
    apply();
  }

  initFilter("m-search", "data-mfilter", ".m-item", ".m-group");
  initFilter("e-search", "data-efilter", ".e-item", null);
})();
