/* sealed console — connects to a running backend and shows ONLY real results,
   in plain words. No raw data, no IDs, no code, no sequence numbers. */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var LS = "sealed-endpoints";
  var RED_TOKEN = "red-cap-token-dev";

  var urls = { broker: "http://localhost:8000", audit: "http://localhost:8001", red: "http://localhost:8004" };
  try { var saved = JSON.parse(localStorage.getItem(LS) || "null"); if (saved) urls = saved; } catch (e) {}
  ["broker", "audit", "red"].forEach(function (k) { if ($(k)) $(k).value = urls[k]; });

  var connected = { broker: false, audit: false, red: false };
  var timer = null;

  function trim(u) { return (u || "").replace(/\/+$/, ""); }
  function setBadge(el, state, text) { el.className = "badge " + state; el.textContent = text; }

  async function getJSON(url, opts) {
    var ctrl = new AbortController();
    var t = setTimeout(function () { ctrl.abort(); }, 8000);
    try {
      var r = await fetch(url, Object.assign({ signal: ctrl.signal }, opts || {}));
      clearTimeout(t);
      return { ok: r.ok, data: await safeJson(r) };
    } catch (e) { clearTimeout(t); return { ok: false }; }
  }
  async function safeJson(r) { try { return await r.json(); } catch (e) { return null; } }

  function mixedContentWarning() {
    var note = $("mixedNote"); if (!note) return;
    if (location.protocol === "https:" && [urls.broker, urls.audit, urls.red].some(function (u) { return /^http:\/\//i.test(u); })) {
      note.style.display = "";
      note.textContent = "This page is secure (https), so it can't talk to a plain (http) system. Open the console on the same computer that runs it, or put it behind a secure address.";
    } else { note.style.display = "none"; }
  }

  async function probe() {
    for (var k of ["broker", "audit", "red"]) {
      var res = await getJSON(trim(urls[k]) + "/health");
      connected[k] = res.ok;
      setBadge($("st-" + k), res.ok ? "ok" : "idle", res.ok ? "connected" : "not connected");
    }
    $("runEval").disabled = !connected.red;
    $("runContam").disabled = !connected.red;
    $("verifyBtn").disabled = !connected.audit;
    await renderHealth();
    await renderActivity();
  }

  var GOOD = { enforced: 1, on: 1, one_way: 1, dropped_all: 1, read_only: 1 };
  var SOFT = { off: 1, disabled: 1, stateless_calls: 1, not_yet_enforced: 1 };
  var FRIENDLY = {
    network_segmentation: "The teams can't reach each other",
    seccomp: "Dangerous actions are blocked",
    capabilities: "Extra powers are removed",
    rootfs: "Files are locked",
    cgroups: "Each team gets its own limits",
    model_context_fresh: "The AI's memory is wiped each test",
    capability_tokens: "Only allowed requests go through",
    disclosure_gating: "The attack is hidden from the defenders",
    timing_normalization: "Timing clues are smoothed",
    monitor: "A security watcher is running"
  };
  var VALUE = { enforced: "on", on: "on", one_way: "on", dropped_all: "on", read_only: "on",
    off: "off", disabled: "off", stateless_calls: "on", not_yet_enforced: "off" };

  function badgeClass(v) { return GOOD[String(v)] ? "ok" : (SOFT[String(v)] ? "warn" : "idle"); }

  async function renderHealth() {
    var box = $("health");
    if (!connected.broker) {
      box.innerHTML = '<div class="empty"><div class="big">Not connected</div>Connect to see which protections are on.</div>';
      return;
    }
    var res = await getJSON(trim(urls.broker) + "/health/isolation");
    if (!res.ok || !res.data) {
      box.innerHTML = '<div class="empty"><div class="big">Unavailable</div>The system is reachable but did not report its protections.</div>';
      return;
    }
    var rows = "";
    Object.keys(res.data).forEach(function (k) {
      if (!FRIENDLY[k]) return;
      var val = VALUE[String(res.data[k])] || "on";
      rows += '<div class="row"><span class="key">' + FRIENDLY[k] + '</span>' +
        '<span class="badge ' + badgeClass(res.data[k]) + '">' + val + "</span></div>";
    });
    box.innerHTML = rows || '<div class="empty">No status reported.</div>';
  }

  var PHRASE = {
    test_start: "A test started",
    attack: "An attack was sent",
    model_response: "The AI answered",
    verdict: "The defenders checked the answer",
    test_conclude: "The test finished",
    policy_violation: "An unauthorized request was blocked",
    alert: "The security watcher noted something",
    disclosure_withheld: "The attack was kept hidden from the defenders"
  };

  async function renderActivity() {
    var wrap = $("activity");
    if (!connected.audit) {
      wrap.innerHTML = '<div class="empty"><div class="big">Nothing yet</div>Connect, or run a test to see activity.</div>';
      return;
    }
    var res = await getJSON(trim(urls.audit) + "/log?limit=12");
    if (!res.ok || !res.data || !res.data.entries) { wrap.innerHTML = '<div class="empty">Activity unavailable.</div>'; return; }
    var items = res.data.entries.slice().reverse()
      .map(function (e) { return PHRASE[e.event]; })
      .filter(Boolean).slice(0, 10);
    if (!items.length) { wrap.innerHTML = '<div class="empty"><div class="big">Nothing yet</div>Run a test to see activity.</div>'; return; }
    wrap.innerHTML = '<ul class="feed">' + items.map(function (t) {
      return '<li><span class="tick"></span>' + t + "</li>"; }).join("") + "</ul>";
  }

  function showOut(text) { var o = $("out"); o.style.display = ""; o.textContent = text; }

  async function runEval() {
    showOut("Running a round of tests…");
    var res = await getJSON(trim(urls.red) + "/run", { method: "POST" });
    showOut(res.ok ? "Done. A round of tests just ran — you can follow each step in the activity below."
      : "Couldn't reach your system. Is it running?");
    await renderActivity();
  }

  async function runContam() {
    showOut("Planting a secret in one test, then asking for it in a separate test…");
    var res = await getJSON(trim(urls.red) + "/run_contamination", { method: "POST" });
    if (!res.ok || !res.data) { showOut("Couldn't reach your system. Is it running?"); return; }
    showOut(res.data.leaked
      ? "Leak found: the AI remembered the secret from the earlier test."
      : "Clean: the AI had no memory of the earlier test.");
    await renderActivity();
  }

  async function verify() {
    showOut("Re-checking the record…");
    var res = await getJSON(trim(urls.audit) + "/verify", { method: "POST" });
    if (!res.ok || !res.data) { showOut("Couldn't reach the record. Is your system running?"); return; }
    showOut(res.data.intact
      ? "The record is intact — nothing has been changed."
      : "The record was tampered with — the check caught it.");
  }

  function connect() {
    ["broker", "audit", "red"].forEach(function (k) { urls[k] = trim($(k).value); });
    try { localStorage.setItem(LS, JSON.stringify(urls)); } catch (e) {}
    mixedContentWarning();
    probe();
    if (timer) clearInterval(timer);
    timer = setInterval(probe, 4000);
  }

  $("connectBtn").addEventListener("click", connect);
  $("runEval").addEventListener("click", runEval);
  $("runContam").addEventListener("click", runContam);
  $("verifyBtn").addEventListener("click", verify);

  mixedContentWarning();
  probe();
  timer = setInterval(probe, 4000);
})();
