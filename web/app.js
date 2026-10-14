/* sealed console — connects to a running backend and shows ONLY real data.
   No fabricated values: every number here comes from the backend, or the panel
   stays in its empty/disconnected state. */
(function () {
  "use strict";

  var $ = function (id) { return document.getElementById(id); };
  var LS = "sealed-endpoints";
  var RED_TOKEN = "red-cap-token-dev"; // dev default; matches compose defaults

  var urls = { broker: "http://localhost:8000", audit: "http://localhost:8001", red: "http://localhost:8004" };
  try { var saved = JSON.parse(localStorage.getItem(LS) || "null"); if (saved) urls = saved; } catch (e) {}
  ["broker", "audit", "red"].forEach(function (k) { if ($(k)) $(k).value = urls[k]; });

  var connected = { broker: false, audit: false, red: false };
  var timer = null;

  function trim(u) { return (u || "").replace(/\/+$/, ""); }

  function setBadge(el, state, text) {
    el.className = "badge " + state;
    el.textContent = text;
  }

  async function getJSON(url, opts) {
    var ctrl = new AbortController();
    var t = setTimeout(function () { ctrl.abort(); }, 8000);
    try {
      var r = await fetch(url, Object.assign({ signal: ctrl.signal }, opts || {}));
      clearTimeout(t);
      if (!r.ok) return { ok: false, status: r.status, data: await safeJson(r) };
      return { ok: true, status: r.status, data: await safeJson(r) };
    } catch (e) {
      clearTimeout(t);
      return { ok: false, error: e };
    }
  }
  async function safeJson(r) { try { return await r.json(); } catch (e) { return null; } }

  function mixedContentWarning() {
    var note = $("mixedNote");
    if (!note) return;
    if (location.protocol === "https:" &&
        [urls.broker, urls.audit, urls.red].some(function (u) { return /^http:\/\//i.test(u); })) {
      note.style.display = "";
      note.innerHTML = "This page is served over HTTPS, so browsers block calls to an <code>http://</code> backend (mixed content). Run the console locally (<code>make dashboard</code> or open these files), or serve the backend over HTTPS.";
    } else {
      note.style.display = "none";
    }
  }

  async function probe() {
    for (var k of ["broker", "audit", "red"]) {
      var res = await getJSON(trim(urls[k]) + "/health");
      connected[k] = res.ok;
      var el = $("st-" + k);
      if (res.ok) setBadge(el, "ok", "connected");
      else setBadge(el, "idle", "unreachable");
    }
    $("runEval").disabled = !connected.red;
    $("runContam").disabled = !connected.red;
    $("verifyBtn").disabled = !connected.audit;
    await renderHealth();
    await renderLog();
  }

  var GOOD = { enforced: 1, on: 1, one_way: 1, dropped_all: 1, read_only: 1 };
  var SOFT = { off: 1, disabled: 1, stateless_calls: 1, not_yet_enforced: 1 };

  // Plain-English label for each technical status key.
  var FRIENDLY = {
    network_segmentation: "Teams can't reach each other",
    seccomp: "Dangerous actions blocked",
    capabilities: "Extra powers removed",
    rootfs: "Files locked (read-only)",
    cgroups: "Resources capped per team",
    model_context_fresh: "AI memory wiped each test",
    capability_tokens: "Only allowed calls permitted",
    disclosure_gating: "Attack hidden from defenders",
    timing_normalization: "Timing leaks smoothed",
    monitor: "Security watcher"
  };
  // Plain-English version of each status value.
  var VALUE = {
    enforced: "on", on: "on", one_way: "one-way", dropped_all: "removed",
    read_only: "locked", off: "off", disabled: "off",
    stateless_calls: "fresh", not_yet_enforced: "not yet"
  };

  function badgeClass(v) {
    var s = String(v);
    if (GOOD[s]) return "ok";
    if (SOFT[s]) return "warn";
    return "idle";
  }

  async function renderHealth() {
    var box = $("health");
    if (!connected.broker) {
      box.innerHTML = '<div class="empty"><div class="big">Not connected</div>Connect to see which protections are active.</div>';
      return;
    }
    var res = await getJSON(trim(urls.broker) + "/health/isolation");
    if (!res.ok || !res.data) {
      box.innerHTML = '<div class="empty"><div class="big">Unavailable</div>The system is reachable but did not report its protections.</div>';
      return;
    }
    var rows = "";
    Object.keys(res.data).forEach(function (k) {
      if (k === "proven_by" || k === "note") return;
      var raw = res.data[k];
      var label = FRIENDLY[k] || k.replace(/_/g, " ");
      var val = VALUE[String(raw)] || String(raw);
      rows += '<div class="row"><span class="key">' + label +
        '<br><span class="tech">' + k.replace(/_/g, " ") + '</span></span>' +
        '<span class="badge ' + badgeClass(raw) + '">' + val + "</span></div>";
    });
    box.innerHTML = rows || '<div class="empty">No status reported.</div>';
  }

  async function renderLog() {
    var wrap = $("logWrap"), count = $("auditCount");
    if (!connected.audit) {
      wrap.innerHTML = '<div class="empty"><div class="big">No events yet</div>Connect to the audit service, or run an eval to generate events.</div>';
      count.textContent = ""; count.className = "badge idle";
      return;
    }
    var res = await getJSON(trim(urls.audit) + "/log?limit=30");
    if (!res.ok || !res.data || !res.data.entries) {
      wrap.innerHTML = '<div class="empty">Audit log unavailable.</div>';
      count.textContent = ""; return;
    }
    var entries = res.data.entries.slice().reverse();
    count.textContent = res.data.count + " entries"; count.className = "badge ok";
    if (!entries.length) {
      wrap.innerHTML = '<div class="empty"><div class="big">No events yet</div>Run an eval to generate audit events.</div>';
      return;
    }
    var rows = entries.map(function (e) {
      return "<tr><td class='mono'>" + e.seq + "</td><td>" + esc(e.actor) +
        "</td><td>" + esc(e.event) + "</td><td class='mono'>" + esc(e.test_id || "") + "</td></tr>";
    }).join("");
    wrap.innerHTML = "<table><thead><tr><th>seq</th><th>actor</th><th>event</th><th>test</th></tr></thead><tbody>" + rows + "</tbody></table>";
  }

  function esc(s) { return String(s).replace(/[&<>]/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]; }); }

  function showOut(obj) {
    var out = $("out");
    out.style.display = "";
    out.textContent = typeof obj === "string" ? obj : JSON.stringify(obj, null, 2);
  }

  function showResult(summary, data) {
    showOut(summary + "\n\n— details —\n" + JSON.stringify(data, null, 2));
  }

  async function runEval() {
    showOut("Running a test…");
    var res = await getJSON(trim(urls.red) + "/run", { method: "POST" });
    if (!res.ok || !res.data) { showOut("Couldn't reach your system. Is it running?"); return; }
    var rs = res.data.results || [];
    var refused = rs.filter(function (r) { return r.verdict === "refused"; }).length;
    var flagged = rs.filter(function (r) { return r.flagged; }).length;
    showResult("Ran " + (res.data.attacks_run || rs.length) + " attacks. The AI refused " +
      refused + ", and the defenders flagged " + flagged + " as unsafe.", res.data);
    await renderLog();
  }

  async function runContam() {
    showOut("Planting a secret in one test, then asking for it in a separate test…");
    var res = await getJSON(trim(urls.red) + "/run_contamination", { method: "POST" });
    if (!res.ok || !res.data) { showOut("Couldn't reach your system. Is it running?"); return; }
    var msg = res.data.leaked
      ? "⚠ Leak: the AI remembered the secret across tests."
      : "✓ Clean: the AI had no memory of the earlier test.";
    showResult(msg, res.data);
    await renderLog();
  }

  async function verify() {
    showOut("Re-checking every entry in the record…");
    var res = await getJSON(trim(urls.audit) + "/verify", { method: "POST" });
    if (!res.ok || !res.data) { showOut("Couldn't reach the record. Is your system running?"); return; }
    var msg = res.data.intact
      ? "✓ Untampered: every entry checks out."
      : "⚠ Tampering found at entry " + res.data.broken_seq + " (" + res.data.reason + ").";
    showResult(msg, res.data);
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
  probe(); // try the defaults on load
  timer = setInterval(probe, 4000);
})();
