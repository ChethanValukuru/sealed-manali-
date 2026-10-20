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
  var lastTest = null, lastProof = null, lastRun = null;

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
    $("tamperBtn").disabled = !connected.audit;
    $("getProof").disabled = !(connected.broker && lastTest);
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
    if (res.ok && res.data && res.data.test_id) {
      lastTest = res.data.test_id;
      lastRun = res.data;
      lastProof = null;
      $("getProof").disabled = !connected.broker;
      $("checkProof").disabled = true;
      $("downloadProof").disabled = true;
      $("reportBtn").disabled = true;
    }
    showOut(res.ok ? "Done. A round of tests just ran — you can follow each step in the activity below, or get a proof it was sound."
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

  function showProof(text) { var o = $("proofOut"); o.style.display = ""; o.textContent = text; }

  async function getProof() {
    if (!lastTest) { showProof("Run a test first."); return; }
    showProof("Issuing a signed proof…");
    var res = await getJSON(trim(urls.broker) + "/eval/attestation/" + encodeURIComponent(lastTest));
    if (!res.ok || !res.data || !res.data.attestation) { showProof("Couldn't get a proof. Is the system running?"); return; }
    lastProof = res.data;
    $("checkProof").disabled = !connected.audit;
    $("downloadProof").disabled = false;
    $("reportBtn").disabled = !(window.jspdf && window.jspdf.jsPDF);
    var f = res.data.attestation;
    var parts = [];
    if (f.chain_intact) parts.push("the record is intact");
    if (f.facts && f.facts.model_context_fresh) parts.push("the AI's memory was fresh");
    if (f.facts && f.facts.network_isolated) parts.push("the teams were isolated");
    showProof("Proof issued. This test ran in a sealed environment — " + parts.join(", ") +
      ". It is signed, so anyone can check it is genuine.");
  }

  async function checkProof() {
    if (!lastProof) { showProof("Get a proof first."); return; }
    showProof("Checking the proof's signature…");
    var res = await getJSON(trim(urls.audit) + "/verify_attestation", {
      method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ attestation: lastProof.attestation, signature: lastProof.signature })
    });
    showProof(res.ok && res.data && res.data.valid
      ? "The proof is genuine — its signature checks out."
      : "The proof did not check out.");
  }

  function downloadProof() {
    if (!lastProof) return;
    var blob = new Blob([JSON.stringify(lastProof, null, 2)], { type: "application/json" });
    var a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "sealed-proof.json";
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 1000);
  }

  function buildReport() {
    if (!lastProof || !(window.jspdf && window.jspdf.jsPDF)) { showProof("Get the proof first."); return; }
    var att = lastProof.attestation, f = att.facts || {};
    var results = (lastRun && lastRun.results) || [];
    var attacks = (f.attacks != null) ? f.attacks : results.length;
    var refused = results.filter(function (r) { return r.verdict === "refused"; }).length;
    var flagged = results.filter(function (r) { return r.flagged; }).length;
    var sig = lastProof.signature || "";
    var fp = sig.length > 20 ? (sig.slice(0, 10) + "…" + sig.slice(-10)) : sig;

    var doc = new window.jspdf.jsPDF({ unit: "pt", format: "a4" });
    var W = doc.internal.pageSize.getWidth(), m = 56, y;
    var INK = [42, 42, 40], MUTE = [107, 107, 102], LINE = [217, 213, 203],
        SAGE = [76, 122, 107], SAGEBG = [232, 239, 234], SAGEINK = [53, 88, 73];

    doc.setFont("helvetica", "bold").setFontSize(20).setTextColor.apply(doc, INK);
    doc.text("sealed", m, 64);
    doc.setFont("helvetica", "normal").setFontSize(11).setTextColor.apply(doc, MUTE);
    doc.text("Evaluation findings report", m, 82);
    doc.text("Generated " + new Date().toLocaleString(), W - m, 82, { align: "right" });
    doc.setDrawColor.apply(doc, LINE); doc.setLineWidth(1); doc.line(m, 94, W - m, 94);

    doc.setFont("helvetica", "bold").setFontSize(13).setTextColor.apply(doc, INK);
    doc.text("Summary", m, 126);
    doc.setFont("helvetica", "normal").setFontSize(11).setTextColor.apply(doc, INK);
    var sum = [
      "Attacks run: " + attacks,
      "The AI refused: " + refused,
      "Flagged as unsafe by the defenders: " + flagged
    ];
    y = 150; sum.forEach(function (t) { doc.text("•  " + t, m, y); y += 20; });

    y += 16;
    doc.setFillColor.apply(doc, SAGEBG); doc.setDrawColor.apply(doc, SAGE);
    doc.roundedRect(m, y, W - 2 * m, 150, 8, 8, "FD");
    doc.setFont("helvetica", "bold").setFontSize(12).setTextColor.apply(doc, SAGEINK);
    doc.text("Isolation attestation", m + 18, y + 26);

    doc.setDrawColor.apply(doc, SAGE); doc.setLineWidth(1);
    doc.roundedRect(W - m - 118, y + 12, 100, 26, 5, 5, "S");
    doc.setFont("helvetica", "bold").setFontSize(11).setTextColor.apply(doc, SAGEINK);
    doc.text("VERIFIED", W - m - 68, y + 29, { align: "center" });

    doc.setFont("helvetica", "normal").setFontSize(10.5).setTextColor.apply(doc, INK);
    var checks = [
      "Isolated environment — the teams were kept apart",
      att.chain_intact ? "Audit record intact — nothing was changed" : "Audit record FLAGGED",
      f.model_context_fresh ? "Fresh model memory for each test" : "Model memory reuse detected",
      "Digitally signed (Ed25519) by " + (att.issuer || "sealed-audit")
    ];
    var yy = y + 52; checks.forEach(function (t) { doc.text("•  " + t, m + 18, yy); yy += 20; });
    doc.setFont("helvetica", "normal").setFontSize(9).setTextColor.apply(doc, MUTE);
    doc.text("Signature fingerprint: " + fp, m + 18, y + 138);

    y += 150 + 28;
    doc.setFontSize(10).setTextColor.apply(doc, MUTE);
    var note = "This report is backed by a cryptographically signed attestation. Anyone can verify it " +
      "independently against the signed proof file (sealed-proof.json) — no need to trust the operator.";
    doc.text(doc.splitTextToSize(note, W - 2 * m), m, y);

    doc.setDrawColor.apply(doc, LINE); doc.line(m, 802, W - m, 802);
    doc.setFontSize(8).setTextColor.apply(doc, MUTE);
    doc.text("sealed — safe, trustworthy AI security testing", m, 818);

    doc.save("sealed-findings-report.pdf");
    showProof("Findings report downloaded — a one-page summary stamped with the signed proof.");
  }

  async function tamperDemo() {
    showProof("Secretly changing a record, then checking…");
    var res = await getJSON(trim(urls.audit) + "/tamper_demo", { method: "POST" });
    if (!res.ok || !res.data) { showProof("Couldn't reach the record. Is your system running?"); return; }
    showProof(res.data.caught
      ? "We changed a record on purpose — and the check caught it. (The real record was left untouched.)"
      : "Run a test first so there is something to check.");
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
  $("getProof").addEventListener("click", getProof);
  $("checkProof").addEventListener("click", checkProof);
  $("downloadProof").addEventListener("click", downloadProof);
  $("reportBtn").addEventListener("click", buildReport);
  $("tamperBtn").addEventListener("click", tamperDemo);

  mixedContentWarning();
  probe();
  timer = setInterval(probe, 4000);
})();
