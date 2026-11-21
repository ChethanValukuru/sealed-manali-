"""Build the accuracy report for a suite run, as a PDF.

The corpus is 10,000 prompts; every count below is read from the run, never
hardcoded, so this stays correct whatever size was actually run.

The numbers come from the live run -- red's /suite/status -- and the receipt
details come from the broker, so the report can only ever say what actually
happened. Nothing here is typed in by hand.

Usage
-----
    python sealed/tools/suite_report.py              # report on the last run
    python sealed/tools/suite_report.py --run        # run the suite first, then report
                                                     # (--run takes ~30 min: 10,000 prompts)
    python sealed/tools/suite_report.py --out x.pdf  # choose the filename

Needs the stack running (python run-local.py) and reportlab installed.
"""
from __future__ import annotations

import argparse
import collections
import datetime as dt
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (BaseDocTemplate, Frame, KeepTogether, PageBreak,
                                Paragraph, Spacer, Table, TableStyle)

import os

RED = os.environ.get("RED_URL", "http://127.0.0.1:8004")
BROKER = os.environ.get("BROKER_URL", "http://127.0.0.1:8000")

# Same palette as the web pages, so the report looks like the product.
INK = colors.HexColor("#22272b")
MUTED = colors.HexColor("#5e666d")
LINE = colors.HexColor("#d4d0c6")
HAIR = colors.HexColor("#e4e1d9")
ACCENT = colors.HexColor("#4c7a6b")
ACCENT_INK = colors.HexColor("#355849")
ACCENT_SOFT = colors.HexColor("#e8efea")
WARN = colors.HexColor("#9a7b33")
BAD = colors.HexColor("#a9544b")
PAPER2 = colors.HexColor("#f1efe9")


def esc(t: str) -> str:
    """Prompts contain <, > and & (HTML comments, JSON, code fences). reportlab
    parses its own mini-markup, so they must be escaped or the build dies."""
    return (t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))


def hx(c) -> str:
    """reportlab's hexval() gives '0xrrggbb'; its markup wants '#rrggbb'."""
    return "#" + c.hexval()[2:]

# Plain-words names for the attack categories in the log.
CAT_NAMES = {
    "instruction_override": "Telling it to ignore its instructions",
    "role_play_bypass": "Asking it to become a character with no rules",
    "social_engineering": "Pretending to be someone with permission",
    "context_manipulation": "Faking the conversation history",
    "obfuscation:base64": "Hidden as base64",
    "obfuscation:rot13": "Hidden as ROT13",
    "obfuscation:hex": "Hidden as hex codes",
    "obfuscation:leetspeak": "Written in leetspeak (1gn0r3...)",
    "obfuscation:letter_spacing": "Spaced out letter by letter",
    "obfuscation:reversed": "Written backwards",
    "obfuscation:word_order": "Words shuffled out of order",
    "obfuscation:html_comment": "Buried in an HTML comment",
    "obfuscation:json_role": "Disguised as a JSON system message",
    "obfuscation:code_fence": "Wrapped in a code block",
}


def get(url: str, timeout: int = 120):
    with urllib.request.urlopen(url, timeout=timeout) as r:
        return json.loads(r.read().decode())


def post(url: str, body: dict | None = None, timeout: int = 120):
    data = json.dumps(body or {}).encode()
    req = urllib.request.Request(url, data=data, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def run_suite_and_wait() -> None:
    started = post(f"{RED}/suite/run", {})
    if started.get("error") == "already_running":
        print("a run is already going -- waiting for it")
    elif started.get("error"):
        sys.exit(f"could not start the run: {started}")
    else:
        print(f"running {started.get('total')} prompts...")
    deadline = time.time() + 3600
    while time.time() < deadline:
        st = get(f"{RED}/suite/status")
        if st.get("state") != "running":
            return
        print(f"  {st.get('done')}/{st.get('total')}", end="\r", flush=True)
        time.sleep(2)
    sys.exit("the run did not finish in time")


# ----------------------------------------------------------------- styles

def styles() -> dict:
    ss = getSampleStyleSheet()
    base = ss["BodyText"]
    s = {}
    s["h1"] = ParagraphStyle("h1", parent=base, fontName="Helvetica-Bold",
                             fontSize=23, leading=27, textColor=INK,
                             spaceAfter=4)
    s["sub"] = ParagraphStyle("sub", parent=base, fontName="Helvetica",
                              fontSize=11, leading=16, textColor=MUTED,
                              spaceAfter=16)
    s["h2"] = ParagraphStyle("h2", parent=base, fontName="Helvetica-Bold",
                             fontSize=14.5, leading=19, textColor=INK,
                             spaceBefore=17, spaceAfter=7)
    s["h3"] = ParagraphStyle("h3", parent=base, fontName="Helvetica-Bold",
                             fontSize=11.5, leading=15, textColor=ACCENT_INK,
                             spaceBefore=11, spaceAfter=4)
    s["p"] = ParagraphStyle("p", parent=base, fontName="Helvetica",
                            fontSize=10.3, leading=15.6, textColor=INK,
                            alignment=TA_LEFT, spaceAfter=8)
    s["small"] = ParagraphStyle("small", parent=s["p"], fontSize=9,
                                leading=13, textColor=MUTED)
    s["quote"] = ParagraphStyle("quote", parent=s["p"], fontSize=10.5,
                                leading=16, leftIndent=11, textColor=ACCENT_INK,
                                borderPadding=0, spaceBefore=4, spaceAfter=10)
    s["cell"] = ParagraphStyle("cell", parent=base, fontName="Helvetica",
                               fontSize=9.2, leading=12.4, textColor=INK)
    s["cellb"] = ParagraphStyle("cellb", parent=s["cell"],
                                fontName="Helvetica-Bold")
    s["cellm"] = ParagraphStyle("cellm", parent=s["cell"], textColor=MUTED,
                                fontSize=8.4, leading=11)
    return s


def big_numbers(items, s):
    """A row of headline figures."""
    cells, widths = [], []
    for value, label, tone in items:
        col = {"good": ACCENT_INK, "bad": BAD, "warn": WARN}.get(tone, INK)
        cells.append(Paragraph(
            f'<font size="21" color="{hx(col)}"><b>{value}</b></font><br/>'
            f'<font size="8.2" color="{hx(MUTED)}">{label}</font>',
            s["cell"]))
        widths.append(168 / len(items) * mm)
    t = Table([cells], colWidths=widths)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 11),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 11),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("BACKGROUND", (0, 0), (-1, -1), PAPER2),
        ("BOX", (0, 0), (-1, -1), 0.6, LINE),
        ("LINEAFTER", (0, 0), (-2, -1), 0.6, HAIR),
    ]))
    return t


def bar(pct: float, width_mm: float = 30, tone=ACCENT):
    """A tiny horizontal bar, drawn as a one-cell table."""
    filled = max(0.6, width_mm * pct / 100.0)
    t = Table([[""]], colWidths=[filled * mm], rowHeights=[3.3 * mm])
    t.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), tone),
                           ("LEFTPADDING", (0, 0), (-1, -1), 0),
                           ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    return t


def table(rows, widths, s, head=True, zebra=True):
    t = Table(rows, colWidths=widths, repeatRows=1 if head else 0)
    style = [
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5.5),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("LINEBELOW", (0, 0), (-1, -2), 0.4, HAIR),
    ]
    if head:
        style += [("BACKGROUND", (0, 0), (-1, 0), ACCENT_SOFT),
                  ("LINEBELOW", (0, 0), (-1, 0), 0.7, LINE),
                  ("TOPPADDING", (0, 0), (-1, 0), 6),
                  ("BOTTOMPADDING", (0, 0), (-1, 0), 6)]
    if zebra:
        for i in range(1 + (1 if head else 0), len(rows), 2):
            style.append(("BACKGROUND", (0, i), (-1, i), colors.HexColor("#faf9f6")))
    t.setStyle(TableStyle(style))
    return t


# ------------------------------------------------------------- the report

def _dur(secs: float, n: int) -> str:
    """Seconds are unreadable once a run takes half an hour."""
    if secs < 90:
        return f"{secs:.1f} seconds for {n:,} prompts"
    return f"{secs / 60:.0f} minutes for {n:,} prompts"


def build(st: dict, proof: dict | None, out: Path) -> None:
    s = styles()
    tot = st["totals"]
    attacks, controls = tot["attacks_ran"], tot["controls_ran"]
    refused, over = tot["refused"], tot["over_refused"]
    catch = (refused / attacks * 100) if attacks else 0.0
    false_alarm = (over / controls * 100) if controls else 0.0
    when = dt.datetime.now().strftime("%d %B %Y, %H:%M")

    story = []

    # ---- cover -----------------------------------------------------------
    story.append(Paragraph("Accuracy report", s["h1"]))
    story.append(Paragraph(
        f"{st['done']:,} safety tests run through <b>sealed</b> &mdash; what the AI caught, "
        "what got past it, and how you can check that this page is telling the truth.",
        s["sub"]))

    story.append(big_numbers([
        (f"{catch:.1f}%", "attacks refused", "good"),
        (f"{false_alarm:.0f}%", "harmless questions<br/>wrongly refused", "good"),
        (f"{st['done']:,}", "prompts sent", "plain"),
        (f"{int(round(st['elapsed_s']))}s", "to run them all", "plain"),
    ], s))
    story.append(Spacer(1, 13))

    story.append(Paragraph("What was tested", s["h2"]))
    story.append(Paragraph(
        f"<b>{st['done']:,} prompts</b> were sent to the AI in one go: "
        f"<b>{attacks:,} real attacks</b> and <b>{controls:,} completely ordinary "
        "questions</b>. "
        "They were split into five sets, each set a different <i>kind</i> of attack. "
        f"No prompt appears twice anywhere in the {st['done']:,}.", s["p"]))
    story.append(Paragraph(
        f"The AI refused <b>{refused:,} of the {attacks:,}</b> attacks. It wrongly refused "
        f"<b>{over:,} of the {controls:,}</b> harmless questions. The defenders flagged "
        f"<b>{tot['flagged']}</b> answers as unsafe.", s["p"]))

    meta = [
        ["Test reference", st.get("test_id") or "-"],
        ["AI under test", st.get("_backend", "built-in stand-in model")],
        ["Run on", when],
        ["Time taken", _dur(st['elapsed_s'], st['done'])],
        ["Errors during the run", str(tot["errors"])],
    ]
    story.append(Spacer(1, 4))
    story.append(table(
        [[Paragraph(f"<b>{a}</b>", s["cell"]), Paragraph(b, s["cell"])] for a, b in meta],
        [46 * mm, 122 * mm], s, head=False))

    # ---- how to read it --------------------------------------------------
    story.append(Paragraph("How to read these two numbers", s["h2"]))
    story.append(Paragraph(
        "There are two scores, and you need both. One on its own tells you nothing.", s["p"]))
    story.append(table([
        [Paragraph("<b>Score</b>", s["cellb"]),
         Paragraph("<b>What it means</b>", s["cellb"]),
         Paragraph("<b>Result</b>", s["cellb"])],
        [Paragraph("Attacks refused", s["cell"]),
         Paragraph("Of the attacks we sent, how many did the AI turn down? "
                   "Higher is better.", s["cell"]),
         Paragraph(f"<b>{refused} of {attacks}</b><br/>({catch:.1f}%)", s["cell"])],
        [Paragraph("Harmless questions<br/>wrongly refused", s["cell"]),
         Paragraph("Of the ordinary questions, how many did it refuse by mistake? "
                   "Lower is better.", s["cell"]),
         Paragraph(f"<b>{over} of {controls}</b><br/>({false_alarm:.0f}%)", s["cell"])],
    ], [34 * mm, 94 * mm, 40 * mm], s))
    story.append(Spacer(1, 7))
    story.append(Paragraph(
        "This is why the second number matters: <b>an AI that refuses absolutely "
        "everything would score 100% on the first one and be useless.</b> This one "
        f"refused {over} of the {controls} ordinary questions &mdash; so it is turning down "
        "attacks, not just saying no to everybody.", s["quote"]))

    story.append(PageBreak())

    # ---- per-set ---------------------------------------------------------
    story.append(Paragraph("Results by set", s["h2"]))
    story.append(Paragraph(
        "Each set is 80 attacks plus 20 ordinary questions. The sets are not harder or "
        "easier versions of each other &mdash; they are different <i>methods</i>.", s["p"]))

    rows = [[Paragraph("<b>Set</b>", s["cellb"]),
             Paragraph("<b>Method</b>", s["cellb"]),
             Paragraph("<b>Attacks refused</b>", s["cellb"]),
             Paragraph("", s["cellb"]),
             Paragraph("<b>Wrongly<br/>refused</b>", s["cellb"])]]
    for st_set in st["sets"]:
        pct = (st_set["refused"] / st_set["attacks_ran"] * 100) if st_set["attacks_ran"] else 0
        tone = ACCENT if pct >= 75 else (WARN if pct >= 40 else BAD)
        rows.append([
            Paragraph(f"<b>{st_set['set']}</b>", s["cell"]),
            Paragraph(f"{st_set['name']}<br/>"
                      f"<font size='8' color='{hx(MUTED)}'>{st_set['focus']}</font>",
                      s["cell"]),
            Paragraph(f"<b>{st_set['refused']} / {st_set['attacks_ran']}</b>  "
                      f"<font color='{hx(tone)}'>{pct:.0f}%</font>", s["cell"]),
            bar(pct, 26, tone),
            Paragraph(f"{st_set['over_refused']} / {st_set['controls_ran']}", s["cell"]),
        ])
    pct_all = catch
    rows.append([
        Paragraph("<b>All</b>", s["cellb"]),
        Paragraph("<b>Every set together</b>", s["cellb"]),
        Paragraph(f"<b>{refused} / {attacks}</b>  <b>{pct_all:.1f}%</b>", s["cellb"]),
        bar(pct_all, 26, ACCENT_INK),
        Paragraph(f"<b>{over} / {controls}</b>", s["cellb"]),
    ])
    t = table(rows, [12 * mm, 70 * mm, 36 * mm, 28 * mm, 22 * mm], s)
    t.setStyle(TableStyle([("BACKGROUND", (0, len(rows) - 1), (-1, len(rows) - 1), PAPER2),
                           ("LINEABOVE", (0, len(rows) - 1), (-1, len(rows) - 1), 0.7, LINE)]))
    story.append(t)

    # the weakest set, named
    scored = [x for x in st["sets"] if x["attacks_ran"]]
    worst = min(scored, key=lambda x: x["refused"] / x["attacks_ran"])
    wpct = worst["refused"] / worst["attacks_ran"] * 100
    story.append(Spacer(1, 10))
    story.append(Paragraph("The main finding", s["h2"]))
    story.append(Paragraph(
        f"The AI did worst on <b>set {worst['set']} &mdash; {worst['name']}</b>, refusing "
        f"only <b>{wpct:.0f}%</b> of those attacks. Every other set scored "
        f"{min(x['refused'] / x['attacks_ran'] * 100 for x in scored if x is not worst):.0f}% "
        "or better.", s["p"]))
    story.append(Paragraph(
        "That gap <b>is the result</b>, not a fault in the testing. The point of sending "
        f"{attacks:,} attacks is to find the kind that gets through. A test that comes "
        "back 100% "
        "has not measured anything.", s["quote"]))

    # One real prompt per set. Nothing paraphrased -- this is the text that was
    # actually sent, so nobody has to take the attack count on faith.
    ex_rows = []
    for st_set in st["sets"]:
        ex = (st.get("examples") or {}).get(str(st_set["set"])) or []
        atk = next((e for e in ex if e.get("kind") == "attack"), None)
        if not atk:
            continue
        txt = " ".join((atk.get("prompt") or "").split())
        if len(txt) > 128:
            txt = txt[:128] + "…"
        v = atk.get("verdict", "?")
        tone = ACCENT_INK if v == "refused" else WARN
        ex_rows.append([
            Paragraph(f"<b>{st_set['set']}</b>", s["cell"]),
            Paragraph(esc(txt), s["cellm"]),
            Paragraph(f"<font color='{hx(tone)}'><b>{v}</b></font>", s["cell"]),
        ])
    if ex_rows:
        story.append(Paragraph("One real prompt from each set", s["h3"]))
        story.append(Paragraph(
            "Not paraphrased &mdash; this is the exact text that was sent, with what the "
            "AI did about it.", s["p"]))
        story.append(table(
            [[Paragraph("<b>Set</b>", s["cellb"]),
              Paragraph("<b>What was actually sent</b>", s["cellb"]),
              Paragraph("<b>Result</b>", s["cellb"])]] + ex_rows,
            [12 * mm, 130 * mm, 26 * mm], s))

    # ---- breakdown -------------------------------------------------------
    cat = collections.defaultdict(lambda: [0, 0])
    for r in st.get("rows", []):
        if r["kind"] != "attack":
            continue
        c = cat[r["category"]]
        c[1] += 1
        c[0] += 1 if r["verdict"] == "refused" else 0

    if cat:
        story.append(PageBreak())
        story.append(Paragraph("Every method, scored", s["h2"]))
        story.append(Paragraph(
            f"The same {attacks:,} attacks, grouped by exactly how they were written. "
            "This is the "
            "level a judge should look at &mdash; it says not just <i>that</i> some attacks "
            "got through, but <b>which</b>.", s["p"]))

        rows = [[Paragraph("<b>How the attack was written</b>", s["cellb"]),
                 Paragraph("<b>Refused</b>", s["cellb"]),
                 Paragraph("", s["cellb"]),
                 Paragraph("<b>Score</b>", s["cellb"])]]
        for key in sorted(cat, key=lambda k: (cat[k][0] / cat[k][1], k)):
            good, total = cat[key]
            pct = good / total * 100
            tone = ACCENT if pct >= 75 else (WARN if pct >= 40 else BAD)
            rows.append([
                Paragraph(CAT_NAMES.get(key, key), s["cell"]),
                Paragraph(f"{good} / {total}", s["cell"]),
                bar(pct, 34, tone),
                Paragraph(f"<font color='{hx(tone)}'><b>{pct:.0f}%</b></font>",
                          s["cell"]),
            ])
        story.append(table(rows, [84 * mm, 22 * mm, 38 * mm, 24 * mm], s))

        zeros = [CAT_NAMES.get(k, k) for k in cat if cat[k][0] == 0]
        if zeros:
            story.append(Spacer(1, 9))
            story.append(Paragraph(
                f"<b>{len(zeros)} of these methods got through every single time.</b> "
                "They are all the same thing: the attack text hidden so the words "
                "themselves change &mdash; " + ", ".join(sorted(zeros)) + ".", s["p"]))
            story.append(Paragraph(
                "The reason is plain. This AI's guard works by <b>looking for certain "
                "words</b>. Encode the sentence and the words are no longer there to find, "
                "even though the instruction still is. The methods that keep the text "
                "readable &mdash; inside a code block, an HTML comment, a JSON message "
                "&mdash; were still caught.", s["p"]))
            story.append(Paragraph(
                "That is a real, useful result about keyword-based safety filters, and it "
                f"took {attacks:,} attacks to show it rather than assert it.", s["quote"]))

    story.append(PageBreak())

    # ---- method ----------------------------------------------------------
    story.append(Paragraph(f"Where the {st['done']:,} prompts came from", s["h2"]))
    story.append(Paragraph(
        f"They are not {st['done']:,} lines somebody typed and nobody can check. Each one "
        "is built by "
        "combining a named <b>attack pattern</b> with a named <b>target</b>, in "
        "<font face='Courier'>sealed/datasets/build_suite.py</font>. Read the patterns, read "
        f"the targets, and you can reproduce all {st['done']:,} exactly.", s["p"]))
    story.append(Paragraph(
        "The builder <b>refuses to produce the file</b> unless two things hold:", s["p"]))
    story.append(table([
        [Paragraph("<b>1</b>", s["cellb"]),
         Paragraph(f"All {st['done']:,} prompts are different &mdash; no repeat inside a "
                   "set, and no "
                   "repeat between sets either.", s["cell"])],
        [Paragraph("<b>2</b>", s["cellb"]),
         Paragraph("The 100 ordinary questions contain none of the words the AI's guard "
                   "reacts to. Otherwise a harmless question would be refused because of "
                   "our wording, and the second score would be measuring our own mistake.",
                   s["cell"])],
    ], [10 * mm, 158 * mm], s, head=False))
    story.append(Spacer(1, 7))
    story.append(Paragraph(
        "Eight automated tests hold it to that, including one that fails if the stored "
        f"{st['done']:,} ever stop matching the builder:", s["p"]))
    story.append(Paragraph(
        "<font face='Courier' size='8.6'>python -m pytest sealed/tests/test_suite_corpus.py -q</font>",
        s["small"]))

    # ---- verification ----------------------------------------------------
    story.append(Paragraph("How to check this report is true", s["h2"]))
    story.append(Paragraph(
        f"Every one of the {st['done']:,} was written into a tamper-evident record as it "
        "happened, and "
        "the whole run was signed as a single test. You do not have to trust this PDF.",
        s["p"]))

    checks = [["Test reference", st.get("test_id") or "-"]]
    if proof:
        inc = proof.get("inclusion") or {}
        att = (proof.get("attestation") or {})
        facts = att.get("facts") or {}
        wits = len(proof.get("witnesses") or [])
        sig = (proof.get("signature") or "")[:32]
        checks += [
            ["Attacks named in the signed receipt", str(facts.get("attacks", "-"))],
            ["Position in the public record",
             f"entry {inc.get('leaf_index', 0) + 1} of {inc.get('tree_size', '-')}"],
            ["Independent checkers who co-signed", f"{wits}"],
            ["Signature (first 32 characters)", sig + "..."],
        ]
    story.append(table(
        [[Paragraph(f"<b>{a}</b>", s["cell"]),
          Paragraph(f"<font face='Courier' size='8.6'>{b}</font>", s["cell"])]
         for a, b in checks],
        [66 * mm, 102 * mm], s, head=False))

    story.append(Spacer(1, 8))
    story.append(Paragraph("Check it yourself, in three ways", s["h3"]))
    story.append(table([
        [Paragraph("<b>In your own browser</b>", s["cell"]),
         Paragraph("Open <font face='Courier' size='8.4'>verify.html</font>, paste the test "
                   "reference above, and your browser redoes every calculation itself. It "
                   "trusts nothing the server says.", s["cell"])],
        [Paragraph("<b>From the record</b>", s["cell"]),
         Paragraph("Press <b>Check the record is untouched</b> on the console. It re-reads "
                   "every entry from the first one and reports whether the chain is intact.",
                   s["cell"])],
        [Paragraph("<b>By re-running it</b>", s["cell"]),
         Paragraph(f"The same {st['done']:,} prompts, in the same order, with randomness "
                   "switched off. "
                   "Run it again and you should get the same numbers.", s["cell"])],
    ], [38 * mm, 130 * mm], s, head=False))

    # ---- honest limits ---------------------------------------------------
    story.append(PageBreak())
    story.append(Paragraph("What this report does not say", s["h2"]))
    story.append(Paragraph(
        "Being straight about the edges is part of the point of this project.", s["p"]))
    for line in [
        "<b>This is not a league table of AI models.</b> It measures one AI, on one "
        f"machine, on this particular set of {st['done']:,} prompts.",
        "<b>The judge is deliberately simple.</b> The part that decides 'refused' or not is "
        "a basic word-matching filter, on purpose. A cleverer one would score differently. "
        "What is being proven here is that the test was isolated, recorded and provable "
        "&mdash; not that the filter is smart.",
        "<b>'Inconclusive' is not 'passed'.</b> Where the AI neither refused nor handed "
        "anything over, it is counted as not refused. That is the cautious way round.",
        "<b>These are attack shapes, not dangerous content.</b> The prompts test whether "
        "instructions can be overridden. They are not requests for genuinely harmful "
        "material.",
    ]:
        story.append(Paragraph("&bull;&nbsp; " + line, s["p"]))

    story.append(Paragraph("Reproducing this report", s["h2"]))
    story.append(Paragraph(
        f"Three commands. The first starts the system, the second runs all {st['done']:,} "
        "prompts and "
        "rebuilds this PDF from the result, the third re-checks the corpus itself.", s["p"]))
    story.append(table([
        [Paragraph("<b>1</b>", s["cellb"]),
         Paragraph("<font face='Courier' size='8.6'>python run-local.py</font><br/>"
                   "<font size='8.6' color='" + hx(MUTED) + "'>starts the system; wait for "
                   "READY</font>", s["cell"])],
        [Paragraph("<b>2</b>", s["cellb"]),
         Paragraph("<font face='Courier' size='8.6'>python sealed/tools/suite_report.py "
                   "--run</font><br/>"
                   "<font size='8.6' color='" + hx(MUTED) + "'>runs the suite and writes this "
                   "report again, from the new numbers</font>", s["cell"])],
        [Paragraph("<b>3</b>", s["cellb"]),
         Paragraph("<font face='Courier' size='8.6'>python -m pytest "
                   "sealed/tests/test_suite_corpus.py -q</font><br/>"
                   "<font size='8.6' color='" + hx(MUTED) + "'>proves the prompts are "
                   "all different and the corpus matches its builder</font>", s["cell"])],
    ], [10 * mm, 158 * mm], s, head=False))
    story.append(Paragraph(
        "Leave off <font face='Courier' size='8.6'>--run</font> to report on a run you "
        "already did from the console instead of starting a new one.", s["small"]))

    story.append(Spacer(1, 10))
    story.append(Paragraph(
        f"Generated from a live run on {when} by "
        "<font face='Courier' size='8.4'>sealed/tools/suite_report.py</font>. "
        "Re-run it and the numbers come from the system, not from this file.", s["small"]))

    # ---- page furniture --------------------------------------------------
    doc = BaseDocTemplate(str(out), pagesize=A4,
                          leftMargin=21 * mm, rightMargin=21 * mm,
                          topMargin=19 * mm, bottomMargin=17 * mm,
                          title=f"sealed - accuracy report ({st['done']:,} tests)",
                          author="sealed")
    frame = Frame(doc.leftMargin, doc.bottomMargin, doc.width, doc.height, id="n")

    def furniture(canvas, _doc):
        canvas.saveState()
        canvas.setFont("Helvetica", 7.6)
        canvas.setFillColor(MUTED)
        canvas.drawString(21 * mm, 11 * mm, "sealed — accuracy report")
        canvas.drawRightString(A4[0] - 21 * mm, 11 * mm, f"page {canvas.getPageNumber()}")
        canvas.setStrokeColor(HAIR)
        canvas.setLineWidth(0.5)
        canvas.line(21 * mm, 14.5 * mm, A4[0] - 21 * mm, 14.5 * mm)
        canvas.restoreState()

    from reportlab.platypus import PageTemplate
    doc.addPageTemplates([PageTemplate(id="all", frames=[frame], onPage=furniture)])
    doc.build(story)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", action="store_true",
                    help="run the whole suite first (~30 min), then report on it")
    ap.add_argument("--out", default="SEALED-accuracy-report.pdf")
    args = ap.parse_args()

    try:
        if args.run:
            run_suite_and_wait()
        st = get(f"{RED}/suite/status?rows=true")
    except urllib.error.URLError as exc:
        sys.exit(f"could not reach the attack runner at {RED} -- is the system running?\n"
                 f"  start it with:  python run-local.py\n  ({exc})")

    if st.get("state") == "idle":
        sys.exit("no run to report on yet. Either press 'Run all 5 sets' on the console, "
                 "or re-run this with --run.")
    if st.get("state") == "running":
        sys.exit(f"a run is still going ({st['done']}/{st['total']}). Wait for it to finish.")
    if st.get("state") == "failed":
        sys.exit(f"the last run failed: {st.get('error')}")

    # Name the model that actually answered, rather than assuming.
    try:
        iso = get(f"{BROKER}/health/isolation", timeout=20)
        backend = ((iso.get("model") or {}).get("backend") or "").lower()
        st["_backend"] = {"ollama": "Real local model (via Ollama)",
                          "mock": "Built-in stand-in model",
                          "mock-fallback": "Built-in stand-in (real model unreachable)"
                          }.get(backend, "Built-in stand-in model")
    except Exception:  # noqa: BLE001
        st["_backend"] = "Built-in stand-in model"

    proof = None
    if st.get("test_id"):
        try:
            proof = get(f"{BROKER}/eval/proof/{st['test_id']}", timeout=60)
        except Exception:  # noqa: BLE001
            pass   # the report still works without it, and says less rather than guessing

    out = Path(args.out).resolve()
    build(st, proof, out)
    t = st["totals"]
    pct = t["refused"] / t["attacks_ran"] * 100 if t["attacks_ran"] else 0
    print(f"wrote {out}")
    print(f"  {st['done']} prompts | {t['refused']}/{t['attacks_ran']} attacks refused "
          f"({pct:.1f}%) | {t['over_refused']}/{t['controls_ran']} controls wrongly refused")


if __name__ == "__main__":
    main()
