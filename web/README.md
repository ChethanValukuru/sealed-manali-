# sealed — the web front end

A zero-build static site. Everything it shows is read from a **running sealed system** —
there are no fabricated numbers anywhere, and when the backend is down it says so rather
than inventing a result.

## The pages

There are **three pages and nothing else**. The guided story page and the animated
walkthrough were removed in November 2026: they told the judges what happens instead of
letting them do it, and the console does the same job with real data.

| File | What it is |
|---|---|
| `console.html` + `app.js` | **Start here.** The live control panel, in three numbered steps. Connects by itself. Run a test or type your own attack, get a signed receipt whose every line opens to show its evidence, then try to break the record. A looping diagram in the right-hand column illustrates whichever step is in view. Ledger tools, the memory-contamination check and the addresses sit under **Advanced tools**. The live protections readout and the activity feed were removed in November 2026 to make room for the step diagram; `/health/isolation` still reports them and `renderWalls()` in `app.js` still renders them if a `#walls` element is put back. |
| `verify.html` + `verify.js` | The zero-trust proof checker. Re-computes the signatures and the Merkle inclusion **in your browser**, trusting nothing the server says. Includes a tamper theatre and a QR proof receipt. |
| `index.html` | A one-screen landing page: the idea in a sentence, and two doors — the console and the verifier. Deliberately fits in the viewport with nothing to scroll past. |
| `styles.css` | The shared design system. Black, red and white; one theme, no toggle. Animations are transform/opacity only and switch off under `prefers-reduced-motion`. |
| `diagram-solution.jpg` | The architecture diagram embedded in the top-level `README.md`. |
| `sample-proof.json` | A **real** captured proof bundle. Paste it into `verify.html` to demo the verifier with no backend running — the venue-wifi fallback. |
| `vendor/` | `noble-ed25519.js` (signature checking) and `qrcode.min.js` (proof receipts). Vendored so the verifier works offline. |
| `vercel.json` | Static hosting config with a few safe headers. |

## Running it

From the project root (one level up):

```bash
node serve-web.js
```

It prints the address — normally `http://localhost:8080`, stepping to the next free port if
that one is taken. No Python, no build step, no dependencies.

To make the pages show live data, start the backend in another window:

```bash
python run-local.py
```

Add `--real` to put a genuine local model behind it instead of the built-in stand-in.
See [`../docs/DEMO.md`](../docs/DEMO.md) for which mode to use when.

## Connecting to a backend elsewhere

The pages call the broker (`:8000`), audit (`:8001`) and red (`:8004`) services straight
from the browser, and default to `localhost`. To point them somewhere else, open
**Advanced tools** at the bottom of the console and edit the three addresses.

**Mixed-content note:** a page served over **HTTPS** cannot call an **HTTP** backend —
browsers block it. So the landing page is what belongs on a public URL; the console and
verifier shine locally, or against a backend behind TLS.

## Deploying the static pages

Vercel: import the repo and deploy it unchanged. The **root** `vercel.json` (one level up)
sets `framework: null` and `outputDirectory: "web"`, so this folder becomes the site root
with no build step and no dashboard settings to remember.

The `vercel.json` in *this* folder is the equivalent config for the older setup where
**Root Directory** is set to `web` by hand; Vercel reads whichever one sits at the
configured root. Keep the headers in the two files in step if you change them.
