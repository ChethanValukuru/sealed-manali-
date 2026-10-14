# sealed — web frontend

A zero-build static site: a clean explainer plus a live **console** that connects to
*your own* running `sealed` backend. It shows real data or an honest
"not connected" state — there are **no fabricated numbers** anywhere.

- `index.html` — overview (problem, architecture, objectives, threat model)
- `console.html` + `app.js` — live console (isolation health, audit log, eval runs)
- `styles.css` — peaceful sage/stone theme, light + dark
- `vercel.json` — static hosting with a few safe headers

## Deploy on Vercel

1. Import the GitHub repo into Vercel.
2. **Root Directory:** `web`
3. **Framework Preset:** Other (no build command; output is the directory itself).
4. Deploy. That's it — it's static.

## Run locally

Any static server works (the console calls the backend from the browser):

```bash
cd web
python -m http.server 8080      # then open http://localhost:8080
```

## Connecting the console to a backend

The console calls the broker / audit / red services directly from the browser, so:

- Start the backend: from `../sealed`, run `make up` (defaults: broker `:8000`,
  audit `:8001`, red `:8004`). The backend already sends permissive CORS headers.
- In the console's **Backend** panel, point the three URLs at your backend and
  press **Connect**. The defaults are `localhost`.

**Mixed content note:** a site served over **HTTPS** (as on Vercel) cannot call an
**HTTP** backend — browsers block it. For a live console against a remote backend,
serve that backend over HTTPS (or a reverse proxy with TLS). Running the console
locally against `localhost` has no such restriction, so the explainer is the part
meant for the public Vercel URL; the console shines locally or against a TLS backend.
