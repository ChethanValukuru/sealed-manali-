# sealed — Makefile
#
# Container engine: defaults to `docker compose`. On the target Ubuntu VM with
# rootless Podman, override:  make up COMPOSE="podman compose"
# (or COMPOSE="podman-compose" depending on your Podman version).
COMPOSE ?= docker compose
NAIVE   ?= $(COMPOSE) -f compose.naive.yaml

.PHONY: help up down ps logs build demo-secure demo-naive naive-up naive-down \
        test latency verify-audit demo-tamper dashboard fetch-datasets

help:
	@echo "sealed targets:"
	@echo "  make up            - build + start the 5-service secure stack"
	@echo "  make down          - stop and remove the stack"
	@echo "  make ps            - show container status/health"
	@echo "  make logs          - tail logs"
	@echo "  make demo-naive    - BEFORE: show the leaks in the naive shared sandbox"
	@echo "  make demo-secure   - AFTER: same attacks contained + audited (needs make up)"
	@echo "  make test          - run all objective-proof tests"
	@echo "  make latency       - measure + print isolation overhead per eval (M7)"
	@echo "  make verify-audit  - verify the tamper-evident log (expect intact)"
	@echo "  make demo-tamper   - tamper a copy of the log; verifier flags the entry"
	@echo "  make dashboard     - serve the minimal console at http://localhost:8080"
	@echo "  make naive-down    - tear down the naive sandbox"
	@echo ""
	@echo "Override engine: make up COMPOSE=\"podman compose\""

# ---- Phase 0 (M0) -----------------------------------------------------------
up:
	$(COMPOSE) up -d --build
	@echo "Waiting for services to become healthy..."
	@$(COMPOSE) ps

down:
	$(COMPOSE) down -v

ps:
	$(COMPOSE) ps

logs:
	$(COMPOSE) logs -f

build:
	$(COMPOSE) build

# ---- Phase 1 + Phase 3: the AFTER (secure containment) ----------------------
# One full eval cycle, then the contamination + disclosure checks come back
# CONTAINED, then the audit log. Mirrors demo-naive step for step.
demo-secure:
	@echo "========================= SECURE (AFTER) ========================="
	@echo ">> Waiting for the secure stack to be ready..."
	@for i in $$(seq 1 60); do curl -sf http://localhost:8004/health >/dev/null 2>&1 && break; sleep 1; done
	@echo ">> 1. Full eval cycle via the red tenant:"
	@curl -s -X POST http://localhost:8004/run | python3 -m json.tool || \
		curl -s -X POST http://localhost:8004/run
	@echo ""
	@echo ">> 2. CONTAINED (contamination): plant in Test A, probe in Test B ->"
	@curl -s -X POST http://localhost:8004/run_contamination | python3 -m json.tool || \
		curl -s -X POST http://localhost:8004/run_contamination
	@echo "   ^ leaked:false and no secret in probe_response = fresh context held."
	@echo ""
	@echo ">> 3. CONTAINED (disclosure): blue has no shared store to read red from:"
	@$(COMPOSE) exec -T blue python -c "import urllib.request;print(urllib.request.urlopen('http://localhost:8003/peek_shared').read().decode())"
	@echo ""
	@echo ">> 4. Audit log (every event recorded, tamper-evident):"
	@curl -s http://localhost:8001/log | python3 -m json.tool || \
		curl -s http://localhost:8001/log

# ---- Datasets ---------------------------------------------------------------
fetch-datasets:
	python3 datasets/fetch_advbench.py
	python3 datasets/fetch_jailbreakbench.py

# ---- Phase 2 (M2 isolation + M3 tamper-evident audit) -----------------------
# Objective-proof tests exec into the running stack, so `make up` must be up.
test:
	SEALED_COMPOSE="$(COMPOSE)" python3 -m pytest tests/ -v

# -s so the latency numbers print; also writes tests/latency_report.txt
latency:
	SEALED_COMPOSE="$(COMPOSE)" python3 -m pytest tests/test_latency.py -v -s

dashboard:
	@echo ">> Minimal console at http://localhost:8080 (Ctrl-C to stop). Secure stack must be up."
	@cd dashboard && python3 -m http.server 8080

verify-audit:
	@echo ">> Verifying the tamper-evident audit log (expect intact)..."
	$(COMPOSE) exec -T audit python verify.py

demo-tamper:
	@echo ">> Tampering a COPY of the log; the verifier should flag the exact entry..."
	$(COMPOSE) exec -T audit python tamper_demo.py

# ---- Phase 3: the BEFORE (naive shared sandbox) -----------------------------
naive-up:
	$(NAIVE) up -d --build
	@$(NAIVE) ps

naive-down:
	$(NAIVE) down -v

demo-naive: naive-up
	@echo "========================= NAIVE (BEFORE) ========================="
	@echo ">> Waiting for the naive stack to be ready..."
	@for i in $$(seq 1 60); do curl -sf http://localhost:18004/health >/dev/null 2>&1 && break; sleep 1; done
	@echo ">> Running plant->probe across two tests in the shared sandbox..."
	@curl -s -X POST http://localhost:18004/run_contamination | python3 -m json.tool || \
		curl -s -X POST http://localhost:18004/run_contamination
	@echo "   ^ LEAK 1 (contamination): leaked:true, Test B recovered Test A's secret."
	@echo ""
	@echo ">> LEAK 2 (disclosure): blue reads red's RAW payload off the shared volume:"
	@curl -s http://localhost:18003/peek_shared | python3 -m json.tool || \
		curl -s http://localhost:18003/peek_shared
	@echo ""
	@echo ">> Both leak = this safety result cannot be trusted. Now run: make demo-secure"
