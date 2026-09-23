# Changes from the ENTRUST prototype (v1 → v2)

## Blocking bugs fixed
| v1 problem | v2 |
|---|---|
| `requirements.txt` unresolvable (`langchain 0.1.16` vs `langchain-core 0.3.46`); `confluent-kafka` missing | New minimal pinned set, verified to install into a clean venv; LangChain and nvdlib dropped |
| Early `return` skipped DB write → `/threat-models` and `/datasets/*` always empty | Every model persisted (normalised tables + full JSON document) |
| `cpeName` sent by API docs/Kafka but engine only read `cpe` → silent keyword fallback | `cpe`, `cpeName`, `cpe23name` all accepted and validated |
| `GET /threat-models` → TypeError (bad signature) | Paginated, filterable by pilot |
| `/analysis/asset/<id>` → KeyError (`..._ASSETS_URL`) | Config accepts both spellings; RA client with URL templates |
| Kafka consumer crashed at start-up; results only logged | Worker publishes to results topic + DLQ, manual commits, graceful shutdown |
| `while len(cve_list)==0` infinite NVD retry loop | Bounded retries with backoff, rate limiter, clean 502 |
| Ollama path broken (`response.content` on str) | Groq-only as agreed; `LLM_PROVIDER=none` deterministic mode |
| `THREAT_MODEL_LIMIT` ignored | Honoured, overridable per request (`limit`) |
| App exited at start-up if Risk Assessment was down | Only RA-backed endpoints depend on it |

## Security fixes
- Auth was never enforced (decorator read a non-existent `'Keycloak'` key) → JWT bearer validation against Keycloak JWKS (issuer, expiry, audience/azp, optional role). `/health` stays open.
- Flask dev server with `--debug` on `0.0.0.0` (Werkzeug debugger) → gunicorn, non-root container, no debug.
- CORS `*` with credentials → explicit `CORS_ORIGINS`, off by default, no credentials.
- Upstream error bodies echoed to clients → logged server-side only.
- Prompt injection via device/topology names → untrusted fields sanitised, truncated and passed as JSON data; model output validated and grounded (CWE/ATT&CK ids not offered are dropped).
- CSV exports neutralise spreadsheet formula injection.
- Outdated pins with known CVEs (Werkzeug 3.0.2, Jinja2 3.1.3, requests 2.31.0, python-jose) replaced.

## Method / quality improvements
- **CVE selection:** risk-ranked (CVSS, KEV, EPSS, pilot C/I/A weighting, attack vector) instead of "3 most recently published"; rationale in output.
- **Exploitation data:** CISA KEV (from NVD fields + live feed) and FIRST EPSS.
- **CVEs without CWE mapping** kept (previously dropped).
- **Mitigations:** per-CWE and complete (v1 attached every CWE's mitigations to every threat and dropped all multi-paragraph ones — e.g. 6 of 7 for CWE-787).
- **CAPEC names + ATT&CK techniques** (with the CAPEC catalogue from `scripts/update_data.py`).
- **Scenarios:** structured JSON (actor, entry point, preconditions, steps, C/I/A/safety impact, likelihood, detection, mitigations), one LLM call per CVE instead of per CWE, parallelised; hard-coded "healthcare industry" replaced by pilot profiles.
- **Topology:** deterministic, reproducible attack-path search from CVSS attack vectors and typed relationships, multi-hop paths, entry points, choke points; LLM only summarises. v1 asked an "Aggressive" LLM to assume everything was remotely exploitable.
- **Async jobs** (`?async=true`) for long topology runs.
- **Efficiency** (INTACT KPI): NVD/EPSS/KEV caching, in-memory CWE/CAPEC indexes, fewer LLM calls.
- 40 unit/API tests with recorded fixtures; no network needed.

## Removed
- `nvdcve-1.1-2023.json` (125 MB, unused; NVD 1.1 feeds are retired), `Pipfile*`, `run.sh`, flasgger (replaced by static OpenAPI 3 spec + Swagger UI), flask-oidc/python-keycloak/python-jose, LangChain, nvdlib.

## Compatibility notes for consumers
- All v1 response fields are still present. `threats[].description` is now a text rendering of the structured scenarios.
- `topology_analysis` items gain `relationship`, `channel`, `likelihood`, `verified_vector`; extra keys `attack_paths`, `entry_points`, `choke_points`, `summary` sit in the same final result object.
- Order of `vulnerabilities` is now by risk score, not publish date.
- Errors: 400 invalid input, 401/403 auth, 404 not found, 502 NVD unavailable, 503 RA not configured.
