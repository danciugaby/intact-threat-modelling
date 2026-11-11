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

## v2.1 – tests, CI/CD, sandbox
- **Tests:** there are now 67 of them (up from 41). New coverage includes the KEV and EPSS
  clients, retry and failure paths, the Kafka worker loop, an OpenAPI route-coverage check and a
  check that the example stays in sync. Coverage is 92%, and CI fails below 85%. The new
  end-to-end tests run against the built container, and the new live-source tests run nightly.
- **CI/CD:** GitHub Actions now handles:
  - lint, tests (Python 3.11 and 3.12) and pip-audit;
  - end-to-end tests against the Docker image;
  - CodeQL security analysis;
  - publishing the image to GHCR, as multi-arch builds with SBOM and provenance, a Trivy scan and
    a cosign signature;
  - a GitHub Release on each tag;
  - a nightly live-source check and image re-scan.
- **Dependabot** now covers pip, Docker, Actions and the devcontainer.
- **Sandbox:** added a GitHub Codespaces devcontainer and `sandbox/` with a mock Risk Assessment
  service. It has a demo topology for each pilot, an offline NVD mode, a demo script and
  REST-client requests.
- **Security:** bumped `cryptography` to 50.0.1, `PyJWT` to 2.13.0 and `python-dotenv` to 1.2.3.
  pip-audit reported known vulnerabilities in the previous pins.
- **Config:** added `NVD_RATE_LIMIT`, which overrides the NVD request rate for mirrors and mocks.

## v2.2 – review fixes (November 2026)

**Results**
- NVD returns matches oldest first. When there are more than `NVD_MAX_RESULTS`, the newest window plus
  every CISA KEV entry is now ranked (previously only the oldest CVEs were), and the output warns about it.
  Paging no longer stops early on rejected records.
- The CVSS exploitability proxy no longer drops when a CNA adds a CVSS v4 score (v4 has no exploitability
  sub-score): a v3.x sub-score is used when present, else one is derived from the vector. v2 sub-scores
  are rescaled from 0–10.
- Topology analysis:
  - Assets with no vulnerability data now become flagged `unassessed` targets instead of silently
    breaking paths. In the demo topologies the MRI console, fuel-cell ECU and radiation sensors are now
    reported as reachable.
  - Transit assets (switches, VLANs …) relay traffic.
  - Control relationships (`MANAGES`, `HOSTS`, `DEPENDS_ON` …) propagate impact.
  - Every CVE found counts for lateral steps, not only the top `limit`.
  - The target's impact comes from `criticality` / `safety_critical` when present.
  - Only the best path per (entry, target) is kept, and choke points exclude entry and target assets.
- The topology pilot recorded in Risk Assessment is used when the request names none.

**Bugs**
- **CWE 5.0.** MITRE released CWE 5.0 on 28 Oct 2026, on XML schema 8, which uses a new namespace.
  The parser loaded 0 weaknesses from it. Every image built since then (including the Dependabot
  CI runs from 4 Nov) produced threat models without CWE names, mitigations or CAPEC/ATT&CK
  mappings, and the container e2e test failed.
  - Elements are now matched by local name, and IDs may be written as `CWE-79`.
  - `scripts/update_data.py` refuses a catalogue it cannot parse, so the image build fails
    instead of shipping an empty catalogue.
  - `/health` reports `cwe_weaknesses`.
- A Risk Assessment topology returned as a bare JSON list no longer crashes the analysis.
- `offset` is no longer capped at 1000 on `/threat-models` and `/datasets/*`.

**Security and operations**
- Dependencies: PyJWT 2.15.1, Werkzeug 3.1.9 and the rest of the Dependabot group. pip-audit is clean.
- Per-pilot access control (`PILOT_ROLE_PREFIX`) for analyses, stored models, jobs and CSV exports.
- Async jobs: at most `JOB_MAX_PENDING` per process (then 429); stale jobs are reported as failed.
- Kafka worker:
  - SASL/TLS settings.
  - Transient failures are retried before the DLQ.
  - The offset is only committed once the result was delivered (otherwise the message is re-read).
- `LLM_REDACT_ASSET_DETAILS` keeps asset names and locations out of LLM prompts.
- Publish/nightly workflows:
  - The scanner runs in a separate job with a read-only token.
  - The scanner image is pinned and its signature is verified. `aquasec/trivy:latest` was backdoored
    in March 2026.
- Compose:
  - `apache/kafka` replaces the withdrawn `bitnami/kafka` tags.
  - The API binds to localhost.
  - The NVD rate is split between the API and the worker.
- The image runs one gunicorn process with 16 threads, so the NVD rate limiter, caches and jobs
  are shared.
- Merged the `fix-codespace-sandbox` branch (the Kafka client is an optional dependency, and the
  sandbox starts reliably).

**Compatibility**
- Topology results gain the following:
  - `paths_total`, `reachable_assets`, `unassessed_assets`, `transit_assets`, `exposed_unassessed`
    and `notes`.
  - Attack paths gain `asset_ids`, `target`, `outcome` and `target_impact`.
  - Steps gain `kind`, `from_id` and `to_id`.
- `attack_paths` now holds the best path per (entry, target) instead of every prefix.
- Choke points no longer list the entry asset.
- Threat models gain `exploitability_by_vector` and `metadata.nvd_total_results`.
