# INTACT Threat Modelling Service (v2)

[![CI](https://github.com/danciugaby/intact-threat-modelling/actions/workflows/ci.yml/badge.svg)](https://github.com/danciugaby/intact-threat-modelling/actions/workflows/ci.yml)
[![Publish image](https://github.com/danciugaby/intact-threat-modelling/actions/workflows/publish.yml/badge.svg)](https://github.com/danciugaby/intact-threat-modelling/actions/workflows/publish.yml)
[![Open in GitHub Codespaces](https://github.com/codespaces/badge.svg)](https://codespaces.new/danciugaby/intact-threat-modelling?quickstart=1)

This is the threat modelling module, adapted for the [INTACT](https://intact-horizon.eu/) Horizon Europe
project. It began as the ENTRUST threat-modelling prototype. See [CHANGES.md](CHANGES.md) for what was
fixed and what changed.

For a device (identified by CPE or by name), the service returns a risk-ranked threat model. For an
asset topology from the INTACT Risk Assessment service, it also returns the lateral-movement attack
paths.

```
device / asset / topology
   │
   ├─ 1. Threat landscape ─── NVD CVE API 2.0 (cached, rate-limited, bounded retries)
   ├─ 2. Exploitation ─────── CISA KEV + FIRST EPSS (optional, fail-soft)
   ├─ 3. Risk ranking ─────── CVSS + KEV/EPSS + pilot C/I/A weighting + attack vector → 0-100, P1-P4
   ├─ 4. Threat mapping ───── MITRE CWE → CAPEC → ATT&CK, full CWE mitigations
   ├─ 5. Scenarios ────────── Groq LLM, JSON-validated, grounded; deterministic fallback
   └─ 6. Topology ─────────── deterministic attack-path search + choke points (+ LLM summary)
```

## INTACT pilot profiles

Set `pilot` on a request, or `DEFAULT_PILOT` for the whole service. Each profile changes three things:
the scenario context, the C/I/A weighting used in the risk score, and the regulatory references
attached to the output. The profiles are defined in `app/engine/pilots.py`.

| key | Pilot | C / I / A weight | Safety-critical | References attached |
|---|---|---|---|---|
| `telecom` (PUC1) | 5G / virtualised telecom | .25 / .30 / .45 | no | 3GPP SCAS, ENISA 5G Toolbox, NIS2, CRA |
| `health` (PUC2) | Health 4.0 | .40 / .35 / .25 | yes | EU MDR, MDCG 2019-16, IEC 81001-5-1, IEC 80001-1, GDPR, NIS2 |
| `transport` (PUC3) | Fuel-cell vehicles / OTA | .15 / .50 / .35 | yes | UNECE R155/R156, ISO/SAE 21434, ISO 26262 |
| `nuclear` (PUC4) | Safety-critical nuclear monitoring | .15 / .45 / .40 | yes | IEC 62645, IEC 63096, IAEA NSS 17-T, IEC 62443, NIS2 |
| `smart_city` | Cross-vertical smart city | .30 / .35 / .35 | no | ETSI EN 303 645, IEC 62443, CRA, GDPR, NIS2 |
| `generic` | Default | ⅓ / ⅓ / ⅓ | no | CRA, NIS2, IEC 62443 |

The weights and the standards lists are a starting point. Each pilot owner should review them.

## Quick start

**Try it in the browser:** open a Codespace with the badge above. The sandbox starts by itself: the
API, plus a mock Risk Assessment service with a demo topology for each pilot. Run
`bash sandbox/demo.sh health` or open `/api/docs` on forwarded port 5000. See
[sandbox/README.md](sandbox/README.md).

**Run the published image:**

```bash
docker run -p 5000:5000 -e LLM_PROVIDER=none ghcr.io/danciugaby/intact-threat-modelling:main
```

**Full stack** (API, Kafka worker, Postgres, Kafka):

```bash
cp .env.example .env              # set GROQ_API_KEY, NVD_API_KEY, Keycloak, Risk Assessment URLs
docker compose up --build         # the build downloads the latest MITRE CWE + CAPEC catalogues
```

**Development:**

```bash
make install                      # pip install -r requirements-dev.txt
python scripts/update_data.py     # downloads CWE + CAPEC into data/
make sandbox                      # API + mock services (OFFLINE=1 / make sandbox-offline: no internet)
make lint test cov                # ruff, 67 tests, coverage gate 85%
make e2e                          # build the image and run end-to-end tests against it
```

API docs are served at `/api/docs`, and the OpenAPI spec is at `/api/openapi.yaml`.

## API

| Method | Path | Purpose |
|---|---|---|
| POST | `/analysis` | Threat model for one device. `{"device_data": {"cpe": "...", "deviceName": "..."}, "pilot": "health", "limit": 5}` |
| GET | `/analysis/asset/{asset_id}` | Fetch the asset from Risk Assessment and model it |
| GET | `/threat-models/{topology_id}` (alias `/topologies/{id}/analysis`) | Model every asset in a topology, plus attack paths |
| GET | `/threat-models`, `/threat-models/by-id/{id}` | Stored threat models (filter with `?pilot=`) |
| GET | `/jobs/{job_id}` | Status of a call made with `?async=true` (recommended for topologies) |
| GET | `/datasets/{threat-models,vulnerabilities,threats}` | CSV exports |
| GET | `/pilots`, `/health` | Pilot profiles; health and configuration (no auth) |

The legacy request and response fields still work. The legacy request fields are `cpeName`,
`deviceName`, `vulnerabilities[].threats[].attributes`, `topology_analysis` and the misspelt
`BENCHAMRK_COMPUTE_TIME`. New information is added alongside the legacy fields:

- `risk` block per CVE: score, priority, KEV, EPSS, C/I/A, attack vector, and a readable `rationale`.
- Structured `scenarios` per threat.
- `capec` with names, and ATT&CK `attack_techniques`.
- Structured CWE `mitigations`.
- A `summary` block with the regulatory references.
- A `metadata` block with sources, versions and timings.

For an example output, see `examples/response-fixture-health-no-llm.json`. It was produced from the
test fixtures with the LLM disabled.

### Kafka

The worker needs the optional Kafka client, installed with `pip install -r requirements-kafka.txt`.
The Docker image already includes it. `python kafka_worker.py` reads requests from `KAFKA_REQUEST_TOPIC`. Results are published to
`KAFKA_RESULT_TOPIC`, and failed requests go to `KAFKA_DLQ_TOPIC`. A request looks like:

```json
{"request_id": "abc", "type": "device|asset|topology", "pilot": "nuclear",
 "device_data": {"cpe": "cpe:2.3:..."}, "asset_id": "...", "topology_id": "..."}
```

To send a test request, run `python kafka_worker.py --send-example`.

## Topology analysis

Each Risk Assessment relationship type maps to a channel, which decides which CVSS attack vectors
can be used to move across that link:

| Channel | Relationship types (examples) | Usable attack vectors |
|---|---|---|
| network | `CONNECTED_TO`↔, `COMMUNICATES_WITH`↔, `DEPENDS_ON`, `MANAGES`, unknown types | Network, Adjacent |
| local (co-resident) | `HOSTS`↔, `RUNS_ON`↔, `INSTALLED_ON`↔, `ATTACHED_TO`↔ | Network, Adjacent, Local |
| neutral | `DOCUMENTS`, `NOTE`, `OWNED_BY`, `LOCATED_IN` | none |

A physical-only attack vector (AV:P) never allows lateral movement.

Entry points are assets that have the attribute `internet_facing=true` or `exposed=true`. If no
asset is flagged, every asset with a network-exploitable CVE is treated as a possible entry point,
and the output says so. The analysis then searches for paths of up to `TOPOLOGY_MAX_PATH_DEPTH`
hops, scores them as step likelihood × target impact, and reports the choke-point assets that most
paths pass through. The mapping lives in `app/engine/topology.py`. Adjust it to match the Risk
Assessment vocabulary.

## Tests and CI/CD

| Layer | What | Where / when |
|---|---|---|
| Unit, API, contract | 67 tests with recorded fixtures, no network. Includes an OpenAPI check that fails if an endpoint is undocumented. Coverage gate 85%. | `tests/`, every PR (Python 3.11 + 3.12) |
| End-to-end | Real Docker image against mock Risk Assessment/NVD (`docker-compose.e2e.yml`). Covers device analysis, persistence, CSV, and async topology analysis for all 5 pilots. | `tests/e2e/`, every PR |
| Live sources | Real NVD, CISA KEV, FIRST EPSS and Groq (if `GROQ_API_KEY` is set). Catches upstream API changes. | `tests/live/`, nightly |
| Static | ruff lint, CodeQL (security-extended), pip-audit on pinned dependencies | every PR |
| Image | Multi-arch build (amd64/arm64), SBOM and provenance attestations, Trivy scan into code scanning, keyless cosign signature | on `main` and `v*` tags; nightly re-scan |

Workflows are in `.github/workflows/`:

- `ci.yml`: lint, tests, dependency audit and end-to-end tests.
- `publish.yml`: pushes to `ghcr.io/danciugaby/intact-threat-modelling`, and creates a GitHub
  Release on `v*` tags.
- `nightly.yml`: live-source tests and image re-scan.
- `codeql.yml`: CodeQL security analysis.

Dependabot keeps pip packages, the base image, GitHub Actions and the devcontainer up to date.

To release, run `git tag v2.0.0 && git push --tags`. The workflow publishes `:2.0.0`, `:2.0` and
`:latest`, then creates the release.

## Configuration

All configuration is through environment variables. See `.env.example` and `app/config.py`. The
most important ones:

- `GROQ_API_KEY` and `LLM_MODEL_NAME`. Check Groq's current model list, because models get retired.
- `NVD_API_KEY`. Without a key, NVD allows 5 requests per 30 seconds, and the service throttles to
  that limit.
- `AUTH_ENABLED=true` with the `KEYCLOAK_*` settings. The service verifies bearer tokens against the
  realm JWKS and can require a role.
- `CORS_ORIGINS`. Set it to the dashboard origin(s). CORS is off by default.
- `NVD_RATE_LIMIT`. Requests per 30 seconds. Override it only for a local NVD mirror or mock.
- `RISK_ASSESSMENT_GET_ASSET_URL` and `RISK_ASSESSMENT_GET_TOPOLOGY_URL`. These are templates with
  `{asset_id}` / `{topology_id}` placeholders.

## Limitations

- Scenarios are LLM-generated. They are grounded in NVD, CWE and CAPEC data, but an analyst still
  has to review them before they go into a safety case.
- NVD keyword search, used when no CPE is given, is noisy. Always supply CPEs in the Risk Assessment
  asset inventory.
- The risk score is a way to rank vulnerabilities, not a formal risk assessment. The INTACT Risk
  Assessment module remains the authority.
- The database schema is created with `create_all`. Add Alembic migrations before any schema changes
  go into a shared deployment.
