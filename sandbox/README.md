# Sandbox

A self-contained environment for trying the threat-modelling service: the API plus a mock INTACT
Risk Assessment service with one demo topology per pilot (`health`, `telecom`, `transport`,
`nuclear`, `smart_city`). The asset names, links and CPEs in `topologies.json` are illustrative,
not real pilot inventories.

## In GitHub Codespaces

1. Open the repo on GitHub → **Code → Codespaces → Create codespace on main**, or use the badge
   in the main README.
2. Optional: add `GROQ_API_KEY` and `NVD_API_KEY` as
   [Codespaces secrets](https://github.com/settings/codespaces) for this repository. Without them
   the sandbox still works: scenarios are deterministic, and NVD is queried at the public (slower)
   rate.
3. The sandbox starts automatically. Open the forwarded port **5000** and add `/api/docs` for the
   interactive API, or run:

```bash
bash sandbox/demo.sh health      # or telecom | transport | nuclear | smart_city
```

`requests.http` has ready-made requests for the VS Code REST Client extension.

## Locally

```bash
pip install -r requirements-dev.txt
bash sandbox/start.sh             # live NVD/KEV/EPSS; Groq if GROQ_API_KEY is set
OFFLINE=1 bash sandbox/start.sh   # no internet: recorded NVD data, no KEV/EPSS/LLM
bash sandbox/demo.sh nuclear
bash sandbox/start.sh stop
```

Logs are in `sandbox/.run/`. To change the demo topologies, edit `topologies.json` and restart.
