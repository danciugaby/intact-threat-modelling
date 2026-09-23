"""Deterministic lateral-movement analysis over an asset topology.

The original sent the whole graph to an LLM told to be an "Aggressive Security Analysis
Engine" and to assume every vulnerability was remotely exploitable. That produces
unreproducible results with many false positives. Here feasibility is computed from the
graph and each CVE's CVSS attack vector; the LLM (optionally) only writes a summary of
the computed paths.

Model:
  * an edge T -> A exists for each relationship; its channel class decides which attack
    vectors can cross it (network / local co-residence / physical-only / neutral);
  * a step T -> A is feasible if A has a vulnerability whose attack vector the channel
    allows (AV:P never allows lateral movement);
  * entry points are assets flagged internet-facing/exposed, or - if none are flagged -
    any asset with a network-exploitable vulnerability (flagged as an assumption);
  * paths are simple paths up to ``max_depth`` hops, scored by the product of step
    likelihoods times the impact on the final asset.
"""
from collections import Counter

# channel -> attack vectors that can be used across it
CHANNEL_VECTORS = {
    "network": {"network", "adjacent"},
    "local": {"network", "adjacent", "local"},
    "neutral": set(),
}

RELATIONSHIP_CHANNELS = {
    "CONNECTED_TO": ("network", True),
    "COMMUNICATES_WITH": ("network", True),
    "NETWORK_ACCESS": ("network", False),
    "DEPENDS_ON": ("network", False),
    "USES": ("network", False),
    "MANAGES": ("network", False),
    "CONTROLS": ("network", False),
    "SENDS_DATA_TO": ("network", False),
    "ATTACHED_TO": ("local", True),
    "INSTALLED_ON": ("local", True),
    "RUNS_ON": ("local", True),
    "HOSTS": ("local", True),
    "HOSTED_ON": ("local", True),
    "PART_OF": ("local", True),
    "CONTAINS": ("local", True),
    "NOTE": ("neutral", False),
    "DOCUMENTS": ("neutral", False),
    "OWNED_BY": ("neutral", False),
    "LOCATED_IN": ("neutral", False),
}
EXPOSURE_KEYS = {"internet_facing", "internetfacing", "exposed", "exposure", "public", "dmz"}


def channel_for(rel_type):
    """Unknown relationship types are treated as directed network links."""
    return RELATIONSHIP_CHANNELS.get(str(rel_type or "").upper(), ("network", False))


def step_likelihood(vuln):
    if vuln.get("known_exploited"):
        return 0.9
    pct = vuln.get("epss_percentile")
    if pct is not None:
        return round(0.2 + 0.6 * pct, 3)
    if vuln.get("attack_vector") is None:
        return 0.15  # no CVSS - unverified
    return round(0.2 + 0.5 * (vuln.get("score", 50) / 100.0), 3)


def _is_exposed(asset):
    for k, v in (asset.get("attributes") or {}).items():
        if k.lower().replace("-", "_") in EXPOSURE_KEYS and str(v).lower() in {"true", "yes", "1", "internet", "public"}:
            return True
    return False


def analyze(assets, max_depth=4, max_paths=25):
    """``assets``: {asset_id: {"name", "attributes": {}, "vulnerabilities": [...],
    "relationships": [{"target_id", "type"}]}} where each vulnerability has
    id, attack_vector, score, known_exploited, epss_percentile, threats (names)."""
    names = {aid: a.get("name") or str(aid) for aid, a in assets.items()}
    label = lambda aid: f"{names.get(aid, aid)} ({aid})"  # noqa: E731

    # adjacency: src -> [(dst, rel_type, channel)]
    edges = {aid: [] for aid in assets}
    for aid, a in assets.items():
        for rel in a.get("relationships", []):
            dst = rel.get("target_id")
            if dst is None or dst == aid:
                continue
            channel, bidirectional = channel_for(rel.get("type"))
            if channel == "neutral":
                continue
            edges.setdefault(aid, []).append((dst, rel.get("type"), channel))
            if bidirectional:
                edges.setdefault(dst, []).append((aid, rel.get("type"), channel))

    def best_exploit(target, channel):
        vulns = assets.get(target, {}).get("vulnerabilities", [])
        allowed = CHANNEL_VECTORS[channel]
        usable = [v for v in vulns if (v.get("attack_vector") in allowed) or v.get("attack_vector") is None]
        if not usable:
            return None
        return max(usable, key=lambda v: (step_likelihood(v), v.get("score", 0)))

    # --- single-hop feasible moves (backwards-compatible output) ---------------
    lateral_moves = []
    for src, outs in edges.items():
        for dst, rtype, channel in outs:
            if dst not in assets:
                continue
            v = best_exploit(dst, channel)
            if v:
                lateral_moves.append({
                    "asset_id": label(dst),
                    "vulnerability_id": v["id"],
                    "threat_id": label(src),
                    "relationship": rtype,
                    "channel": channel,
                    "likelihood": step_likelihood(v),
                    "verified_vector": v.get("attack_vector") is not None,
                })

    # --- entry points ------------------------------------------------------------
    flagged = [aid for aid, a in assets.items() if _is_exposed(a)]
    assumption = None
    if flagged:
        candidates = flagged
    else:
        candidates = list(assets)
        assumption = ("No asset is flagged internet-facing; every asset with a network-exploitable "
                      "vulnerability is treated as a potential entry point.")
    entry_points = []
    for aid in candidates:
        vulns = [v for v in assets[aid].get("vulnerabilities", []) if v.get("attack_vector") == "network"]
        if flagged and not vulns:
            # exposed but no remote vuln: still an entry if credentials/phishing - not modelled
            continue
        if vulns:
            v = max(vulns, key=lambda x: (step_likelihood(x), x.get("score", 0)))
            entry_points.append({"asset": label(aid), "asset_id": aid, "vulnerability_id": v["id"],
                                 "likelihood": step_likelihood(v)})

    # --- multi-hop paths ------------------------------------------------------------
    paths = []
    budget = [20000]  # cap on explored edges so dense graphs stay bounded

    def dfs(entry, node, visited, prob, steps):
        if len(steps) >= max_depth or budget[0] <= 0:
            return
        budget[0] -= 1
        for dst, rtype, channel in edges.get(node, []):
            if dst in visited or dst not in assets:
                continue
            v = best_exploit(dst, channel)
            if not v:
                continue
            p = prob * step_likelihood(v)
            step = {"from": label(node), "to": label(dst), "relationship": rtype, "channel": channel,
                    "vulnerability_id": v["id"], "likelihood": step_likelihood(v)}
            new_steps = steps + [step]
            target_score = max((x.get("score", 0) for x in assets[dst].get("vulnerabilities", [])), default=0)
            paths.append({
                "assets": [entry["asset"]] + [s["to"] for s in new_steps],
                "entry_vulnerability": entry["vulnerability_id"],
                "steps": new_steps,
                "likelihood": round(p, 4),
                "path_score": round(p * target_score, 2),
            })
            dfs(entry, dst, visited | {dst}, p, new_steps)

    for entry in entry_points:
        dfs(entry, entry["asset_id"], {entry["asset_id"]}, entry["likelihood"], [])

    paths.sort(key=lambda p: (-p["path_score"], len(p["steps"])))
    paths = paths[:max_paths]

    through = Counter()
    for p in paths:
        for a in p["assets"][:-1]:
            through[a] += 1
    choke_points = [{"asset": a, "paths_through": n} for a, n in through.most_common(10)]

    return {
        "entry_points": entry_points,
        "entry_point_assumption": assumption,
        "lateral_moves": lateral_moves,
        "attack_paths": paths,
        "choke_points": choke_points,
    }
