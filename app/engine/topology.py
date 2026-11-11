"""Deterministic lateral-movement analysis over an asset topology.

The original sent the whole graph to an LLM told to be an "Aggressive Security Analysis
Engine" and to assume every vulnerability was remotely exploitable. Here feasibility is
computed from the graph and each CVE's CVSS attack vector; the LLM (optionally) only writes
a summary of the computed paths.

Model
-----
Every relationship ``A -[type]-> B`` gives a *channel* (network / local co-residence /
neutral) that decides which CVSS attack vectors can cross it, and a *direction of control*
(does compromising A affect B, or the other way round?). From an asset the attacker holds,
a step to a neighbour is one of:

``exploit``     the neighbour has a CVE whose attack vector the channel allows. The attacker
                now holds the neighbour and keeps moving. Likelihood from KEV / EPSS / CVSS.
``transit``     the neighbour is network plumbing (``transit=true`` or an asset type such as
                switch / hub / vlan). The attacker reaches what is behind it without having to
                compromise it. Likelihood 1.
``impact``      the neighbour has no usable CVE, but the relationship gives the compromised
                asset control over it (HOSTS, MANAGES, CONTROLS, SENDS_DATA_TO, or the reverse
                of RUNS_ON / DEPENDS_ON ...). The neighbour is affected; the path ends there.
``unassessed``  the neighbour is reachable but has no vulnerability data (no CPE, or its
                analysis failed). Its exploitability is unknown, so the path ends there and is
                flagged; likelihood ``UNASSESSED_LIKELIHOOD``.

An asset that *was* analysed and has no CVE usable over that channel stops the path: that is
evidence, not a gap. AV:P never allows lateral movement.

Entry points are assets flagged internet-facing/exposed with a network-exploitable CVE, or -
if none is flagged - every asset with one (reported as an assumption). Paths are simple paths
of up to ``max_depth`` hops; for each (entry, target) only the best path is kept. A path's
score is ``100 x product of step likelihoods x impact of the target``, where the target's
impact comes from its ``criticality`` / ``safety_critical`` attributes when the Risk Assessment
inventory provides them, else from its highest CVE risk score. Choke points are the assets
*inside* the kept paths (not their entry or target), ranked by the total score crossing them.
"""
from collections import defaultdict

# channel -> attack vectors that can be used across it
CHANNEL_VECTORS = {
    "network": {"network", "adjacent"},
    "local": {"network", "adjacent", "local"},
    "neutral": set(),
}

# type -> (channel, bidirectional for lateral movement)
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
RELATIONSHIP_TYPES = tuple(RELATIONSHIP_CHANNELS)

# A -[type]-> B: compromising A affects B ...
SOURCE_CONTROLS_TARGET = {"HOSTS", "CONTAINS", "MANAGES", "CONTROLS", "SENDS_DATA_TO"}
# ... or compromising B affects A
TARGET_CONTROLS_SOURCE = {"RUNS_ON", "INSTALLED_ON", "HOSTED_ON", "PART_OF", "DEPENDS_ON", "USES"}

EXPOSURE_KEYS = {"internet_facing", "internetfacing", "exposed", "exposure", "public", "dmz"}
TRUE_VALUES = {"true", "yes", "1", "internet", "public", "y", "on"}
TYPE_KEYS = ("asset_type", "type", "category", "kind", "role", "device_type")
TRANSIT_TYPES = {"switch", "hub", "bridge", "network", "network_segment", "segment", "vlan", "lan",
                 "subnet", "wlan", "access_point", "fieldbus", "bus"}
CRITICALITY = {"low": 0.25, "medium": 0.5, "moderate": 0.5, "high": 0.75, "critical": 1.0, "very_high": 1.0}

IMPACT_LIKELIHOOD = 1.0
UNASSESSED_LIKELIHOOD = 0.3
DEFAULT_IMPACT = 0.5


def channel_for(rel_type):
    """Unknown relationship types are treated as directed network links."""
    return RELATIONSHIP_CHANNELS.get(_norm(rel_type), ("network", False))


def _norm(rel_type):
    return str(rel_type or "").strip().upper().replace("-", "_").replace(" ", "_")


def step_likelihood(vuln):
    if vuln.get("known_exploited"):
        return 0.9
    pct = vuln.get("epss_percentile")
    if pct is not None:
        return round(0.2 + 0.6 * pct, 3)
    if vuln.get("attack_vector") is None:
        return 0.15  # no CVSS - unverified
    return round(0.2 + 0.5 * (vuln.get("score", 50) / 100.0), 3)


def _attrs(asset):
    return {str(k).lower().replace("-", "_"): v for k, v in (asset.get("attributes") or {}).items()}


def _truthy(v):
    return str(v).strip().lower() in TRUE_VALUES


def _is_exposed(asset):
    return any(k in EXPOSURE_KEYS and _truthy(v) for k, v in _attrs(asset).items())


def _is_transit(asset):
    a = _attrs(asset)
    if "transit" in a:
        return _truthy(a["transit"])
    return any(str(a.get(k, "")).strip().lower().replace(" ", "_") in TRANSIT_TYPES for k in TYPE_KEYS)


def target_impact(asset):
    """0..1 impact of reaching ``asset``: inventory criticality first, then its CVE scores."""
    a = _attrs(asset)
    values = []
    crit = a.get("criticality", a.get("business_criticality"))
    if crit is not None:
        s = str(crit).strip().lower().replace(" ", "_")
        if s in CRITICALITY:
            values.append(CRITICALITY[s])
        else:
            try:
                n = float(s)
                values.append(n / 5.0 if n > 1 else n)  # 1-5 scale or 0-1
            except ValueError:
                pass
    if _truthy(a.get("safety_critical", "")):
        values.append(1.0)
    if values:
        return max(0.0, min(1.0, max(values)))
    scores = [v.get("score", 0) for v in _vulns(asset)]
    return max(scores) / 100.0 if scores else DEFAULT_IMPACT


def _vulns(asset):
    seen, out = set(), []
    for v in list(asset.get("vulnerabilities") or []) + list((asset.get("exploit_summary") or {}).values()):
        if v and v.get("id") not in seen:
            seen.add(v.get("id"))
            out.append(v)
    return out


def _edges(assets):
    """src -> [edge]; an edge is {dst, type, channel, lateral, impact}."""
    edges = defaultdict(list)
    for aid, a in assets.items():
        for rel in a.get("relationships") or []:
            dst = rel.get("target_id")
            if dst is None or dst == aid:
                continue
            rtype = _norm(rel.get("type")) or "CONNECTED_TO"
            channel, bidirectional = channel_for(rtype)
            lateral = channel != "neutral"
            if lateral:
                edges[aid].append({"dst": dst, "type": rtype, "channel": channel, "lateral": True,
                                   "impact": rtype in SOURCE_CONTROLS_TARGET})
                if bidirectional:
                    edges[dst].append({"dst": aid, "type": rtype, "channel": channel, "lateral": True,
                                       "impact": rtype in TARGET_CONTROLS_SOURCE})
            if rtype in TARGET_CONTROLS_SOURCE and not (lateral and bidirectional):
                # B compromised => A affected, even though B cannot move laterally to A this way
                edges[dst].append({"dst": aid, "type": rtype, "channel": "impact", "lateral": False,
                                   "impact": True})
    return edges


def analyze(assets, max_depth=4, max_paths=25, unassessed_likelihood=UNASSESSED_LIKELIHOOD):
    """``assets``: {asset_id: {"name", "attributes": {}, "relationships": [{"target_id", "type"}],
    "vulnerabilities": [...], "exploit_summary": {vector: vuln}, "assessed": bool}}.
    Each vulnerability has id, attack_vector, score, known_exploited, epss_percentile.
    ``assessed`` is False when the asset has no vulnerability data (no CPE / analysis failed)."""
    names = {aid: a.get("name") or str(aid) for aid, a in assets.items()}

    def label(aid):
        return f"{names.get(aid, aid)} ({aid})"

    edges = _edges(assets)
    transit = {aid for aid, a in assets.items() if _is_transit(a)}
    unassessed = {aid for aid, a in assets.items() if a.get("assessed") is False}

    def best_exploit(target, channel):
        allowed = CHANNEL_VECTORS.get(channel, set())
        usable = [v for v in _vulns(assets.get(target, {}))
                  if v.get("attack_vector") in allowed or v.get("attack_vector") is None]
        if not usable:
            return None
        return max(usable, key=lambda v: (step_likelihood(v), v.get("score", 0)))

    def step(src, edge, holding):
        """The step from ``src`` across ``edge``; ``holding`` is False when the attacker is only
        passing through ``src`` (transit) and does not control it."""
        dst = edge["dst"]
        if dst not in assets:
            return None
        base = {"from": label(src), "to": label(dst), "from_id": src, "to_id": dst,
                "relationship": edge["type"], "channel": edge["channel"]}
        if edge["lateral"]:
            if dst in transit and edge["channel"] == "network":
                return {**base, "kind": "transit", "vulnerability_id": None, "likelihood": 1.0}
            v = best_exploit(dst, edge["channel"])
            if v:
                return {**base, "kind": "exploit", "vulnerability_id": v["id"],
                        "likelihood": step_likelihood(v), "verified_vector": v.get("attack_vector") is not None}
        if holding and edge["impact"]:
            return {**base, "kind": "impact", "vulnerability_id": None, "likelihood": IMPACT_LIKELIHOOD}
        if edge["lateral"] and dst in unassessed:
            return {**base, "kind": "unassessed", "vulnerability_id": None, "likelihood": unassessed_likelihood}
        return None

    # --- single-hop exploitable moves (legacy output) -----------------------------
    lateral_moves = []
    for src in assets:
        for edge in edges.get(src, []):
            s = step(src, edge, holding=True)
            if s and s["kind"] == "exploit":
                lateral_moves.append({"asset_id": s["to"], "vulnerability_id": s["vulnerability_id"],
                                      "threat_id": s["from"], "relationship": s["relationship"],
                                      "channel": s["channel"], "likelihood": s["likelihood"],
                                      "verified_vector": s["verified_vector"]})

    # --- entry points ----------------------------------------------------------------
    flagged = [aid for aid, a in assets.items() if _is_exposed(a) and aid not in transit]
    assumption = None
    if not flagged:
        assumption = ("No asset is flagged internet-facing; every asset with a network-exploitable "
                      "vulnerability is treated as a potential entry point.")
    entry_points, exposed_unassessed = [], []
    for aid in (flagged or [a for a in assets if a not in transit]):
        vulns = [v for v in _vulns(assets[aid]) if v.get("attack_vector") == "network"]
        if vulns:
            v = max(vulns, key=lambda x: (step_likelihood(x), x.get("score", 0)))
            entry_points.append({"asset": label(aid), "asset_id": aid, "vulnerability_id": v["id"],
                                 "likelihood": step_likelihood(v)})
        elif flagged and aid in unassessed:
            exposed_unassessed.append(label(aid))

    # --- multi-hop paths: best path per (entry, target) ---------------------------------
    best = {}
    budget = [50000]  # explored steps; keeps dense graphs bounded

    def record(entry, steps, prob):
        last = steps[-1]
        target = last["to_id"]
        impact = target_impact(assets[target])
        path = {
            "assets": [entry["asset"]] + [s["to"] for s in steps],
            "asset_ids": [entry["asset_id"]] + [s["to_id"] for s in steps],
            "entry_vulnerability": entry["vulnerability_id"],
            "target": label(target),
            "target_id": target,
            "outcome": {"exploit": "compromised", "impact": "affected via " + last["relationship"],
                        "unassessed": "reachable - exploitability not assessed"}[last["kind"]],
            "steps": steps,
            "likelihood": round(prob, 4),
            "target_impact": round(impact, 3),
            "path_score": round(100 * prob * impact, 2),
        }
        key = (entry["asset_id"], target)
        cur = best.get(key)
        if cur is None or (path["path_score"], -len(steps)) > (cur["path_score"], -len(cur["steps"])):
            best[key] = path

    def dfs(entry, node, holding, visited, prob, steps):
        if len(steps) >= max_depth or budget[0] <= 0:
            return
        for edge in edges.get(node, []):
            if edge["dst"] in visited:
                continue
            budget[0] -= 1
            s = step(node, edge, holding)
            if not s:
                continue
            p = prob * s["likelihood"]
            new_steps = steps + [s]
            if s["kind"] == "transit":
                dfs(entry, s["to_id"], False, visited | {s["to_id"]}, p, new_steps)
                continue
            record(entry, new_steps, p)
            if s["kind"] == "exploit":
                dfs(entry, s["to_id"], True, visited | {s["to_id"]}, p, new_steps)

    for entry in entry_points:
        dfs(entry, entry["asset_id"], True, {entry["asset_id"]}, entry["likelihood"], [])

    paths = sorted(best.values(), key=lambda p: (-p["path_score"], len(p["steps"])))

    # --- reachable assets: best outcome per target over all entries -----------------------
    reach = {}
    for p in paths:
        t = p["target_id"]
        if t not in reach or p["path_score"] > reach[t]["best_path_score"]:
            reach[t] = {"asset": p["target"], "asset_id": t, "outcome": p["outcome"],
                        "best_path_score": p["path_score"], "hops": len(p["steps"]),
                        "safety_critical": _truthy(_attrs(assets[t]).get("safety_critical", ""))}
    reachable = sorted(reach.values(), key=lambda r: -r["best_path_score"])

    # --- choke points: assets inside paths (not entry, not target) -----------------------------
    through, score = defaultdict(int), defaultdict(float)
    for p in paths:
        for aid in p["asset_ids"][1:-1]:
            through[aid] += 1
            score[aid] += p["path_score"]
    choke_points = [{"asset": label(a), "asset_id": a, "paths_through": through[a],
                     "score_through": round(score[a], 2), "transit": a in transit}
                    for a in sorted(through, key=lambda a: (-score[a], -through[a]))[:10]]

    return {
        "entry_points": entry_points,
        "entry_point_assumption": assumption,
        "exposed_unassessed": exposed_unassessed,
        "lateral_moves": lateral_moves,
        "attack_paths": paths[:max_paths],
        "paths_total": len(paths),
        "reachable_assets": reachable,
        "choke_points": choke_points,
        "unassessed_assets": [label(a) for a in sorted(unassessed)],
        "transit_assets": [label(a) for a in sorted(transit)],
    }
