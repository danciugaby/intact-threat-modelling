"""Transparent, sector-aware CVE prioritisation.

The original tool kept the three *most recently published* CVEs. Here every candidate
CVE gets a 0-100 priority score built from four signals, each reported in the output so
risk assessors can see (and challenge) why something ranked high:

    severity   CVSS base score / 10                                   weight 0.35
    exploit    1.0 if in CISA KEV, else EPSS percentile, else a CVSS   weight 0.30
               exploitability proxy (capped at 0.5 - unknown != likely)
    impact     C/I/A impact of the CVE weighted by the pilot profile   weight 0.20
    exposure   CVSS attack vector (Network > Adjacent > Local > Physical) weight 0.15
"""

WEIGHTS = {"severity": 0.35, "exploit": 0.30, "impact": 0.20, "exposure": 0.15}
AV_EXPOSURE = {"N": 1.0, "A": 0.8, "L": 0.55, "P": 0.3}
AV_NAMES = {"N": "network", "A": "adjacent", "L": "local", "P": "physical"}
IMPACT_LEVEL = {"H": 1.0, "C": 1.0, "L": 0.4, "P": 0.4, "N": 0.0}


def cvss_profile(metric):
    """Return attack vector and C/I/A impacts (0..1) from a CvssMetric, any version."""
    if metric is None:
        return {"av": None, "C": None, "I": None, "A": None}
    p = metric.parts()
    if metric.version.startswith("4"):
        # v4: impacts on the vulnerable system, raised by subsequent-system impacts
        c = max(IMPACT_LEVEL.get(p.get("VC"), 0), IMPACT_LEVEL.get(p.get("SC"), 0))
        i = max(IMPACT_LEVEL.get(p.get("VI"), 0), IMPACT_LEVEL.get(p.get("SI"), 0))
        a = max(IMPACT_LEVEL.get(p.get("VA"), 0), IMPACT_LEVEL.get(p.get("SA"), 0))
    else:
        c, i, a = (IMPACT_LEVEL.get(p.get(k), 0) for k in ("C", "I", "A"))
    return {"av": p.get("AV"), "C": c, "I": i, "A": a}


def score_cve(cve, pilot):
    metric = cve.primary_cvss
    prof = cvss_profile(metric)
    rationale = []

    if metric:
        severity = metric.base_score / 10.0
        rationale.append(f"CVSS {metric.version} base {metric.base_score} ({metric.severity or 'n/a'})")
    else:
        severity = 0.5
        rationale.append("No CVSS score published yet; severity assumed medium")

    if cve.kev:
        exploit = 1.0
        rationale.append(f"Known exploited (CISA KEV, added {cve.kev.get('date_added')})")
    elif cve.epss_percentile is not None:
        exploit = cve.epss_percentile
        rationale.append(f"EPSS {cve.epss:.3f} (percentile {cve.epss_percentile:.2f})")
    else:
        expl = (metric.exploitability if metric and metric.exploitability else None)
        exploit = min(0.5, (expl / 3.9) * 0.5) if expl else 0.25
        rationale.append("No exploitation data (KEV/EPSS); using CVSS exploitability proxy")

    w = pilot.cia_weights
    if prof["C"] is not None:
        impact = w["C"] * prof["C"] + w["I"] * prof["I"] + w["A"] * prof["A"]
        dominant = max(("C", "I", "A"), key=lambda k: w[k] * prof[k])
        names = {"C": "confidentiality", "I": "integrity", "A": "availability"}
        if impact > 0:
            rationale.append(f"{names[dominant].capitalize()} impact weighted for {pilot.name}")
    else:
        impact = 0.5

    exposure = AV_EXPOSURE.get(prof["av"], 0.6)
    if prof["av"]:
        rationale.append(f"Attack vector: {AV_NAMES.get(prof['av'], prof['av'])}")

    score = 100 * (WEIGHTS["severity"] * severity + WEIGHTS["exploit"] * exploit
                   + WEIGHTS["impact"] * impact + WEIGHTS["exposure"] * exposure)
    safety_flag = bool(pilot.safety_critical and prof["I"] is not None
                       and max(prof["I"], prof["A"]) >= 1.0)
    if safety_flag:
        rationale.append("High integrity/availability impact in a safety-critical pilot")

    if cve.kev or score >= 75:
        priority = "P1"
    elif score >= 55:
        priority = "P2"
    elif score >= 35:
        priority = "P3"
    else:
        priority = "P4"

    return {
        "score": round(score, 1),
        "priority": priority,
        "components": {
            "severity": round(severity, 3),
            "exploit": round(exploit, 3),
            "impact": round(impact, 3),
            "exposure": round(exposure, 3),
        },
        "cvss": ({"version": metric.version, "vector": metric.vector, "base_score": metric.base_score,
                  "severity": metric.severity, "source": metric.source} if metric else None),
        "attack_vector": AV_NAMES.get(prof["av"]) if prof["av"] else None,
        "cia_impact": {k: prof[k] for k in ("C", "I", "A")},
        "known_exploited": bool(cve.kev),
        "kev": cve.kev,
        "epss": cve.epss,
        "epss_percentile": cve.epss_percentile,
        "safety_relevant": safety_flag,
        "rationale": rationale,
    }
