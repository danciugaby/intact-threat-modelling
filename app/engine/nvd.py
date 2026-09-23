"""NVD CVE API 2.0 client.

Replaces ``nvdlib``: explicit rate limiting (with/without API key), bounded retries,
pagination, response caching and a typed record with everything the risk scorer needs
(CVSS v4/v3.1/v3.0/v2 metrics, CWE ids, CISA KEV fields, references)."""
import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import requests

from .http import RateLimiter, TTLCache, UpstreamError, get_json

log = logging.getLogger(__name__)

CPE_RE = re.compile(r"^cpe:2\.3:[aho\*\-](:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!\"#$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){5}(:(([a-zA-Z]{2,3}(-([a-zA-Z]{2}|[0-9]{3}))?)|[\*\-]))(:(((\?*|\*?)([a-zA-Z0-9\-\._]|(\\[\\\*\?!\"#$%&'\(\)\+,/:;<=>@\[\]\^`\{\|}~]))+(\?*|\*?))|[\*\-])){4}$")
CVSS_ORDER = ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2")


def is_valid_cpe(cpe):
    return bool(cpe) and bool(CPE_RE.match(cpe))


@dataclass
class CvssMetric:
    version: str
    vector: str
    base_score: float
    severity: str
    source: str = ""
    exploitability: float = None

    def parts(self):
        """Parse a vector string into {'AV': 'N', ...}."""
        out = {}
        for chunk in self.vector.split("/"):
            if ":" in chunk:
                k, v = chunk.split(":", 1)
                out[k] = v
        return out


@dataclass
class CveRecord:
    id: str
    published: datetime
    description: str
    status: str = ""
    cvss: list = field(default_factory=list)  # [CvssMetric], best first
    cwe_ids: list = field(default_factory=list)  # [int]
    cpes: list = field(default_factory=list)
    references: list = field(default_factory=list)
    kev: dict = None  # {"date_added", "due_date", "required_action", "name"} when in CISA KEV
    epss: float = None
    epss_percentile: float = None

    @property
    def primary_cvss(self):
        return self.cvss[0] if self.cvss else None

    @property
    def title(self):
        if self.kev and self.kev.get("name"):
            return self.kev["name"]
        return self.id


def _parse_dt(value):
    if not value:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)
    value = value.replace("Z", "")
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return datetime(1970, 1, 1, tzinfo=timezone.utc)


def _collect_cpes(configurations):
    seen, out = set(), []
    for conf in configurations or []:
        for node in conf.get("nodes", []):
            for m in node.get("cpeMatch", []):
                crit = m.get("criteria")
                if m.get("vulnerable", True) and crit and crit not in seen:
                    seen.add(crit)
                    out.append(crit)
    return out


def parse_cve(item):
    """Convert one ``vulnerabilities[i].cve`` object from the NVD 2.0 API."""
    cve = item.get("cve", item)
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")

    metrics = cve.get("metrics", {}) or {}
    cvss = []
    for key in CVSS_ORDER:
        entries = metrics.get(key) or []
        # prefer the NVD "Primary" score, fall back to the CNA's
        entries = sorted(entries, key=lambda e: 0 if e.get("type") == "Primary" else 1)
        for e in entries[:1]:
            data = e.get("cvssData", {})
            cvss.append(CvssMetric(
                version=str(data.get("version", key[-2:])),
                vector=data.get("vectorString", ""),
                base_score=float(data.get("baseScore", 0) or 0),
                severity=(data.get("baseSeverity") or e.get("baseSeverity") or "").upper(),
                source=e.get("source", ""),
                exploitability=e.get("exploitabilityScore"),
            ))

    cwe_ids = []
    for w in cve.get("weaknesses", []) or []:
        for d in w.get("description", []):
            m = re.match(r"CWE-(\d+)$", d.get("value", ""))
            if m and int(m.group(1)) not in cwe_ids:
                cwe_ids.append(int(m.group(1)))

    kev = None
    if cve.get("cisaExploitAdd"):
        kev = {
            "date_added": cve.get("cisaExploitAdd"),
            "due_date": cve.get("cisaActionDue"),
            "required_action": cve.get("cisaRequiredAction"),
            "name": cve.get("cisaVulnerabilityName"),
        }

    return CveRecord(
        id=cve["id"],
        published=_parse_dt(cve.get("published")),
        description=desc,
        status=cve.get("vulnStatus", ""),
        cvss=cvss,
        cwe_ids=cwe_ids,
        cpes=_collect_cpes(cve.get("configurations")),
        references=[r.get("url") for r in cve.get("references", [])[:10] if r.get("url")],
        kev=kev,
    )


class NvdClient:
    PAGE_SIZE = 2000

    def __init__(self, api_url, api_key=None, timeout=30, cache_ttl=21600, max_results=2000,
                 session=None):
        self.api_url = api_url
        self.api_key = api_key
        self.timeout = timeout
        self.max_results = max_results
        self.session = session or requests.Session()
        # NVD public limits: 5 requests / 30 s without a key, 50 / 30 s with one.
        self.limiter = RateLimiter(45 if api_key else 5, 30)
        self.cache = TTLCache(cache_ttl)

    def _headers(self):
        h = {"Accept": "application/json", "User-Agent": "INTACT-threat-modelling/2.0"}
        if self.api_key:
            h["apiKey"] = self.api_key
        return h

    def _search(self, params):
        cache_key = tuple(sorted(params.items()))
        cached = self.cache.get(cache_key)
        if cached is not None:
            return cached
        results, start = [], 0
        while True:
            page = dict(params, startIndex=start, resultsPerPage=min(self.PAGE_SIZE, self.max_results))
            data = get_json(self.session, self.api_url, params=page, headers=self._headers(),
                            timeout=self.timeout, limiter=self.limiter)
            if not data:
                break
            vulns = data.get("vulnerabilities", [])
            for v in vulns:
                try:
                    rec = parse_cve(v)
                    if rec.status.lower() != "rejected":
                        results.append(rec)
                except (KeyError, TypeError, ValueError) as exc:
                    log.warning("Skipping unparsable NVD record: %s", exc)
            total = int(data.get("totalResults", 0))
            start += len(vulns)
            if not vulns or start >= total or len(results) >= self.max_results:
                if total > self.max_results:
                    log.warning("NVD returned %d CVEs for %s; only the first %d are ranked",
                                total, params, self.max_results)
                break
        self.cache.set(cache_key, results)
        return results

    def search_by_cpe(self, cpe):
        """CVEs affecting ``cpe``. A CPE with a wildcard version is matched with
        ``virtualMatchString`` (all versions); a concrete one with ``cpeName``."""
        if not is_valid_cpe(cpe):
            raise ValueError(f"Invalid CPE 2.3 string: {cpe!r}")
        version = cpe.split(":")[5]
        if "*" in version or "?" in version:
            return self._search({"virtualMatchString": cpe})
        results = self._search({"cpeName": cpe})
        if not results:
            # cpeName only matches CPEs present in the NVD dictionary; fall back to a
            # match against the applicability statements.
            results = self._search({"virtualMatchString": cpe})
        return results

    def search_by_keyword(self, keyword):
        keyword = " ".join(str(keyword).split())[:200]
        if not keyword:
            return []
        return self._search({"keywordSearch": keyword})

    def get_cve(self, cve_id):
        res = self._search({"cveId": cve_id})
        return res[0] if res else None


def filter_by_age(cves, max_age_years):
    if not max_age_years:
        return cves
    cutoff = datetime.now(timezone.utc) - timedelta(days=365 * max_age_years)
    return [c for c in cves if c.published >= cutoff]


__all__ = ["NvdClient", "CveRecord", "CvssMetric", "parse_cve", "is_valid_cpe", "UpstreamError",
           "filter_by_age"]
