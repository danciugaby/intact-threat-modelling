"""Tests against the real data sources. Run nightly (see .github/workflows/nightly.yml) to catch
upstream API changes:  pytest -m live tests/live

NVD_API_KEY is optional (slower without). GROQ_API_KEY enables the LLM test.
"""

import os

import pytest

from app.config import Config
from app.engine.exploitability import EpssClient, KevFeed
from app.engine.llm import ScenarioGenerator
from app.engine.nvd import NvdClient

pytestmark = pytest.mark.live
CVE = "CVE-2023-20198"


@pytest.fixture(scope="module")
def nvd():
    return NvdClient(Config.NVD_API_URL, os.getenv("NVD_API_KEY"), timeout=60)


def test_nvd_cve_lookup_shape(nvd):
    cve = nvd.get_cve(CVE)
    assert cve and cve.id == CVE
    assert cve.cwe_ids and cve.primary_cvss and cve.primary_cvss.base_score >= 9
    assert cve.kev  # NVD exposes CISA KEV fields


def test_nvd_cpe_search(nvd):
    cves = nvd.search_by_cpe("cpe:2.3:o:cisco:ios_xe:16.12.4:*:*:*:*:*:*:*")
    assert any(c.id == CVE for c in cves)


def test_kev_feed():
    feed = KevFeed(Config.KEV_FEED_URL)
    assert feed.lookup(CVE) and feed.available


def test_epss():
    scores = EpssClient(Config.EPSS_API_URL).scores([CVE])
    assert CVE in scores and 0 <= scores[CVE][0] <= 1


@pytest.mark.skipif(not os.getenv("GROQ_API_KEY"), reason="GROQ_API_KEY not set")
def test_groq_scenarios(nvd, tmp_path):
    from app.engine.catalogs import CweCatalog
    from app.engine.pilots import get_pilot
    from app.engine.risk import score_cve

    cve = nvd.get_cve(CVE)
    pilot = get_pilot("health")
    gen = ScenarioGenerator(provider="groq", model=Config.LLM_MODEL_NAME, api_key=os.environ["GROQ_API_KEY"])
    cwe = CweCatalog(Config.CWEC_FILE_PATH)
    out = gen.scenarios({"deviceName": "Edge router"}, pilot, cve, score_cve(cve, pilot),
                        [w for w in (cwe.get(i) for i in cve.cwe_ids) if w], [])
    assert out and out[0]["generated_by"] == "llm", out
