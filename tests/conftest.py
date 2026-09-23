import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from app.config import TestConfig  # noqa: E402
from app.engine.catalogs import CapecCatalog, CweCatalog  # noqa: E402
from app.engine.nvd import parse_cve  # noqa: E402

FIX = os.path.join(ROOT, "tests", "fixtures")


def load_fixture(name):
    with open(os.path.join(FIX, name)) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def nvd_page():
    return load_fixture("nvd_cisco_ios_xe.json")


@pytest.fixture(scope="session")
def cwe_catalog():
    return CweCatalog(os.path.join(FIX, "cwec_sample.xml"))


@pytest.fixture(scope="session")
def capec_catalog():
    return CapecCatalog(os.path.join(FIX, "capec_sample.xml"))


class FakeNvd:
    def __init__(self, page):
        self.page = page
        self.calls = []

    def _all(self):
        return [parse_cve(v) for v in self.page["vulnerabilities"]]

    def search_by_cpe(self, cpe):
        self.calls.append(("cpe", cpe))
        return self._all()

    def search_by_keyword(self, kw):
        self.calls.append(("keyword", kw))
        return self._all()


class FakeCompletions:
    def __init__(self, content):
        self.content = content
        self.calls = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        content = self.content(kwargs) if callable(self.content) else self.content

        class Msg:
            pass

        m = Msg()
        m.content = content
        choice = type("C", (), {"message": m})
        return type("R", (), {"choices": [choice]})


class FakeGroq:
    def __init__(self, content):
        self.chat = type("Chat", (), {})()
        self.chat.completions = FakeCompletions(content)


@pytest.fixture
def make_app(tmp_path, nvd_page, cwe_catalog, capec_catalog):
    from app import create_app
    from app.engine.llm import ScenarioGenerator
    from app.engine.modeler import ThreatModeler

    def _make(llm_client=None, **overrides):
        cfg = type("Cfg", (TestConfig,), {
            "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path}/test.db", **overrides})
        cfg_map = {k: getattr(cfg, k) for k in dir(cfg) if k.isupper()}
        llm = ScenarioGenerator(provider="groq" if llm_client else "none", model="test-model",
                                client=llm_client)
        tm = ThreatModeler(cfg_map, nvd=FakeNvd(nvd_page), llm=llm, cwe=cwe_catalog, capec=capec_catalog)
        return create_app(cfg, threat_modeler=tm)

    return _make
