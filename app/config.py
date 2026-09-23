"""Runtime configuration, read from environment variables (and an optional .env file)."""
import os

try:  # python-dotenv is optional
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _bool(name, default=False):
    return os.getenv(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


def _int(name, default):
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _float(name, default):
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _list(name, default=""):
    return [v.strip() for v in os.getenv(name, default).split(",") if v.strip()]


class Config:
    # ---- Threat model selection -------------------------------------------------
    # Number of CVEs kept per device after risk ranking.
    THREAT_MODEL_LIMIT = _int("THREAT_MODEL_LIMIT", 5)
    # Upper bound on CVEs pulled from NVD before ranking (keyword searches can be huge).
    NVD_MAX_RESULTS = _int("NVD_MAX_RESULTS", 2000)
    # Ignore CVEs older than N years (0 = no filter). Old CVEs still matter for legacy
    # medical/nuclear kit, so the default keeps everything.
    CVE_MAX_AGE_YEARS = _int("CVE_MAX_AGE_YEARS", 0)
    # Default INTACT pilot profile when the request doesn't name one.
    DEFAULT_PILOT = os.getenv("DEFAULT_PILOT", "generic")

    # ---- Data sources -------------------------------------------------------------
    NVD_API_URL = os.getenv("NVD_API_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0")
    NVD_API_KEY = os.getenv("NVD_API_KEY")  # strongly recommended: 50 req/30s instead of 5
    NVD_TIMEOUT = _float("NVD_TIMEOUT", 30)
    NVD_CACHE_TTL = _int("NVD_CACHE_TTL", 6 * 3600)
    EPSS_ENABLED = _bool("EPSS_ENABLED", True)
    EPSS_API_URL = os.getenv("EPSS_API_URL", "https://api.first.org/data/v1/epss")
    KEV_FEED_URL = os.getenv(
        "KEV_FEED_URL",
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    KEV_ENABLED = _bool("KEV_ENABLED", True)
    HTTP_TIMEOUT = _float("HTTP_TIMEOUT", 20)
    # Prefer a catalogue refreshed by scripts/update_data.py, else the bundled CWE 4.13.
    CWEC_FILE_PATH = os.getenv("CWEC_FILE_PATH") or next(
        (p for p in (os.path.join(_BASE_DIR, "data", "cwec_latest.xml"),
                     os.path.join(_BASE_DIR, "data", "cwec_v4.13.xml")) if os.path.exists(p)),
        os.path.join(_BASE_DIR, "data", "cwec_v4.13.xml"))
    CAPEC_FILE_PATH = os.getenv("CAPEC_FILE_PATH", os.path.join(_BASE_DIR, "data", "capec_latest.xml"))

    # ---- LLM (Groq) -----------------------------------------------------------------
    # LLM_PROVIDER: "groq" (production) or "none" (deterministic output, used by tests/offline).
    LLM_PROVIDER = os.getenv("LLM_PROVIDER", "groq").lower()
    LLM_MODEL_NAME = os.getenv("LLM_MODEL_NAME", "llama-3.3-70b-versatile")
    GROQ_API_KEY = os.getenv("GROQ_API_KEY") or os.getenv("API_KEY")  # API_KEY kept for backwards compat
    LLM_TEMPERATURE = _float("LLM_TEMPERATURE", 0.3)
    LLM_TIMEOUT = _float("LLM_TIMEOUT", 60)
    LLM_MAX_RETRIES = _int("LLM_MAX_RETRIES", 2)
    LLM_MAX_CONCURRENCY = _int("LLM_MAX_CONCURRENCY", 4)
    SCENARIOS_PER_CVE = _int("SCENARIOS_PER_CVE", 3)

    # ---- Topology analysis ------------------------------------------------------------
    TOPOLOGY_MAX_PATH_DEPTH = _int("TOPOLOGY_MAX_PATH_DEPTH", 4)
    TOPOLOGY_MAX_PATHS = _int("TOPOLOGY_MAX_PATHS", 25)
    TOPOLOGY_LLM_SUMMARY = _bool("TOPOLOGY_LLM_SUMMARY", True)

    # ---- Database -------------------------------------------------------------------------
    SQLALCHEMY_DATABASE_URI = os.getenv(
        "SQLALCHEMY_DATABASE_URI", "sqlite:///" + os.path.join(_BASE_DIR, "data", "threat_models.db")
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    PERSIST_RESULTS = _bool("PERSIST_RESULTS", True)

    # ---- Background jobs --------------------------------------------------------------------
    JOB_WORKERS = _int("JOB_WORKERS", 2)

    # ---- Security ---------------------------------------------------------------------------
    SECRET_KEY = os.getenv("SECRET_KEY") or os.urandom(32).hex()
    AUTH_ENABLED = _bool("AUTH_ENABLED", _bool("KEYCLOAK_USAGE", False))
    KEYCLOAK_SERVER_URL = os.getenv("KEYCLOAK_SERVER_URL", "").rstrip("/")
    KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "")
    KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID")  # expected audience / azp
    KEYCLOAK_REQUIRED_ROLE = os.getenv("KEYCLOAK_REQUIRED_ROLE")  # optional realm or client role
    CORS_ORIGINS = _list("CORS_ORIGINS", "")  # empty = CORS disabled
    MAX_CONTENT_LENGTH = _int("MAX_CONTENT_LENGTH", 1024 * 1024)

    # ---- Risk Assessment service (INTACT integration) -----------------------------------------
    RISK_ASSESSMENT_TOKEN = os.getenv("RISK_ASSESSMENT_TOKEN")
    RISK_ASSESSMENT_SERVICE_URL = os.getenv("RISK_ASSESSMENT_SERVICE_URL")
    # Templates; {topology_id} / {asset_id} are substituted.
    RISK_ASSESSMENT_GET_TOPOLOGY_URL = os.getenv("RISK_ASSESSMENT_GET_TOPOLOGY_URL")
    RISK_ASSESSMENT_GET_ASSET_URL = os.getenv(
        "RISK_ASSESSMENT_GET_ASSET_URL", os.getenv("RISK_ASSESSMENT_GET_ASSETS_URL")
    )

    # ---- Kafka --------------------------------------------------------------------------------
    KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
    KAFKA_REQUEST_TOPIC = os.getenv("KAFKA_REQUEST_TOPIC", "threat-modeling-topic")
    KAFKA_RESULT_TOPIC = os.getenv("KAFKA_RESULT_TOPIC", "threat-modeling-results")
    KAFKA_DLQ_TOPIC = os.getenv("KAFKA_DLQ_TOPIC", "threat-modeling-dlq")
    KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "threat-modeling-group")

    API_NAME = "INTACT Threat Modelling API"
    API_VERSION = "2.0.0"


class TestConfig(Config):
    TESTING = True
    LLM_PROVIDER = "none"
    SQLALCHEMY_DATABASE_URI = "sqlite:///:memory:"
    AUTH_ENABLED = False
    EPSS_ENABLED = False
    KEV_ENABLED = False
    NVD_API_KEY = None
    JOB_WORKERS = 1
