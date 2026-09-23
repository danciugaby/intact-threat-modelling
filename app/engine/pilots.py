"""INTACT pilot / sector profiles.

Each profile tunes three things:
  * the context given to the LLM when it writes attack scenarios,
  * how CVSS impact (C/I/A) is weighted when ranking CVEs for that sector,
  * the regulatory / standards references attached to the threat model.

Profiles follow the INTACT pilot use cases (PUC1-PUC4) plus the smart-city
cross-vertical demonstrations. Add or edit profiles here; nothing else in the
code hard-codes a sector.
"""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class PilotProfile:
    key: str
    name: str
    context: str
    typical_assets: tuple
    # Relative importance of Confidentiality / Integrity / Availability (sum ~= 1).
    cia_weights: dict
    # Whether a successful attack can plausibly harm people or physical processes.
    safety_critical: bool
    impact_focus: str
    standards: tuple = field(default_factory=tuple)


PILOTS = {
    "telecom": PilotProfile(
        key="telecom",
        name="PUC1 - Telecommunications / 5G",
        context=(
            "Virtualised 5G network (core and RAN functions on OpenStack / Kubernetes, "
            "OpenAirInterface-style components) spanning IoT, edge and cloud, mirrored in a "
            "cyber-range digital twin."
        ),
        typical_assets=("5G core network functions", "gNB / RAN", "MEC edge nodes",
                        "OpenStack controllers", "orchestrators (NFV MANO)", "IoT UEs"),
        cia_weights={"C": 0.25, "I": 0.30, "A": 0.45},
        safety_critical=False,
        impact_focus="service availability, subscriber data, lateral movement between network slices and tenants",
        standards=("3GPP SCAS (TS 33.117 and NF-specific)", "ENISA 5G Toolbox", "NIS2 Directive",
                   "EU Cyber Resilience Act"),
    ),
    "health": PilotProfile(
        key="health",
        name="PUC2 - Health 4.0",
        context=(
            "Hospital environment with medical IoT (MIoT) devices, blood analysers, MRI scanners, "
            "RIS/PACS workstations and electronic patient records, connected edge-to-cloud."
        ),
        typical_assets=("medical IoT devices", "RIS/PACS", "EHR systems", "lab analysers",
                        "imaging modalities", "clinical gateways"),
        cia_weights={"C": 0.40, "I": 0.35, "A": 0.25},
        safety_critical=True,
        impact_focus="patient safety, confidentiality of health data (GDPR special category), integrity of diagnostic results",
        standards=("EU MDR 2017/745 (Annex I 17.2/17.4)", "MDCG 2019-16", "IEC 81001-5-1",
                   "IEC 80001-1", "GDPR Art. 9 & 32", "NIS2 Directive"),
    ),
    "transport": PilotProfile(
        key="transport",
        name="PUC3 - Transportation / fuel-cell vehicles",
        context=(
            "Fuel-cell truck test infrastructure: fuel-cell ECUs, in-vehicle networks (CAN / "
            "automotive Ethernet), telematics and over-the-air (OTA) software update backend."
        ),
        typical_assets=("fuel-cell ECUs", "gateway ECU", "telematics unit", "OTA backend",
                        "diagnostic interfaces", "test-bench controllers"),
        cia_weights={"C": 0.15, "I": 0.50, "A": 0.35},
        safety_critical=True,
        impact_focus="functional safety, integrity of software updates and control commands, vehicle availability",
        standards=("UNECE R155 (CSMS)", "UNECE R156 (SUMS)", "ISO/SAE 21434", "ISO 26262 (safety interplay)"),
    ),
    "nuclear": PilotProfile(
        key="nuclear",
        name="PUC4 - Safety-critical nuclear operations",
        context=(
            "Monitoring network for a nuclear / radiological facility: radiation and environmental "
            "sensors, IoT-edge gateways and SDN/NFV infrastructure operated from a network "
            "operations centre."
        ),
        typical_assets=("radiation sensors", "environmental sensors", "edge gateways",
                        "SDN controllers", "VNFs", "NOC monitoring systems"),
        cia_weights={"C": 0.15, "I": 0.45, "A": 0.40},
        safety_critical=True,
        impact_focus="integrity and availability of safety monitoring data, false or suppressed alarms, loss of situational awareness",
        standards=("IEC 62645", "IEC 63096", "IAEA Nuclear Security Series No. 17-T", "IEC 62443",
                   "NIS2 Directive"),
    ),
    "smart_city": PilotProfile(
        key="smart_city",
        name="Smart city (cross-vertical)",
        context=(
            "Municipal IoT deployments (traffic, lighting, environmental sensing) with shared edge "
            "and cloud platforms and third-party supply-chain components."
        ),
        typical_assets=("IoT sensors", "LoRaWAN / NB-IoT gateways", "city data platform",
                        "traffic controllers", "citizen-facing apps"),
        cia_weights={"C": 0.30, "I": 0.35, "A": 0.35},
        safety_critical=False,
        impact_focus="public service disruption, citizen privacy, supply-chain compromise across verticals",
        standards=("ETSI EN 303 645", "IEC 62443", "EU Cyber Resilience Act", "GDPR", "NIS2 Directive"),
    ),
    "generic": PilotProfile(
        key="generic",
        name="Generic IoT-to-cloud",
        context="Distributed IoT-edge-cloud infrastructure.",
        typical_assets=("IoT devices", "edge nodes", "cloud services"),
        cia_weights={"C": 1 / 3, "I": 1 / 3, "A": 1 / 3},
        safety_critical=False,
        impact_focus="confidentiality, integrity and availability of the service",
        standards=("EU Cyber Resilience Act", "NIS2 Directive", "IEC 62443"),
    ),
}

ALIASES = {
    "puc1": "telecom", "5g": "telecom", "telecommunications": "telecom",
    "puc2": "health", "healthcare": "health", "health4.0": "health", "medical": "health",
    "puc3": "transport", "transportation": "transport", "automotive": "transport",
    "puc4": "nuclear",
    "smartcity": "smart_city", "smart-city": "smart_city", "city": "smart_city",
}


def get_pilot(key):
    """Return the profile for ``key`` (case-insensitive, aliases allowed); ``None`` if unknown."""
    if not key:
        return None
    k = str(key).strip().lower().replace(" ", "")
    k = ALIASES.get(k, k)
    return PILOTS.get(k)


def list_pilots():
    return [
        {"key": p.key, "name": p.name, "safety_critical": p.safety_critical,
         "cia_weights": p.cia_weights, "standards": list(p.standards)}
        for p in PILOTS.values()
    ]
