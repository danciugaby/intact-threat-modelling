"""Kafka integration for the INTACT event bus.

Consumes analysis requests from KAFKA_REQUEST_TOPIC and publishes results to
KAFKA_RESULT_TOPIC (failures to KAFKA_DLQ_TOPIC). The old consumer only logged results
and crashed at start-up (wrong ThreatModeler signature).

Request message (JSON):
    {"request_id": "...",                      # optional, echoed back (also the message key)
     "type": "device" | "asset" | "topology",   # default "device"
     "device_data": {...},                      # for type=device
     "asset_id": "...", "topology_id": "...",   # for type=asset / topology
     "pilot": "health", "limit": 5}

Result message:
    {"request_id": ..., "status": "done"|"failed", "type": ..., "result": {...} | "error": "..."}

Run:  python kafka_worker.py            (consumer)
      python kafka_worker.py --send-example   (publish a sample request)
"""
import argparse
import json
import logging
import signal
import time
import uuid
from datetime import datetime, timezone

import requests

try:  # optional dependency: pip install -r requirements-kafka.txt
    from confluent_kafka import Consumer, KafkaError, Producer, TopicPartition
except ImportError:  # pragma: no cover - exercised only when Kafka support isn't installed
    Consumer = KafkaError = Producer = TopicPartition = None

from app import create_app
from app.config import Config
from app import services
from app.engine.http import UpstreamError
from app.risk_assessment import RiskAssessmentError

log = logging.getLogger("kafka_worker")
RUNNING = True


def _stop(*_):
    global RUNNING
    RUNNING = False


def handle(app, payload):
    kind = payload.get("type", "device")
    pilot, limit = payload.get("pilot"), payload.get("limit")
    with app.app_context():
        if kind == "device":
            return services.analyze_device(payload.get("device_data") or {}, pilot, limit)
        if kind == "asset":
            return services.analyze_asset(payload["asset_id"], pilot, limit)
        if kind == "topology":
            return services.analyze_topology(payload["topology_id"], pilot, limit)
    raise ValueError(f"unknown request type '{kind}'")


def _require_kafka():
    if Consumer is None:
        raise SystemExit("Kafka support is not installed: pip install -r requirements-kafka.txt")


def client_config(cfg, **extra):
    """librdkafka settings, including SASL/TLS for a secured INTACT event bus."""
    conf = {"bootstrap.servers": cfg["KAFKA_BOOTSTRAP_SERVERS"]}
    for key, setting in (("KAFKA_SECURITY_PROTOCOL", "security.protocol"), ("KAFKA_SASL_MECHANISM", "sasl.mechanism"),
                         ("KAFKA_SASL_USERNAME", "sasl.username"), ("KAFKA_SASL_PASSWORD", "sasl.password"),
                         ("KAFKA_SSL_CA_LOCATION", "ssl.ca.location"),
                         ("KAFKA_SSL_CERT_LOCATION", "ssl.certificate.location"),
                         ("KAFKA_SSL_KEY_LOCATION", "ssl.key.location")):
        if cfg.get(key):
            conf[setting] = cfg[key]
    conf.update(extra)
    return conf


def is_transient(exc):
    """Errors worth retrying: a data source or the Risk Assessment service was unavailable."""
    if isinstance(exc, (UpstreamError, requests.RequestException)):
        return True
    return isinstance(exc, RiskAssessmentError) and exc.status >= 500 and exc.status != 501


def _process(app, msg, max_attempts, backoff):
    """Return (topic, message) for one request, retrying transient failures."""
    cfg = app.config
    request_id = (msg.key() or b"").decode("utf-8", "replace") or str(uuid.uuid4())
    payload, attempt = None, 0
    while True:
        attempt += 1
        try:
            if payload is None:
                payload = json.loads(msg.value().decode("utf-8"))
                if not isinstance(payload, dict):
                    raise ValueError("request must be a JSON object")
                request_id = payload.get("request_id") or request_id
            result = handle(app, payload)
            return cfg["KAFKA_RESULT_TOPIC"], request_id, {
                "request_id": request_id, "status": "done", "type": payload.get("type", "device"),
                "result": result, "attempts": attempt}
        except Exception as exc:
            if is_transient(exc) and attempt < max_attempts and RUNNING:
                delay = backoff * (2 ** (attempt - 1))
                log.warning("Request %s: transient failure (%s); retry %d/%d in %.0fs",
                            request_id, exc, attempt, max_attempts - 1, delay)
                time.sleep(delay)
                continue
            log.exception("Request %s failed", request_id)
            return cfg["KAFKA_DLQ_TOPIC"], request_id, {
                "request_id": request_id, "status": "failed", "attempts": attempt,
                "transient": is_transient(exc), "error": f"{exc.__class__.__name__}: {exc}"[:500],
                "original": (msg.value() or b"")[:10000].decode("utf-8", "replace")}


def consume():
    _require_kafka()
    app = create_app()
    cfg = app.config
    consumer = Consumer(client_config(
        cfg,
        **{"group.id": cfg["KAFKA_GROUP_ID"], "auto.offset.reset": "earliest", "enable.auto.commit": False,
           # scenario generation can take minutes for large requests
           "max.poll.interval.ms": 900000}))
    producer = Producer(client_config(cfg, **{"enable.idempotence": True}))
    consumer.subscribe([cfg["KAFKA_REQUEST_TOPIC"]])
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
    max_attempts = max(1, int(cfg.get("KAFKA_MAX_ATTEMPTS", 3)))
    backoff = float(cfg.get("KAFKA_RETRY_BACKOFF", 5))
    log.info("Listening on %s -> results %s", cfg["KAFKA_REQUEST_TOPIC"], cfg["KAFKA_RESULT_TOPIC"])

    try:
        while RUNNING:
            msg = consumer.poll(1.0)
            if msg is None:
                continue
            if msg.error():
                if msg.error().code() != KafkaError._PARTITION_EOF:
                    log.error("Kafka error: %s", msg.error())
                continue
            topic, request_id, out = _process(app, msg, max_attempts, backoff)
            out["completed_at"] = datetime.now(timezone.utc).isoformat()
            producer.produce(topic, key=request_id, value=json.dumps(out, default=str))
            remaining = producer.flush(30)
            if remaining:
                # The result was not delivered: don't commit, re-read this message later.
                log.error("Could not deliver the result for %s to %s; will reprocess", request_id, topic)
                consumer.seek(TopicPartition(msg.topic(), msg.partition(), msg.offset()))
                time.sleep(backoff)
                continue
            consumer.commit(msg, asynchronous=False)
    finally:
        consumer.close()
        log.info("Kafka worker stopped")


def send_example():
    _require_kafka()
    producer = Producer(client_config({k: getattr(Config, k) for k in dir(Config) if k.isupper()}))
    rid = str(uuid.uuid4())
    msg = {"request_id": rid, "type": "device", "pilot": "health",
           "device_data": {"cpe": "cpe:2.3:o:nordicsemi:nrf52840_firmware:-:*:*:*:*:*:*:*",
                           "deviceName": "Medical device using Nordic nRF52840"}}
    producer.produce(Config.KAFKA_REQUEST_TOPIC, key=rid, value=json.dumps(msg))
    producer.flush(10)
    print(f"sent {rid} to {Config.KAFKA_REQUEST_TOPIC}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--send-example", action="store_true")
    if ap.parse_args().send_example:
        send_example()
    else:
        consume()
