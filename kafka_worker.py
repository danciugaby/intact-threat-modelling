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
import uuid
from datetime import datetime, timezone

from confluent_kafka import Consumer, KafkaError, Producer

from app import create_app
from app.config import Config
from app import services

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


def consume():
    app = create_app()
    cfg = app.config
    consumer = Consumer({
        "bootstrap.servers": cfg["KAFKA_BOOTSTRAP_SERVERS"],
        "group.id": cfg["KAFKA_GROUP_ID"],
        "auto.offset.reset": "earliest",
        "enable.auto.commit": False,
        # scenario generation can take minutes for large requests
        "max.poll.interval.ms": 900000,
    })
    producer = Producer({"bootstrap.servers": cfg["KAFKA_BOOTSTRAP_SERVERS"]})
    consumer.subscribe([cfg["KAFKA_REQUEST_TOPIC"]])
    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)
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
            request_id = (msg.key() or b"").decode("utf-8", "replace") or str(uuid.uuid4())
            try:
                payload = json.loads(msg.value().decode("utf-8"))
                request_id = payload.get("request_id") or request_id
                result = handle(app, payload)
                out = {"request_id": request_id, "status": "done", "type": payload.get("type", "device"),
                       "result": result}
                topic = cfg["KAFKA_RESULT_TOPIC"]
            except Exception as exc:
                log.exception("Request %s failed", request_id)
                out = {"request_id": request_id, "status": "failed", "error": f"{exc.__class__.__name__}: {exc}"[:500],
                       "original": (msg.value() or b"")[:10000].decode("utf-8", "replace")}
                topic = cfg["KAFKA_DLQ_TOPIC"]
            out["completed_at"] = datetime.now(timezone.utc).isoformat()
            producer.produce(topic, key=request_id, value=json.dumps(out, default=str))
            producer.flush(30)
            consumer.commit(msg, asynchronous=False)
    finally:
        consumer.close()
        log.info("Kafka worker stopped")


def send_example():
    producer = Producer({"bootstrap.servers": Config.KAFKA_BOOTSTRAP_SERVERS})
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
