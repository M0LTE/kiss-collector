#!/usr/bin/env python3
"""
kisscollector - subscribe to kissproxy/# on MQTT and log every 'unframed'
KISS frame into a per-host SQLite database.

Topic layout (from packet-net/kissproxy):
    kissproxy/<host>/<band>/<direction>/unframed/<port>/<frameType>
    e.g. kissproxy/gb7rdg-node/6m/fromModem/unframed/port0/DataFrameKissCmd

  - <host>       2nd level  -> one SQLite file per host  (<host>.db)
  - <band>       3rd level  -> e.g. 6m, 40m, 2m, 70cm
  - <direction>  4th level  -> fromModem | toModem
  - 'unframed'   5th level  -> ONLY these are stored (framed/decoded ignored)
  - <port>       6th level  -> e.g. port0
  - <frameType>  7th level  -> e.g. DataFrameKissCmd  (all types logged)

Payload = raw bytes of the (un-KISSed) AX.25 frame (kissproxy default
emitAsBase64String=false, published at QoS 2).
"""

import os
import re
import json
import sqlite3
import threading
import time
import logging

import paho.mqtt.client as mqtt

MQTT_HOST = os.environ.get("MQTT_HOST", "mqtt.lan")
MQTT_PORT = int(os.environ.get("MQTT_PORT", "1883"))
MQTT_USER = os.environ.get("MQTT_USER") or None
MQTT_PASS = os.environ.get("MQTT_PASS") or None
TOPIC = os.environ.get("MQTT_TOPIC", "kissproxy/#")
DB_DIR = os.environ.get("KISS_DB_DIR", "/var/lib/kisscollector")

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("kisscollector")

os.makedirs(DB_DIR, exist_ok=True)

# host names become file names; keep them filesystem-safe
_HOST_SAFE = re.compile(r"[^A-Za-z0-9._-]")

_conns = {}
_lock = threading.Lock()
_stats = {"stored": 0, "skipped": 0, "last_log": 0.0}

SCHEMA = """
CREATE TABLE IF NOT EXISTS frames (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_unix     REAL    NOT NULL,
    ts_utc      TEXT    NOT NULL,
    host        TEXT    NOT NULL,
    band        TEXT    NOT NULL,
    direction   TEXT    NOT NULL,
    port        TEXT    NOT NULL,
    frame_type  TEXT    NOT NULL,
    topic       TEXT    NOT NULL,
    payload     BLOB,
    payload_len INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_frames_ts       ON frames(ts_unix);
CREATE INDEX IF NOT EXISTS idx_frames_band_dir ON frames(band, direction);
CREATE INDEX IF NOT EXISTS idx_frames_type     ON frames(frame_type);

-- kissproxy's own ACKMODE transmit-timing, published to
-- kissproxy/<host>/<band>/timing/ackmode as JSON. Used to attach a tx time
-- to the matching outbound (toModem) frame.
CREATE TABLE IF NOT EXISTS ack_timing (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_unix        REAL    NOT NULL,
    ts_utc         TEXT    NOT NULL,
    host           TEXT    NOT NULL,
    band           TEXT    NOT NULL,
    seq            INTEGER,
    payload_bytes  INTEGER,
    mode           INTEGER,
    mode_name      TEXT,
    bit_rate       INTEGER,
    txdelay_ms     REAL,
    tx_duration_ms REAL,
    total_ms       REAL,
    queued_utc     TEXT,
    tx_start_utc   TEXT,
    tx_end_utc     TEXT,
    raw            TEXT
);
CREATE INDEX IF NOT EXISTS idx_ackt_ts  ON ack_timing(ts_unix);
CREATE INDEX IF NOT EXISTS idx_ackt_seq ON ack_timing(seq);
"""


def get_conn(host):
    """Return (creating if needed) the SQLite connection for a reporting host."""
    safe = _HOST_SAFE.sub("_", host) or "_unknown"
    conn = _conns.get(safe)
    if conn is None:
        path = os.path.join(DB_DIR, safe + ".db")
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.executescript(SCHEMA)
        conn.commit()
        _conns[safe] = conn
        log.info("opened database %s", path)
    return conn


def on_connect(client, userdata, flags, rc, *args):
    if rc == 0:
        log.info("connected to mqtt %s:%s; subscribing to %s",
                 MQTT_HOST, MQTT_PORT, TOPIC)
        client.subscribe(TOPIC, qos=0)
    else:
        log.error("mqtt connect failed rc=%s", rc)


def _heartbeat(now):
    if now - _stats["last_log"] >= 60:
        _stats["last_log"] = now
        log.info("stored=%d skipped=%d dbs=%d",
                 _stats["stored"], _stats["skipped"], len(_conns))


def store_frame(parts, payload):
    # kissproxy/<host>/<band>/<direction>/unframed/<port>/<frameType>
    _, host, band, direction, _framing, port, frame_type = parts
    now = time.time()
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    with _lock:
        conn = get_conn(host)
        conn.execute(
            "INSERT INTO frames (ts_unix, ts_utc, host, band, direction, "
            "port, frame_type, topic, payload, payload_len) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (now, iso, host, band, direction, port, frame_type,
             "/".join(parts), sqlite3.Binary(payload), len(payload)),
        )
        conn.commit()
    _stats["stored"] += 1
    _heartbeat(now)


def store_timing(parts, payload):
    # kissproxy/<host>/<band>/timing/ackmode  ->  JSON timing record
    _, host, band, _timing, _ackmode = parts
    try:
        j = json.loads(payload.decode("utf-8", "replace"))
    except Exception:
        log.warning("bad ackmode timing json on %s", "/".join(parts))
        return
    now = time.time()
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))
    with _lock:
        conn = get_conn(host)
        conn.execute(
            "INSERT INTO ack_timing (ts_unix, ts_utc, host, band, seq, "
            "payload_bytes, mode, mode_name, bit_rate, txdelay_ms, "
            "tx_duration_ms, total_ms, queued_utc, tx_start_utc, tx_end_utc, raw) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now, iso, host, band, j.get("seqNumber"), j.get("payloadBytes"),
             j.get("mode"), j.get("modeName"), j.get("bitRate"),
             j.get("txDelayMs"), j.get("txDurationMs"), j.get("totalMs"),
             j.get("queuedUtc"), j.get("txStartUtc"), j.get("txEndUtc"),
             payload.decode("utf-8", "replace")),
        )
        conn.commit()
    _stats["stored"] += 1
    log.info("ackmode timing seq=%s total=%sms band=%s",
             j.get("seqNumber"), j.get("totalMs"), band)
    _heartbeat(now)


def on_message(client, userdata, msg):
    parts = msg.topic.split("/")
    payload = msg.payload or b""
    try:
        if parts and parts[0] == "kissproxy":
            if len(parts) == 7 and parts[4] == "unframed":
                store_frame(parts, payload)
                return
            if len(parts) == 5 and parts[3] == "timing" and parts[4] == "ackmode":
                store_timing(parts, payload)
                return
        _stats["skipped"] += 1
    except Exception:
        log.exception("failed to handle message on %s", msg.topic)


def main():
    # version-agnostic construction (paho-mqtt 1.x and 2.x)
    try:
        client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION1,
                             client_id="kisscollector")
    except (AttributeError, TypeError):
        client = mqtt.Client(client_id="kisscollector")
    if MQTT_USER:
        client.username_pw_set(MQTT_USER, MQTT_PASS)
    client.on_connect = on_connect
    client.on_message = on_message
    client.reconnect_delay_set(min_delay=1, max_delay=30)
    log.info("kisscollector starting; db dir=%s", DB_DIR)
    while True:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
            client.loop_forever(retry_first_connection=True)
        except Exception:
            log.exception("mqtt loop error; retrying in 5s")
            time.sleep(5)


if __name__ == "__main__":
    main()
