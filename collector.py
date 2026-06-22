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
import glob
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
    payload_len INTEGER NOT NULL,
    seq            INTEGER,   -- KISS sequence number (AckMode frames only)
    tx_time_ms     REAL,      -- ACKMODE queue-to-ack time, filled on receipt
    tx_duration_ms REAL       -- ACKMODE on-air time (airtime)
);
CREATE INDEX IF NOT EXISTS idx_frames_ts       ON frames(ts_unix);
CREATE INDEX IF NOT EXISTS idx_frames_band_dir ON frames(band, direction);
CREATE INDEX IF NOT EXISTS idx_frames_type     ON frames(frame_type);
CREATE INDEX IF NOT EXISTS idx_frames_seq      ON frames(seq);

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
        # Add columns to a pre-existing frames table BEFORE executescript runs,
        # so its indexes (e.g. on seq) don't reference a not-yet-added column.
        # On a fresh DB the table doesn't exist yet -> OperationalError, ignored
        # (executescript then creates it complete); on a current DB -> duplicate
        # column, ignored.
        for col, typ in (("seq", "INTEGER"), ("tx_time_ms", "REAL"),
                         ("tx_duration_ms", "REAL")):
            try:
                conn.execute("ALTER TABLE frames ADD COLUMN %s %s" % (col, typ))
            except sqlite3.OperationalError:
                pass
        conn.executescript(SCHEMA)
        conn.commit()
        _conns[safe] = conn
        log.info("opened database %s", path)
    return conn


def migrate_existing():
    """Open every existing DB at startup so schema migrations are applied
    before readers (web UI / MCP) query the new columns."""
    for path in sorted(glob.glob(os.path.join(DB_DIR, "*.db"))):
        host = os.path.basename(path)[:-3]
        try:
            get_conn(host)
        except Exception:
            log.exception("startup migration failed for %s", path)


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
    # AckMode frames carry a 2-byte sequence prefix; capture it for correlation
    seq = None
    if "AckMode" in frame_type and len(payload) >= 2:
        seq = (payload[0] << 8) | payload[1]
    with _lock:
        conn = get_conn(host)
        conn.execute(
            "INSERT INTO frames (ts_unix, ts_utc, host, band, direction, "
            "port, frame_type, topic, payload, payload_len, seq) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (now, iso, host, band, direction, port, frame_type,
             "/".join(parts), sqlite3.Binary(payload), len(payload), seq),
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
    seq = j.get("seqNumber")
    total = j.get("totalMs")
    dur = j.get("txDurationMs")
    matched = 0
    with _lock:
        conn = get_conn(host)
        conn.execute(
            "INSERT INTO ack_timing (ts_unix, ts_utc, host, band, seq, "
            "payload_bytes, mode, mode_name, bit_rate, txdelay_ms, "
            "tx_duration_ms, total_ms, queued_utc, tx_start_utc, tx_end_utc, raw) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now, iso, host, band, seq, j.get("payloadBytes"),
             j.get("mode"), j.get("modeName"), j.get("bitRate"),
             j.get("txDelayMs"), dur, total,
             j.get("queuedUtc"), j.get("txStartUtc"), j.get("txEndUtc"),
             payload.decode("utf-8", "replace")),
        )
        # stamp the tx time onto the originating outbound frame (newest
        # unstamped toModem frame on this band with the same sequence number)
        if seq is not None:
            cur = conn.execute(
                "UPDATE frames SET tx_time_ms=?, tx_duration_ms=? WHERE id=("
                "SELECT id FROM frames WHERE band=? AND direction='toModem' "
                "AND seq=? AND tx_time_ms IS NULL ORDER BY ts_unix DESC LIMIT 1)",
                (round(total, 1) if total is not None else None,
                 round(dur, 1) if dur is not None else None, band, seq),
            )
            matched = cur.rowcount
        conn.commit()
    _stats["stored"] += 1
    log.info("ackmode timing seq=%s total=%sms band=%s (frame %s)",
             seq, total, band, "stamped" if matched else "unmatched")
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
    migrate_existing()
    while True:
        try:
            client.connect(MQTT_HOST, MQTT_PORT, keepalive=30)
            client.loop_forever(retry_first_connection=True)
        except Exception:
            log.exception("mqtt loop error; retrying in 5s")
            time.sleep(5)


if __name__ == "__main__":
    main()
