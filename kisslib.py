"""Shared helpers for kiss-collector: AX.25 decoding, per-host SQLite access,
and high-level traffic queries. Used by both webui.py and mcpserver.py."""

import os
import glob
import sqlite3
import datetime as dt

DB_DIR = os.environ.get("KISS_DB_DIR", "/var/lib/kisscollector")

# --------------------------------------------------------------- AX.25 decode

def _decode_addr(b):
    """Decode one 7-byte AX.25 address -> (callsign, ssid, last, cbit)."""
    call = "".join(chr(c >> 1) for c in b[:6]).strip()
    call = "".join(ch for ch in call if ch.isalnum())
    ssid = (b[6] >> 1) & 0x0F
    return call, ssid, bool(b[6] & 0x01), bool(b[6] & 0x80)


def _fmt(call, ssid):
    return f"{call}-{ssid}" if ssid else call


def decode_ax25(payload):
    """Best-effort AX.25 decode -> dict(from,to,via,type,pid,info) or None."""
    if not payload or len(payload) < 14:
        return None
    addrs, i = [], 0
    while i + 7 <= len(payload) and len(addrs) < 10:
        call, ssid, last, _c = _decode_addr(payload[i:i + 7])
        addrs.append((call, ssid))
        i += 7
        if last:
            break
    if len(addrs) < 2:
        return None
    out = {"from": _fmt(*addrs[1]), "to": _fmt(*addrs[0]),
           "via": [_fmt(*a) for a in addrs[2:]]}
    if i < len(payload):
        ctrl = payload[i]
        if (ctrl & 0x01) == 0:
            out["type"] = "I"
        elif (ctrl & 0x03) == 0x01:
            out["type"] = "S"
        else:
            out["type"] = "UI" if (ctrl & 0xEF) == 0x03 else "U"
        if out["type"] in ("I", "UI") and i + 1 < len(payload):
            out["pid"] = "0x%02X" % payload[i + 1]
            if i + 2 < len(payload):
                out["info"] = payload[i + 2:].decode("latin-1")
    return out


def _valid_call(c):
    base = c.split("-")[0]
    return 1 <= len(base) <= 6 and base.isalnum()


def good(dec):
    return bool(dec) and _valid_call(dec["from"]) and _valid_call(dec["to"])


def decode_frame(payload, frame_type):
    """Decode AX.25, accounting for the 2-byte seq prefix on AckMode frames."""
    is_ack = "AckMode" in (frame_type or "")
    cand = []
    if is_ack and len(payload) > 2:
        cand.append(decode_ax25(payload[2:]))
    cand.append(decode_ax25(payload))
    if not is_ack and len(payload) > 2:
        cand.append(decode_ax25(payload[2:]))
    for d in cand:
        if good(d):
            return d
    return cand[0] if cand else None


def printable(s):
    return "".join(c if 32 <= ord(c) < 127 else "." for c in s).rstrip(". ")


def iso(ts):
    return dt.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%SZ") if ts else ""


def parse_utc(s):
    """Parse a .NET ISO-8601 UTC timestamp -> epoch seconds, or None."""
    if not s:
        return None
    try:
        s = s.strip().replace("Z", "+00:00")
        if "." in s:
            head, _, tail = s.partition(".")
            frac = "".join(ch for ch in tail if ch.isdigit())[:6]
            off = ""
            for sign in ("+", "-"):
                if sign in tail:
                    off = sign + tail.split(sign, 1)[1]
                    break
            s = "%s.%s%s" % (head, frac, off)
        return dt.datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def parse_when(s):
    """Flexible time input -> epoch seconds. Accepts epoch, ISO, or relative
    shorthand like '30m', '6h', '7d'. Returns None if empty/unparseable."""
    if s is None or s == "":
        return None
    if isinstance(s, (int, float)):
        return float(s)
    s = str(s).strip()
    try:
        if s and s[-1] in "smhd" and s[:-1].replace(".", "", 1).isdigit():
            mult = {"s": 1, "m": 60, "h": 3600, "d": 86400}[s[-1]]
            return dt.datetime.utcnow().timestamp() - float(s[:-1]) * mult
        if s.replace(".", "", 1).isdigit():
            return float(s)
        return parse_utc(s) or dt.datetime.fromisoformat(s).timestamp()
    except Exception:
        return None


def norm_direction(d):
    """Input normalisation: accept RX/TX (or raw) -> DB value fromModem/toModem."""
    if not d:
        return None
    d = str(d).lower()
    if d in ("rx", "frommodem"):
        return "fromModem"
    if d in ("tx", "tomodem"):
        return "toModem"
    return d


def dir_label(d):
    """Output: DB direction -> human RX/TX."""
    return "TX" if d == "toModem" else "RX" if d == "fromModem" else d


def native_frame_type(ft):
    """'DataFrameKissCmd' -> 'DataFrame' (strip the KissCmd suffix)."""
    return ft[:-7] if ft and ft.endswith("KissCmd") else ft


def denorm_frame_type(name):
    """Input: accept native 'DataFrame' (or full) -> DB 'DataFrameKissCmd'."""
    if not name:
        return None
    return name if name.endswith("KissCmd") else name + "KissCmd"


# ----------------------------------------------------------------- DB access

def host_dbs():
    return sorted(glob.glob(os.path.join(DB_DIR, "*.db")))


def host_name(path):
    return os.path.basename(path)[:-3]


def connect(path):
    con = sqlite3.connect(path, timeout=5)
    con.execute("PRAGMA query_only=ON;")
    return con


# ------------------------------------------------------------------- queries

def build_where(f):
    clauses, params = [], []
    for col in ("band", "direction", "port", "frame_type"):
        if f.get(col):
            clauses.append("%s = ?" % col)
            params.append(f[col])
    if f.get("from_ts"):
        clauses.append("ts_unix >= ?")
        params.append(float(f["from_ts"]))
    if f.get("to_ts"):
        clauses.append("ts_unix <= ?")
        params.append(float(f["to_ts"]))
    if f.get("since_ts"):
        clauses.append("ts_unix > ?")
        params.append(float(f["since_ts"]))
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def query_frames(f, limit=200, order="DESC"):
    where, params = build_where(f)
    want_host = f.get("host")
    rows = []
    for path in host_dbs():
        host = host_name(path)
        if want_host and host != want_host:
            continue
        try:
            con = connect(path)
            sql = ("SELECT id, ts_unix, ts_utc, band, direction, port, "
                   "frame_type, payload, tx_time_ms, tx_duration_ms "
                   "FROM frames" + where +
                   " ORDER BY ts_unix " + order + " LIMIT ?")
            for r in con.execute(sql, params + [limit]):
                rows.append((host, r))
            con.close()
        except sqlite3.Error:
            continue
    rows.sort(key=lambda hr: hr[1][1], reverse=(order == "DESC"))
    return rows[:limit] if order == "DESC" else rows


def row_to_dict(host, r):
    (rid, ts_unix, ts_utc, band, direction, port, frame_type, payload,
     tx_time_ms, tx_duration_ms) = r
    payload = bytes(payload or b"")
    d = {"uid": "%s:%d" % (host, rid), "host": host, "ts_unix": ts_unix,
         "ts_utc": ts_utc, "band": band, "direction": direction, "port": port,
         "frame_type": frame_type, "len": len(payload), "hex": payload.hex(),
         "from": "", "to": "", "via": "", "type": "", "info": "",
         "tx_time_ms": tx_time_ms, "tx_duration_ms": tx_duration_ms}
    dec = decode_frame(payload, frame_type)
    if dec:
        d["from"] = dec["from"]
        d["to"] = dec["to"]
        d["via"] = " ".join(dec.get("via", []))
        d["type"] = dec.get("type", "")
        if dec.get("pid"):
            d["type"] += " " + dec["pid"]
        d["info"] = printable(dec.get("info", ""))
    d["is_ack"] = ("AckMode" in (frame_type or "")) and not good(dec)
    return d


def matches_text(d, callsign, q):
    if callsign:
        cs = callsign.upper()
        if cs not in d["from"].upper() and cs not in d["to"].upper() \
           and cs not in d["via"].upper():
            return False
    if q:
        hay = " ".join([d["from"], d["to"], d["via"], d["band"], d["direction"],
                        d["port"], d["frame_type"], d["info"], d["hex"]]).lower()
        if q.lower() not in hay:
            return False
    return True


def search(f, limit=200, order="DESC"):
    """Decoded, ack-hidden frame list matching filters f. The tx time is stored
    on the frame row by the collector (no query-time correlation)."""
    callsign = (f.get("callsign") or "").strip()
    q = (f.get("q") or "").strip()
    rows = query_frames(f, limit=limit if not (callsign or q) else 5000,
                        order=order)
    out = []
    for host, r in rows:
        d = row_to_dict(host, r)
        if d["is_ack"]:
            continue
        if matches_text(d, callsign, q):
            out.append(d)
    if order == "DESC":
        out = out[:limit]
    return out


def meta():
    m = {"hosts": [], "bands": set(), "directions": set(),
         "ports": set(), "frame_types": set()}
    for path in host_dbs():
        m["hosts"].append(host_name(path))
        try:
            con = connect(path)
            for col, key in (("band", "bands"), ("direction", "directions"),
                             ("port", "ports"), ("frame_type", "frame_types")):
                for (v,) in con.execute("SELECT DISTINCT %s FROM frames" % col):
                    if v:
                        m[key].add(v)
            con.close()
        except sqlite3.Error:
            continue
    for k in ("bands", "directions", "ports", "frame_types"):
        m[k] = sorted(m[k])
    return m


def overview():
    m = meta()
    total, earliest, latest = 0, None, None
    for path in host_dbs():
        try:
            con = connect(path)
            n, lo, hi = con.execute(
                "SELECT count(*), min(ts_unix), max(ts_unix) FROM frames").fetchone()
            total += n or 0
            if lo and (earliest is None or lo < earliest):
                earliest = lo
            if hi and (latest is None or hi > latest):
                latest = hi
            con.close()
        except sqlite3.Error:
            continue
    m["total_frames"] = total
    m["earliest"] = iso(earliest)
    m["latest"] = iso(latest)
    return m


def stats(f):
    where, params = build_where(f)
    bands, ftypes, dirs, total, recent = {}, {}, {}, 0, []
    for path in host_dbs():
        host = host_name(path)
        if f.get("host") and host != f["host"]:
            continue
        try:
            con = connect(path)
            for band, n, b, fmin, fmax in con.execute(
                    "SELECT band,count(*),sum(payload_len),min(ts_unix),max(ts_unix) "
                    "FROM frames" + where + " GROUP BY band", params):
                bands[(host, band)] = {"host": host, "band": band, "frames": n,
                                       "bytes": b or 0, "first": iso(fmin),
                                       "last": iso(fmax)}
                total += n
            for ft, n in con.execute("SELECT frame_type,count(*) FROM frames" +
                                     where + " GROUP BY frame_type", params):
                ftypes[ft] = ftypes.get(ft, 0) + n
            for dr, n in con.execute("SELECT direction,count(*) FROM frames" +
                                     where + " GROUP BY direction", params):
                dirs[dr] = dirs.get(dr, 0) + n
            for (p,) in con.execute("SELECT payload FROM frames" + where +
                                    " ORDER BY ts_unix DESC LIMIT 5000", params):
                recent.append(bytes(p or b""))
            con.close()
        except sqlite3.Error:
            continue
    top_from, top_to = {}, {}
    for p in recent:
        dec = decode_frame(p, "")
        if good(dec):
            top_from[dec["from"]] = top_from.get(dec["from"], 0) + 1
            top_to[dec["to"]] = top_to.get(dec["to"], 0) + 1

    def topn(d, n=15):
        return [{"call": k, "n": v} for k, v in
                sorted(d.items(), key=lambda x: -x[1])[:n]]

    return {"total": total,
            "bands": sorted(bands.values(), key=lambda x: (x["host"], x["band"])),
            "frame_types": [{"k": k, "n": v} for k, v in
                            sorted(ftypes.items(), key=lambda x: -x[1])],
            "directions": [{"k": k, "n": v} for k, v in
                           sorted(dirs.items(), key=lambda x: -x[1])],
            "top_from": topn(top_from), "top_to": topn(top_to)}


def top_talkers(f, by="from", limit=20):
    data = search(f, limit=5000, order="DESC")
    cnt = {}
    for d in data:
        k = d.get(by) or "?"
        cnt[k] = cnt.get(k, 0) + 1
    return sorted([{"call": k, "count": v} for k, v in cnt.items()],
                  key=lambda x: -x["count"])[:limit]


def activity(f, bucket="hour"):
    sqlfmt = "%Y-%m-%d %H:00" if bucket == "hour" else "%Y-%m-%d"
    where, params = build_where(f)
    buckets = {}
    for path in host_dbs():
        host = host_name(path)
        if f.get("host") and host != f["host"]:
            continue
        try:
            con = connect(path)
            for g, n in con.execute(
                    "SELECT strftime(?, ts_unix, 'unixepoch') AS g, count(*) "
                    "FROM frames" + where + " GROUP BY g", [sqlfmt] + params):
                buckets[g] = buckets.get(g, 0) + n
            con.close()
        except sqlite3.Error:
            continue
    return [{"bucket": k, "frames": v} for k, v in sorted(buckets.items())]


def tx_timing(f, limit=200):
    """ACKMODE transmit-timing records (from kissproxy), newest first.
    Filterable by host/band/time."""
    clauses, params = [], []
    if f.get("band"):
        clauses.append("band = ?")
        params.append(f["band"])
    if f.get("from_ts"):
        clauses.append("ts_unix >= ?")
        params.append(float(f["from_ts"]))
    if f.get("to_ts"):
        clauses.append("ts_unix <= ?")
        params.append(float(f["to_ts"]))
    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    cols = ["received", "band", "seq", "payload_bytes", "mode", "mode_name",
            "bit_rate", "txdelay_ms", "tx_duration_ms", "total_ms",
            "queued_utc", "tx_end_utc"]
    out = []
    for path in host_dbs():
        host = host_name(path)
        if f.get("host") and host != f["host"]:
            continue
        try:
            con = connect(path)
            sql = ("SELECT ts_utc, band, seq, payload_bytes, mode, mode_name, "
                   "bit_rate, txdelay_ms, tx_duration_ms, total_ms, queued_utc, "
                   "tx_end_utc FROM ack_timing" + where +
                   " ORDER BY ts_unix DESC LIMIT ?")
            for row in con.execute(sql, params + [limit]):
                d = dict(zip(cols, row))
                d["host"] = host
                out.append(d)
            con.close()
        except sqlite3.Error:
            continue
    out.sort(key=lambda x: x.get("received") or "", reverse=True)
    return out[:limit]


def _unified_conn():
    con = sqlite3.connect(":memory:")
    fv, av = [], []
    for i, path in enumerate(host_dbs()):
        sch = "h%d" % i
        con.execute("ATTACH DATABASE ? AS %s" % sch, (path,))
        # present friendly direction (RX/TX) and native frame-type names
        fv.append(
            "SELECT id, ts_unix, ts_utc, host, band, "
            "CASE direction WHEN 'toModem' THEN 'TX' "
            "WHEN 'fromModem' THEN 'RX' ELSE direction END AS direction, "
            "port, replace(frame_type, 'KissCmd', '') AS frame_type, "
            "topic, payload, payload_len, seq, tx_time_ms, tx_duration_ms "
            "FROM %s.frames" % sch)
        av.append("SELECT * FROM %s.ack_timing" % sch)
    if fv:
        con.execute("CREATE TEMP VIEW frames AS " + " UNION ALL ".join(fv))
        con.execute("CREATE TEMP VIEW ack_timing AS " + " UNION ALL ".join(av))
    return con


def run_sql(sql, max_rows=500):
    """Run a single read-only SELECT/WITH query over a unified view across all
    per-host DBs (tables: frames, ack_timing). Payload blobs returned as hex."""
    s = (sql or "").strip().rstrip(";")
    low = s.lstrip("(").lower()
    if not (low.startswith("select") or low.startswith("with")):
        raise ValueError("only read-only SELECT / WITH queries are allowed")
    if ";" in s:
        raise ValueError("only a single statement is allowed")
    con = _unified_conn()
    try:
        cur = con.execute(s)
        cols = [c[0] for c in cur.description] if cur.description else []
        rows = cur.fetchmany(max_rows)
        out = []
        for row in rows:
            rec = {}
            for c, v in zip(cols, row):
                rec[c] = v.hex() if isinstance(v, (bytes, bytearray)) else v
            out.append(rec)
        return {"columns": cols, "rows": out,
                "truncated": len(rows) == max_rows}
    finally:
        con.close()
