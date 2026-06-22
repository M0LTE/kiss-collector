#!/usr/bin/env python3
"""kiss-collector MCP server - ask questions about captured AX.25/packet-radio
traffic. Exposes query tools over the per-host SQLite databases via the Model
Context Protocol (streamable-HTTP transport).

Add to an MCP client as:  http://<host>:8765/mcp
"""

import os

from mcp.server.fastmcp import FastMCP

import kisslib

INSTRUCTIONS = """AX.25 packet-radio traffic captured from KISS/MQTT collectors,
one database per receiving node (host).

Glossary — these are easy to confuse, read carefully:
- Every frame has `from` (the station that TRANSMITTED it), `to` (the
  DESTINATION address it was sent to), `via` (digipeater path), and `dir`:
    RX = the node RECEIVED it over the air (the node "heard" this frame)
    TX = the node itself TRANSMITTED it
- "Stations heard by <node>" = the `from` of RX frames. A node hears every
  frame on the channel regardless of its `to`, so the destination (`to`) is
  NOT who heard the frame, and `to` being a node's callsign does not mean that
  node is the receiver here.
- "Last heard" / "most recently heard" = the newest RX frame. Results are
  newest-first, so the first RX row is the most recent.
- "Who called X" / "addressed to X" = filter the destination (station_to=X);
  a different question from who was heard.
- Callsign SSIDs are significant: EI5IYB-1 and EI5IYB-7 are different stations.
"""

mcp = FastMCP(
    "kiss-collector",
    instructions=INSTRUCTIONS,
    host=os.environ.get("MCP_HOST", "0.0.0.0"),
    port=int(os.environ.get("MCP_PORT", "8765")),
)


def _slim(d):
    return {"time": d["ts_utc"], "from": d["from"], "to": d["to"],
            "via": d["via"], "band": d["band"], "host": d["host"],
            "dir": kisslib.dir_label(d["direction"]),
            "type": d["type"], "len": d["len"], "info": d["info"],
            "frame_type": kisslib.native_frame_type(d["frame_type"]),
            "tx_time_ms": d["tx_time_ms"],
            "tx_duration_ms": d["tx_duration_ms"]}


@mcp.tool()
def overview() -> dict:
    """Orientation: which hosts/bands/directions/frame-types exist, the total
    frame count, and the earliest/latest capture times. Directions are RX
    (received over the air / "heard" by the node) / TX (transmitted by the
    node); frame types use native KISS command names (DataFrame, TxDelay,
    AckMode, ...). Call this first."""
    o = kisslib.overview()
    o["directions"] = [kisslib.dir_label(d) for d in o.get("directions", [])]
    o["frame_types"] = [kisslib.native_frame_type(t)
                        for t in o.get("frame_types", [])]
    return o


@mcp.tool()
def search_traffic(callsign: str = "", station_from: str = "",
                   station_to: str = "", band: str = "", direction: str = "",
                   frame_type: str = "", since: str = "", until: str = "",
                   contains: str = "", limit: int = 100) -> list:
    """Search decoded AX.25 frames, NEWEST FIRST (the first row is the most
    recent match). Use for "what/who was heard", "last heard", "who called X",
    traffic between stations, etc.

    direction    - 'RX' = frames the node RECEIVED over the air (i.e. HEARD);
                   'TX' = frames the node TRANSMITTED. "Heard"/"copied"
                   questions are RX, and the heard station is the frame's `from`.
    station_from - the TRANSMITTING station (for RX, the station that was heard)
    station_to   - the DESTINATION address. NOTE: who the frame was addressed
                   to, NOT who heard it — the node receives every frame on the
                   channel regardless of destination.
    callsign     - match in `from`, `to` OR `via` (any role)
    band         - e.g. '2m', '40m', '70cm'
    frame_type   - native KISS command name, e.g. 'DataFrame', 'AckMode'
    since/until  - time bounds: ISO ('2026-06-22 20:00'), epoch, or relative
                   shorthand like '30m','6h','7d'
    contains     - free-text substring over callsigns, info text and hex
    limit        - max rows (default 100)

    Tip: "last station heard on 40m" -> direction='RX', band='40m', read the
    first row's `from`. SSIDs are significant (EI5IYB-1 != EI5IYB-7).

    Returns time, from, to, via, band, dir, type, info, and for TX frames
    tx_time_ms / tx_duration_ms (ACKMODE queue-to-ack time and airtime)."""
    f = {"band": band or None, "direction": kisslib.norm_direction(direction),
         "frame_type": kisslib.denorm_frame_type(frame_type),
         "callsign": callsign or None,
         "q": contains or None, "from_ts": kisslib.parse_when(since),
         "to_ts": kisslib.parse_when(until)}
    res = kisslib.search(f, limit=min(int(limit), 1000))
    if station_from:
        res = [d for d in res if station_from.upper() in d["from"].upper()]
    if station_to:
        res = [d for d in res if station_to.upper() in d["to"].upper()]
    return [_slim(d) for d in res]


@mcp.tool()
def top_talkers(by: str = "from", band: str = "", direction: str = "",
                since: str = "", until: str = "", limit: int = 20) -> list:
    """Most active callsigns. by='from' = transmitting stations (with
    direction='RX' these are the stations heard most often); by='to' =
    most-addressed destinations. Scope with band/direction/time.
    Returns [{call, count}]."""
    f = {"band": band or None, "direction": kisslib.norm_direction(direction),
         "from_ts": kisslib.parse_when(since), "to_ts": kisslib.parse_when(until)}
    return kisslib.top_talkers(f, by=("to" if by == "to" else "from"),
                               limit=min(int(limit), 100))


@mcp.tool()
def activity(bucket: str = "hour", band: str = "", direction: str = "",
             since: str = "", until: str = "") -> list:
    """Frame counts over time. bucket='hour' or 'day'. Returns
    [{bucket, frames}] in chronological order."""
    f = {"band": band or None, "direction": kisslib.norm_direction(direction),
         "from_ts": kisslib.parse_when(since), "to_ts": kisslib.parse_when(until)}
    return kisslib.activity(f, bucket=("day" if bucket == "day" else "hour"))


@mcp.tool()
def stats(band: str = "", since: str = "", until: str = "") -> dict:
    """Per-band summary (frames, bytes, first/last heard), frame-type and
    direction (RX/TX) counts, and top source/destination callsigns."""
    f = {"band": band or None, "from_ts": kisslib.parse_when(since),
         "to_ts": kisslib.parse_when(until)}
    s = kisslib.stats(f)
    s["directions"] = [{"k": kisslib.dir_label(x["k"]), "n": x["n"]}
                       for x in s["directions"]]
    s["frame_types"] = [{"k": kisslib.native_frame_type(x["k"]), "n": x["n"]}
                        for x in s["frame_types"]]
    return s


@mcp.tool()
def tx_timing(band: str = "", since: str = "", until: str = "",
              limit: int = 100) -> list:
    """ACKMODE transmit-timing, one record per acknowledged outbound (TX)
    frame, as measured by kissproxy. Fields (times in milliseconds):
      seq            - 16-bit KISS sequence number
      payload_bytes  - AX.25 payload size
      mode/mode_name/bit_rate - NinoTNC mode in use
      txdelay_ms     - configured TX delay
      tx_duration_ms - on-air transmission time (airtime)
      total_ms       - total queue-to-ack time (airtime + channel access + delay)
      queued_utc / tx_end_utc - queued and acknowledged timestamps
    Optionally scope by band/time. Newest first."""
    f = {"band": band or None, "from_ts": kisslib.parse_when(since),
         "to_ts": kisslib.parse_when(until)}
    return kisslib.tx_timing(f, limit=min(int(limit), 1000))


@mcp.tool()
def run_sql(sql: str) -> dict:
    """Run ONE read-only SQL SELECT/WITH query over a unified view spanning all
    per-host databases. Use for aggregate questions SQL can answer directly
    (callsigns are NOT columns - decode-based questions use search_traffic).

    Tables/views:
      frames(id, ts_unix REAL, ts_utc TEXT, host, band, direction ['RX'|'TX'],
             port, frame_type [native, e.g. 'DataFrame'], topic, payload BLOB,
             payload_len)
      ack_timing(id, ts_unix, ts_utc, host, band, seq, payload_bytes, mode,
             mode_name, bit_rate, txdelay_ms, tx_duration_ms [airtime],
             total_ms [queue-to-ack], queued_utc, tx_start_utc, tx_end_utc, raw)

    ts_unix is epoch seconds; use strftime('%Y-%m-%d %H:00', ts_unix,'unixepoch')
    to bucket by time. Payload blobs are returned hex-encoded. Max 500 rows."""
    return kisslib.run_sql(sql)


class TokenAuth:
    """ASGI middleware requiring a bearer token (or ?token=) on HTTP requests.
    Enabled when MCP_TOKEN is set; lifespan/other scopes pass through."""

    def __init__(self, app, token):
        self.app = app
        self.expected = "Bearer " + token
        self.token = token

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = dict(scope.get("headers") or [])
            auth = headers.get(b"authorization", b"").decode()
            qs = scope.get("query_string", b"").decode()
            qtok = ""
            for part in qs.split("&"):
                if part.startswith("token="):
                    qtok = part[6:]
            if auth != self.expected and qtok != self.token:
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type", b"text/plain"),
                                        (b"www-authenticate", b"Bearer")]})
                await send({"type": "http.response.body", "body": b"unauthorized\n"})
                return
        await self.app(scope, receive, send)


if __name__ == "__main__":
    token = os.environ.get("MCP_TOKEN", "").strip()
    if token:
        import uvicorn
        app = TokenAuth(mcp.streamable_http_app(), token)
        uvicorn.run(app, host=mcp.settings.host, port=mcp.settings.port,
                    log_level="warning")
    else:
        # no token configured -> run unauthenticated (LAN use)
        mcp.run(transport="streamable-http")
