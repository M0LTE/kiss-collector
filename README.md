# kiss-collector

Capture, browse, and query AX.25 packet-radio traffic from
[kissproxy](https://github.com/packet-net/kissproxy).

`kiss-collector` subscribes to a kissproxy MQTT feed, stores every frame in a
lightweight **SQLite database per reporting host**, and gives you three ways to
work with it:

- **Collector** – an MQTT → SQLite daemon (no database server needed).
- **Web UI** – a live tail with AX.25 callsign decoding, search/filter,
  per-band stats, and a PCAP exporter.
- **MCP server** – ask questions about the traffic in natural language from any
  [Model Context Protocol](https://modelcontextprotocol.io) client (Claude etc).

It's intentionally small: Python 3 + `paho-mqtt` + `Flask` + the standard
library `sqlite3`, plus the `mcp` SDK for the MCP server.

## How it works

kissproxy publishes each KISS frame to:

```
kissproxy/<host>/<band>/<direction>/<framing>/<port>/<frameType>
e.g.  kissproxy/gb7rdg-node/6m/fromModem/unframed/port0/DataFrameKissCmd
```

| level | meaning |
|-------|---------|
| `<host>` | reporting host → one SQLite file per host (`<host>.db`) |
| `<band>` | kissproxy instance id, e.g. `2m`, `6m`, `40m`, `70cm` |
| `<direction>` | `fromModem` (received / **RX**) or `toModem` (transmitted / **TX**) |
| `<framing>` | `framed` / `unframed` / `decoded` — collector stores **`unframed`** |
| `<port>` | TNC port, e.g. `port0` |
| `<frameType>` | KISS command, see below |

The message payload is the raw bytes of the (un-KISSed) AX.25 frame.

### Frame types

The last topic level is `<KissCommandCode>KissCmd`:

| topic | byte | meaning |
|-------|------|---------|
| `DataFrameKissCmd` | 0x00 | AX.25 data frame (the actual packet) |
| `TxDelayKissCmd` | 0x01 | TX keyup delay |
| `PersistenceKissCmd` | 0x02 | p-persistence CSMA parameter |
| `SlotTimeKissCmd` | 0x03 | CSMA slot time |
| `TxTailKissCmd` | 0x04 | TX tail |
| `FullDuplexKissCmd` | 0x05 | full/half duplex |
| `SetHardwareKissCmd` | 0x06 | TNC-specific hardware config |
| `AckModeKissCmd` | 0x0C | acknowledged (multi-drop) KISS — carries a 2-byte sequence |
| `ReturnKissCmd` | 0xFF | exit KISS mode |

All types are stored. AckMode frames carry a 2-byte sequence prefix that is
stripped before AX.25 decoding.

### ACKMODE transmit timing

When transmitting in acknowledged KISS mode, kissproxy also publishes timing to
`kissproxy/<host>/<band>/timing/ackmode` (JSON: sequence, queued/ack times,
airtime, total time). When the receipt arrives the collector stamps the **tx
time** (queue-to-ack) and airtime directly onto the originating outbound frame
(matched by KISS sequence number), and keeps the full detail in an `ack_timing`
table. The web UI / MCP hide the bare ACK frames.

## Install

On a Debian/Ubuntu host or container (run as root):

```bash
git clone https://github.com/m0lte/kiss-collector
cd kiss-collector
MQTT_HOST=mqtt.lan ./install.sh
```

This installs to `/opt/kisscollector`, writes databases to
`/var/lib/kisscollector`, and enables three services:

| service | port | purpose |
|---------|------|---------|
| `kisscollector` | – | MQTT → SQLite collector |
| `kisscollector-web` | 8080 | web UI |
| `kisscollector-mcp` | 8765 | MCP server (`/mcp`) |

Configuration is via environment variables in the unit files: `MQTT_HOST`,
`MQTT_PORT`, `MQTT_TOPIC`, `KISS_DB_DIR`, `WEB_PORT`, `MCP_HOST`, `MCP_PORT`.

## Web UI

`http://<host>:8080` — live tail (UTC time, host, band, from, to, via, dir,
AX.25 type, length, tx time). Click a row for the decoded info text and hex.
Filter by host/band/direction/port/frame-type/callsign/free-text, view per-band
**Stats**, and export a time range to a Wireshark-compatible **PCAP**
(`LINKTYPE_AX25`, compatible with
[M0LTE/Ax25Mqtt2pcap](https://github.com/M0LTE/Ax25Mqtt2pcap)).

## MCP server

Add `http://<host>:8765/mcp` to your MCP client as a streamable-HTTP server,
then ask questions like *"who did GB7RDG talk to in the last hour?"* or
*"busiest band today?"*. Tools:

- `overview()` – hosts, bands, frame types, totals, time range
- `search_traffic(...)` – decoded frames by callsign / band / direction / time / text
- `top_talkers(by, ...)` – most active source or destination callsigns
- `activity(bucket, ...)` – frame counts per hour/day
- `stats(...)` – per-band summary and top talkers
- `tx_timing(...)` – ACKMODE transmit timing (airtime, queue-to-ack) per TX frame
- `run_sql(sql)` – read-only SQL over a unified view of all hosts' data

The MCP server speaks in human terms: directions are **RX**/**TX** (not
fromModem/toModem) and frame types use native KISS command names (**DataFrame**,
not DataFrameKissCmd).

### Authentication

By default the server is unauthenticated (fine on a trusted LAN). To require a
token, create `/etc/kisscollector-mcp.env`:

```
MCP_TOKEN=your-long-random-secret
```

and restart `kisscollector-mcp`. Clients must then send
`Authorization: Bearer your-long-random-secret` (or append `?token=...` to the
URL for clients that can't set headers). Requests without it get `401`.

### External access (Tailscale Funnel)

To reach it from outside the LAN without opening router ports, run Tailscale in
the container (userspace mode works in an unprivileged LXC) and expose the
server with [Funnel](https://tailscale.com/kb/1223/funnel) — free, with an
automatic HTTPS certificate:

```bash
tailscale up
tailscale funnel --bg 8765
# -> https://<node>.<tailnet>.ts.net/mcp
```

**Always set `MCP_TOKEN` before enabling Funnel** — Funnel is public internet.

Add to Claude Code with:

```bash
claude mcp add --transport http kiss-collector \
  https://<node>.<tailnet>.ts.net/mcp \
  --header "Authorization: Bearer <token>"
```

## Layout

```
collector.py   MQTT -> per-host SQLite daemon
webui.py       Flask web UI
mcpserver.py   MCP server
kisslib.py     shared AX.25 decode, SQLite access, query helpers
systemd/       unit files
install.sh     installer
```

## License

MIT — see [LICENSE](LICENSE). 73 de M0LTE.
