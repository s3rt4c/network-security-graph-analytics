[← Back to README](../README.md)

# Traffic Ingestion, Aggregation & Graph Data Model

This document details the network traffic input formats, deterministic aggregation semantics, Neo4j graph property schema, metric availability modes, and analysis boundaries implemented in the system.

---

## Traffic Input Formats

The parser (`src/ingestion/traffic_parser.py`) supports two distinct TSV formats:

### 1. Basic / Legacy Format (7-Column TSV)
A backward-compatible 7-column tab-separated format (headerless or with header):
```tsv
eth.src    eth.dst    ip.src    ip.dst    -    -    protocol
```
- Ingests Layer 2 MAC addresses, IPv4/IPv6 endpoints, and dissector protocol labels.
- Detailed volume metrics (`observed_packet_count`, `observed_bytes`, `observed_window_seconds`, transport ports) default to `None` (`traffic_metrics_mode = "basic"`).

### 2. Enriched Format (Project-Defined Enriched tshark TSV Profile)
A headered TSV export generated from packet analysis tools (such as Wireshark / tshark):
```tsv
frame.number    frame.time_epoch    frame.len    eth.src    eth.dst    ip.src    ip.dst    ipv6.src    ipv6.dst    _ws.col.Protocol    tcp.srcport    tcp.dstport    udp.srcport    udp.dstport
```

#### Enriched Field Semantics:
- **`frame.number`** *(optional / recommended)*: Packet index used for duplicate observation tracking.
- **`frame.time_epoch`** *(required in enriched mode)*: Floating-point observation epoch timestamp used to compute `first_seen`, `last_seen`, and `observed_window_seconds`.
- **`frame.len`** *(required in enriched mode)*: Reported wire frame length in bytes, summed into `observed_bytes`.
- **`eth.src` / `eth.dst`**: Layer 2 Ethernet hardware MAC addresses or resolved identifiers.
- **`ip.src` / `ip.dst`**: IPv4 endpoints (coalesced with IPv6; ambiguous rows containing both are skipped).
- **`ipv6.src` / `ipv6.dst`**: IPv6 endpoints (canonicalized to RFC 5952 lowercase compressed format).
- **`_ws.col.Protocol`** *(or `protocol`)*: Dissector protocol label (e.g. `TLS`, `HTTP`, `DNS`, `TCP`, `ICMP`).
- **`tcp.srcport` / `tcp.dstport` / `udp.srcport` / `udp.dstport`**: Transport-layer port numbers extracted independently of upper-layer dissector protocol labels.

---

## Aggregation Model

Packet observations sharing the same directional 5-tuple are deterministically aggregated into a single `TrafficRecord`:

- **Canonical Identity Tuple:** `(canonical src_ip, canonical dst_ip, normalized protocol, src_port, dst_port)`
- **`flow_key`:** Deterministic SHA-256 digest of the canonical JSON-serialized identity payload matching [`compute_flow_key`](../src/ingestion/models.py):
  ```python
  canonical_payload = {
      "src_ip": canonicalize_ip(ip_src),
      "dst_ip": canonicalize_ip(ip_dst),
      "protocol": protocol.strip().upper() if protocol else "UNKNOWN",
      "src_port": src_port if src_port is not None else "null",
      "dst_port": dst_port if dst_port is not None else "null",
  }
  serialized = json.dumps(
      canonical_payload,
      sort_keys=True,
      separators=(",", ":"),
      ensure_ascii=False,
  )
  flow_key = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
  ```
- **Volume Metrics:** Sum of packet observations (`observed_packet_count`) and sum of wire frame bytes (`observed_bytes`).
- **Time Bounds:** Earliest observation (`first_seen`), latest observation (`last_seen`), and window duration (`observed_window_seconds = last_seen - first_seen`).
- **Layer 2 Associations:** Distinct `(eth_src, eth_dst)` pairs observed across packet records with the same 5-tuple are collected into `observed_l2_pairs` and written as `:OBSERVED_WITH` and `:L2_COMMUNICATED_TO` relationships.
- **Parallel Relationships:** Distinct source ports to the same destination IP and port produce separate, parallel `COMMUNICATED_TO` relationships in Neo4j.

---

## Scoped IP Identity & Routing Domains

To support modern segmented networks and multi-tenant telemetry without false-positive node collisions:

- **Scoped Identity Format:** `{domain}#{canonical_ip}` (e.g. `corp#10.0.0.5`, `branch#10.0.0.5`).
- **Domain Assignment:** Every IP belongs to a `(:RoutingDomain)` node via an `[:IN_DOMAIN]` relationship.
- **Default Domain:** Datasets ingested without an explicit routing domain ID default to `"default"`.
- **Overlapping RFC 1918 Isolation:** Hosts in separate routing domains sharing identical private IPv4 addresses (such as `10.0.0.1` or `192.168.1.1`) are represented as independent `:IPAddress` nodes with separate topologies, metrics, and alert facts.
- **Domain-Aware Alert Fact Keys:** Hashing in `compute_alert_fact_key(alert, domain_id)` isolates alert facts across domains while preserving byte-identical digests for the `"default"` domain:
  ```python
  canonical_payload = {
      "src_ip": canonicalize_ip(alert.src_ip),
      "dst_ip": canonicalize_ip(alert.dst_ip),
      "sid": alert.sid,
      "gid": alert.gid,
      "rev": alert.rev,
      "message": alert.message,
      "priority": alert.priority,
      "protocol": alert.protocol,
      "src_port": alert.src_port,
      "dst_port": alert.dst_port,
  }
  if norm_domain != "default":
      canonical_payload["routing_domain_id"] = norm_domain
  ```

---

## Neo4j Graph Model

### Graph Schema

```
                                 (:RoutingDomain)
                              {domain_id: str (UQ)}
                                    ▲       ▲
                                    │       │ [:IN_DOMAIN]
                       [:IN_DOMAIN] │       │
                                    │       │
                   (:Layer2Identifier)      │
                  {identifier: str (UQ)}    │
                            ▲               │
                            │ [:OBSERVED_WITH]
                            │               │
      (src:IPAddress) ──────────────[:COMMUNICATED_TO]─────────────▶ (dst:IPAddress)
    {scoped_id: str (UQ), {flow_key: str,                        {scoped_id: str (UQ),
     address: str (IDX),   protocol: str,                         address: str (IDX),
     routing_domain_id}    src_port: int | None,                  routing_domain_id}
            │              dst_port: int | None,                           ▲
            │              observed_packet_count: int | None,              │
            │              observed_bytes: int | None,                     │
            │              first_seen: float | None,                       │
            │              last_seen: float | None,                        │
            │              observed_window_seconds: float | None}          │
            │                                                              │
            │ [:SOURCE_OF]                                                 │
            ▼                                                              │
       (:AlertFact) ──────────────────────────────────[:TARGETS]───────────┘
      {fact_key: str (UQ),
       routing_domain_id: str,
       sid: int | None,
       gid: int | None,
       rev: int | None,
       message: str | None,
       priority: int | None,
       protocol: str | None,
       src_port: int | None,
       dst_port: int | None}
```

```
Layer 2 Frame Topology:
(:Layer2Identifier) ──[:L2_COMMUNICATED_TO {protocol: str}]──▶ (:Layer2Identifier)

Discrete Zeek Connection Observations (Phase 3A.2):
(:FlowObservation {observation_id: str (UQ), ...})
    ├──[:HAS_ORIGINATOR]──▶ (orig:IPAddress {scoped_id: str (UQ)})
    └──[:HAS_RESPONDER]───▶ (resp:IPAddress {scoped_id: str (UQ)})

Discrete Suricata Alert Events & Rules (Phase 3B.2):
(:AlertEvent {event_id: str (UQ), ...})
    ├──[:TRIGGERED_RULE]───▶ (:AlertDefinition {definition_id: str (UQ), engine, ruleset_namespace, gid, sid})
    ├──[:HAS_SOURCE]───────▶ (src:IPAddress {scoped_id: str (UQ)})
    └──[:HAS_DESTINATION]──▶ (dst:IPAddress {scoped_id: str (UQ)})
```

### Node Entities
- **`:RoutingDomain`**: Logical routing context or network segment domain. Unique constraint on `domain_id`.
- **`:IPAddress`**: Scoped IPv4 or canonicalized IPv6 endpoint. Unique constraint on `scoped_id`. Non-unique index on `address`.
- **`:Layer2Identifier`**: Observed Layer 2 hardware MAC address or resolved identifier. Unique constraint on `identifier`.
- **`:AlertFact`**: Unique normalized alert fact binding source, target, and security rule metadata within a routing domain. Unique constraint on `fact_key`.
- **`:FlowObservation`**: Discrete, immutable telemetry connection observation (e.g., Zeek `conn.log`). Unique constraint on `observation_id`; non-unique lookup indexes on `community_id`, `sensor_id`, `routing_domain_id`, and exact integer `start_epoch_ns`. Retains exact lossless decimal timestamp strings (`start_ts`, `end_ts`, `start_epoch_decimal`, `end_epoch_decimal`, `duration_decimal`) and distinct directional originator/responder payload vs IP-level metrics (`orig_bytes`/`resp_bytes`, `orig_ip_bytes`/`resp_ip_bytes`, `orig_pkts`/`resp_pkts`, `missed_bytes`). Distinct from `COMMUNICATED_TO` aggregates.
- **`:AlertDefinition`**: Static rule/signature identity node (`definition_id` unique constraint). Stores strictly immutable identity fields (`definition_id`, `engine`, `ruleset_namespace`, `gid`, `sid`), leaving mutable rule metadata (`rev`, `signature`, `category`, `severity`, `action`) on individual `:AlertEvent` occurrences.
- **`:AlertEvent`**: Discrete, immutable Suricata alert firing occurrence (`event_id` unique constraint; lookup indexes on `flow_key`, `community_id`, `flow_id`, `sensor_id`, `routing_domain_id`, `timestamp_epoch_ns`). Preserves verbatim `timestamp_source`, lossless `timestamp_epoch_decimal`, optional signed int64 `timestamp_epoch_ns`, canonical unsigned decimal string `flow_id`, and `payload_digest` conflict protection. Distinct from V1 `:AlertFact`.

### Relationship Entities
- **`(:IPAddress)-[:IN_DOMAIN]->(:RoutingDomain)`**: Logical membership connecting an IP address to its routing domain.
- **`(:IPAddress)-[:COMMUNICATED_TO]->(:IPAddress)`**: Directional Layer 3 communication aggregate. Contains `flow_key`, `protocol`, transport ports, and volume metrics when ingested from enriched data.
- **`(:Layer2Identifier)-[:L2_COMMUNICATED_TO {protocol}]->(:Layer2Identifier)`**: Directional Layer 2 frame communication topology.
- **`(:IPAddress)-[:OBSERVED_WITH]->(:Layer2Identifier)`**: Observed Layer 2 / Layer 3 association in captured traffic.
- **`(:IPAddress)-[:SOURCE_OF]->(:AlertFact)`**: Connects the initiator/source IP to the alert fact.
- **`(:AlertFact)-[:TARGETS]->(:IPAddress)`**: Connects the alert fact to the destination/target IP.
- **`(:FlowObservation)-[:HAS_ORIGINATOR]->(:IPAddress)`**: Connects a discrete flow observation to its domain-scoped originator IP.
- **`(:FlowObservation)-[:HAS_RESPONDER]->(:IPAddress)`**: Connects a discrete flow observation to its domain-scoped responder IP.
- **`(:AlertEvent)-[:TRIGGERED_RULE]->(:AlertDefinition)`**: Links a discrete alert firing event to its static rule definition.
- **`(:AlertEvent)-[:HAS_SOURCE]->(:IPAddress)`**: Links a discrete alert event to its domain-scoped source IP.
- **`(:AlertEvent)-[:HAS_DESTINATION]->(:IPAddress)`**: Links a discrete alert event to its domain-scoped destination IP.

---

## Metric Availability Modes

The API and web dashboard categorize traffic metric availability into four explicit modes:

| Mode | Description | Volume Properties Behavior |
|---|---|---|
| **`none`** | No communication aggregates exist in the active workspace. | Metrics unavailable. |
| **`basic`** | Traffic exists, but detailed measurements are absent (legacy TSV). | Packets, frame bytes, timestamps, and ports are `None`. |
| **`enriched`** | All communication aggregates have complete Phase 7 measurements. | Full volume, port, and timestamp metrics are available. |
| **`mixed`** | Both basic and enriched aggregates coexist in the graph. | Global totals and timestamp spans reflect only the enriched subset. |

---

## Semantic & Analysis Boundaries

To ensure analytical integrity and prevent misinterpretation of graph data:

1. **Directional Communication Aggregate (`COMMUNICATED_TO`):** Represents an observed directional aggregation identified by `(src_ip, dst_ip, protocol, src_port, dst_port)`. It is **not** a reconstructed TCP session or connection state machine.
2. **Observed Frame Bytes (`observed_bytes`):** Sum of reported `frame.len` values across aggregated observations. It reflects total wire frame/protocol bytes including headers, **not** application payload bytes.
3. **Observation Window (`observed_window_seconds`):** Difference between `last_seen` and `first_seen` observation timestamps. It is **not** an active session duration.
4. **Correlation vs Causation:** Traffic/alert correlation represents endpoint co-occurrence in captured data and does **not** prove causality.
5. **Source / Target Semantics:** Directional endpoints reflect communication orientation and do **not** infer attacker or victim roles.
6. **Port Context:** Transport ports reflect observed packet headers and do **not** verify the active service or daemon running on the host.
7. **Cardinality Rankings:** Fan-out and fan-in metrics reflect factual peer counts and volume distributions; they do **not** generate automated scan verdicts, maliciousness scores, or C2/beaconing inferences.
