"""
Neo4j Graph Read Repository.

Implements query execution for the Phase 4 FastAPI backend using managed read
transactions (session.execute_read) on a shared Neo4j Driver. All Cypher queries
are parameterized, fully materialized within transaction callbacks, and return
plain Python primitives/dictionaries.
Supports V2 scoped IP identities and explicit ambiguity detection across RoutingDomains.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple, Union

from src.ingestion.v2_models import scoped_ip_id

logger = logging.getLogger(__name__)

_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1


class AmbiguousEndpointError(ValueError):
    """Raised when an address-only query matches multiple endpoints across different routing domains."""

    def __init__(self, address: str, matching_domains: List[str], matching_scoped_ids: List[str]):
        super().__init__(
            f"Address '{address}' is ambiguous: matches multiple endpoints across routing domains "
            f"{matching_domains} ({matching_scoped_ids}). Specify 'domain' or 'scoped_id' to disambiguate."
        )
        self.address = address
        self.matching_domains = matching_domains
        self.matching_scoped_ids = matching_scoped_ids


class Neo4jReadRepository:
    """Read-only repository for querying the network traffic and security alert graph."""

    def __init__(self, driver):
        self.driver = driver

    def check_connectivity(self) -> bool:
        """Verify Neo4j database connectivity.
        
        Returns True if database is reachable, False otherwise.
        """
        if self.driver is None:
            return False
        try:
            self.driver.verify_connectivity()
            return True
        except Exception as exc:
            logger.warning("Neo4j connectivity check failed: %s", exc)
            return False

    @staticmethod
    def _resolve_endpoint(
        tx,
        address: str,
        domain: Optional[str] = None,
        scoped_id: Optional[str] = None,
    ) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """Resolve an endpoint to (scoped_id, address, domain_id).

        Semantics:
        A. scoped_id supplied -> deterministic lookup
        B. address + domain supplied -> deterministic lookup
        C. address supplied and exactly one matching IP exists -> return it
        D. address supplied and multiple IP nodes match -> raise AmbiguousEndpointError

        Returns:
            Tuple of (scoped_id, address, domain_id) or (None, None, None) if not found.
        """
        if scoped_id:
            res = tx.run(
                "MATCH (ip:IPAddress {scoped_id: $scoped_id}) "
                "RETURN ip.scoped_id AS scoped_id, ip.address AS address, ip.routing_domain_id AS domain_id",
                scoped_id=scoped_id,
            )
            rec = res.single()
            if not rec:
                return None, None, None
            return rec.get("scoped_id"), rec.get("address") or address, rec.get("domain_id")

        norm_domain = domain.strip().lower() if domain and domain.strip() else None
        if norm_domain:
            target_scoped = scoped_ip_id(norm_domain, address)
            res = tx.run(
                "MATCH (ip:IPAddress {scoped_id: $scoped_id}) "
                "RETURN ip.scoped_id AS scoped_id, ip.address AS address, ip.routing_domain_id AS domain_id",
                scoped_id=target_scoped,
            )
            rec = res.single()
            if not rec:
                # Also try matching by address and domain property directly
                res2 = tx.run(
                    "MATCH (ip:IPAddress {address: $address, routing_domain_id: $domain}) "
                    "RETURN ip.scoped_id AS scoped_id, ip.address AS address, ip.routing_domain_id AS domain_id",
                    address=address,
                    domain=norm_domain,
                )
                rec2 = res2.single()
                if not rec2:
                    return None, None, None
                return rec2.get("scoped_id"), rec2.get("address") or address, rec2.get("domain_id") or norm_domain
            return rec.get("scoped_id") or target_scoped, rec.get("address") or address, rec.get("domain_id") or norm_domain

        # Only address is supplied
        check_res = tx.run(
            "MATCH (ip:IPAddress {address: $address}) "
            "RETURN count(ip) AS c, "
            "       collect(ip.scoped_id) AS matching_scoped_ids, "
            "       collect(ip.routing_domain_id) AS matching_domains",
            address=address,
        )
        rec = check_res.single()
        if not rec or rec.get("c") == 0:
            return None, None, None

        matching_domains = [d for d in (rec.get("matching_domains") or []) if d is not None]
        matching_scoped_ids = [s for s in (rec.get("matching_scoped_ids") or []) if s is not None]
        distinct_domains = sorted(set(matching_domains))

        c_val = rec.get("c")
        if (c_val is not None and c_val > 1) or len(distinct_domains) > 1:
            raise AmbiguousEndpointError(
                address=address,
                matching_domains=distinct_domains or ["default"],
                matching_scoped_ids=matching_scoped_ids,
            )

        resolved_scoped = matching_scoped_ids[0] if matching_scoped_ids else None
        resolved_domain = matching_domains[0] if matching_domains else None
        return resolved_scoped, address, resolved_domain

    def list_ips(self, limit: int = 50, offset: int = 0, domain: Optional[str] = None) -> Tuple[List[Dict[str, Any]], int]:
        """List observed IP addresses with pagination, optionally filtered by routing domain."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        norm_domain = domain.strip().lower() if domain and domain.strip() else None

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            if norm_domain:
                count_res = tx.run(
                    "MATCH (ip:IPAddress) WHERE ip.routing_domain_id = $domain RETURN count(ip) AS total",
                    domain=norm_domain,
                )
                total = count_res.single()["total"]

                page_res = tx.run(
                    "MATCH (ip:IPAddress) "
                    "WHERE ip.routing_domain_id = $domain "
                    "RETURN ip.address AS address, ip.scoped_id AS scoped_id, ip.routing_domain_id AS routing_domain_id "
                    "ORDER BY ip.address ASC, ip.scoped_id ASC "
                    "SKIP $offset LIMIT $limit",
                    domain=norm_domain,
                    offset=offset,
                    limit=limit,
                )
            else:
                count_res = tx.run("MATCH (ip:IPAddress) RETURN count(ip) AS total")
                total = count_res.single()["total"]

                page_res = tx.run(
                    "MATCH (ip:IPAddress) "
                    "RETURN ip.address AS address, ip.scoped_id AS scoped_id, ip.routing_domain_id AS routing_domain_id "
                    "ORDER BY ip.address ASC, ip.scoped_id ASC "
                    "SKIP $offset LIMIT $limit",
                    offset=offset,
                    limit=limit,
                )
            items = [
                {
                    "address": record["address"],
                    "scoped_id": record.get("scoped_id"),
                    "routing_domain_id": record.get("routing_domain_id"),
                }
                for record in page_res
            ]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_ip_detail(
        self,
        address: str,
        domain: Optional[str] = None,
        scoped_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve local graph context, associated Layer 2 identifiers, flow counts, and volume metrics for an IP."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        cypher = """
        MATCH (ip:IPAddress)
        WHERE (
            ($scoped_id IS NOT NULL AND ip.scoped_id = $scoped_id)
            OR ($scoped_id IS NULL AND ip.address = $address AND ($domain IS NULL OR ip.routing_domain_id = $domain))
        )
        CALL {
            WITH ip
            OPTIONAL MATCH (ip)-[out_c:COMMUNICATED_TO]->(out_peer:IPAddress)
            RETURN count(out_c) AS outbound_aggs,
                   count(DISTINCT out_peer) AS distinct_outbound_peers,
                   count(DISTINCT out_c.dst_port) AS distinct_destination_ports,
                   count(CASE WHEN out_c.observed_packet_count IS NOT NULL
                                   AND out_c.observed_bytes IS NOT NULL
                                   AND out_c.first_seen IS NOT NULL
                                   AND out_c.last_seen IS NOT NULL
                                   AND out_c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS outbound_enriched_aggs,
                   sum(out_c.observed_packet_count) AS raw_pkts_sent,
                   sum(out_c.observed_bytes) AS raw_bytes_sent,
                   min(out_c.first_seen) AS min_out_first,
                   max(out_c.last_seen) AS max_out_last
        }
        CALL {
            WITH ip
            OPTIONAL MATCH (in_peer:IPAddress)-[in_c:COMMUNICATED_TO]->(ip)
            RETURN count(in_c) AS inbound_aggs,
                   count(DISTINCT in_peer) AS distinct_inbound_peers,
                   count(CASE WHEN in_c.observed_packet_count IS NOT NULL
                                   AND in_c.observed_bytes IS NOT NULL
                                   AND in_c.first_seen IS NOT NULL
                                   AND in_c.last_seen IS NOT NULL
                                   AND in_c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS inbound_enriched_aggs,
                   sum(in_c.observed_packet_count) AS raw_pkts_recv,
                   sum(in_c.observed_bytes) AS raw_bytes_recv,
                   min(in_c.first_seen) AS min_in_first,
                   max(in_c.last_seen) AS max_in_last
        }
        RETURN ip.address AS address,
               ip.scoped_id AS scoped_id,
               ip.routing_domain_id AS routing_domain_id,
               COLLECT {
                   MATCH (ip)-[:OBSERVED_WITH]->(l2:Layer2Identifier)
                   RETURN l2.identifier ORDER BY l2.identifier ASC
               } AS layer2_identifiers,
               outbound_aggs,
               inbound_aggs,
               distinct_outbound_peers,
               distinct_inbound_peers,
               distinct_destination_ports,
               outbound_enriched_aggs,
               inbound_enriched_aggs,
               CASE WHEN outbound_enriched_aggs > 0 THEN raw_pkts_sent ELSE null END AS observed_packets_sent,
               CASE WHEN inbound_enriched_aggs > 0 THEN raw_pkts_recv ELSE null END AS observed_packets_received,
               CASE WHEN outbound_enriched_aggs > 0 THEN raw_bytes_sent ELSE null END AS observed_bytes_sent,
               CASE WHEN inbound_enriched_aggs > 0 THEN raw_bytes_recv ELSE null END AS observed_bytes_received,
               CASE WHEN outbound_enriched_aggs > 0 OR inbound_enriched_aggs > 0
                    THEN (CASE WHEN min_out_first IS NOT NULL AND min_in_first IS NOT NULL
                               THEN (CASE WHEN min_out_first < min_in_first THEN min_out_first ELSE min_in_first END)
                               ELSE coalesce(min_out_first, min_in_first) END)
                    ELSE null END AS first_observed,
               CASE WHEN outbound_enriched_aggs > 0 OR inbound_enriched_aggs > 0
                    THEN (CASE WHEN max_out_last IS NOT NULL AND max_in_last IS NOT NULL
                               THEN (CASE WHEN max_out_last > max_in_last THEN max_out_last ELSE max_in_last END)
                               ELSE coalesce(max_out_last, max_in_last) END)
                    ELSE null END AS last_observed,
               COUNT { MATCH (ip)-[:SOURCE_OF]->(:AlertFact) } AS alerts_originated,
               COUNT { MATCH (:AlertFact)-[:TARGETS]->(ip) } AS alerts_targeted
        """

        def _work(tx) -> Optional[Dict[str, Any]]:
            scoped_id_val, addr_val, dom_val = self._resolve_endpoint(tx, address=address, domain=domain, scoped_id=scoped_id)
            if addr_val is None:
                return None

            res = tx.run(cypher, address=addr_val, scoped_id=scoped_id_val, domain=dom_val)
            record = res.single()
            if not record:
                return None

            out_aggs = int(record["outbound_aggs"])
            in_aggs = int(record["inbound_aggs"])
            tot_aggs = out_aggs + in_aggs
            enr_aggs = int(record["outbound_enriched_aggs"]) + int(record["inbound_enriched_aggs"])

            if tot_aggs == 0:
                mode = "none"
            elif enr_aggs == 0:
                mode = "basic"
            elif enr_aggs == tot_aggs:
                mode = "enriched"
            else:
                mode = "mixed"

            return {
                "address": record["address"],
                "scoped_id": record.get("scoped_id"),
                "routing_domain_id": record.get("routing_domain_id"),
                "layer2_identifiers": [str(x) for x in record["layer2_identifiers"]],
                "outbound_flows": out_aggs,
                "inbound_flows": in_aggs,
                "alerts_originated": int(record["alerts_originated"]),
                "alerts_targeted": int(record["alerts_targeted"]),
                "traffic_metrics_mode": mode,
                "distinct_outbound_peers": int(record["distinct_outbound_peers"]),
                "distinct_inbound_peers": int(record["distinct_inbound_peers"]),
                "distinct_destination_ports": int(record["distinct_destination_ports"]),
                "observed_packets_sent": int(record["observed_packets_sent"]) if record["observed_packets_sent"] is not None else None,
                "observed_packets_received": int(record["observed_packets_received"]) if record["observed_packets_received"] is not None else None,
                "observed_bytes_sent": int(record["observed_bytes_sent"]) if record["observed_bytes_sent"] is not None else None,
                "observed_bytes_received": int(record["observed_bytes_received"]) if record["observed_bytes_received"] is not None else None,
                "first_observed": float(record["first_observed"]) if record["first_observed"] is not None else None,
                "last_observed": float(record["last_observed"]) if record["last_observed"] is not None else None,
            }

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_traffic_analytics_summary(self) -> Dict[str, Any]:
        """Retrieve overall traffic analytics summary and distribution metrics."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        def _work(tx) -> Dict[str, Any]:
            summary_cypher = """
            MATCH ()-[c:COMMUNICATED_TO]->()
            WITH count(c) AS total_aggs,
                 count(CASE WHEN c.observed_packet_count IS NOT NULL
                                 AND c.observed_bytes IS NOT NULL
                                 AND c.first_seen IS NOT NULL
                                 AND c.last_seen IS NOT NULL
                                 AND c.observed_window_seconds IS NOT NULL
                            THEN 1 END) AS enriched_aggs,
                 sum(c.observed_packet_count) AS total_pkts,
                 sum(c.observed_bytes) AS total_bytes,
                 min(c.first_seen) AS first_obs,
                 max(c.last_seen) AS last_obs
            RETURN total_aggs, enriched_aggs, total_pkts, total_bytes, first_obs, last_obs
            """
            s_rec = tx.run(summary_cypher).single()
            if not s_rec or s_rec["total_aggs"] == 0:
                return {
                    "traffic_metrics_mode": "none",
                    "total_communication_aggregates": 0,
                    "enriched_communication_aggregates": 0,
                    "basic_communication_aggregates": 0,
                    "total_observed_packets": None,
                    "total_observed_bytes": None,
                    "first_observed": None,
                    "last_observed": None,
                    "protocol_distribution": [],
                    "destination_port_distribution": [],
                    "top_fan_out": [],
                    "top_fan_in": [],
                }

            total_aggs = int(s_rec["total_aggs"])
            enriched_aggs = int(s_rec["enriched_aggs"])
            basic_aggs = total_aggs - enriched_aggs

            if enriched_aggs == 0:
                mode = "basic"
                total_pkts = None
                total_bytes = None
                first_obs = None
                last_obs = None
            elif enriched_aggs == total_aggs:
                mode = "enriched"
                total_pkts = int(s_rec["total_pkts"]) if s_rec["total_pkts"] is not None else None
                total_bytes = int(s_rec["total_bytes"]) if s_rec["total_bytes"] is not None else None
                first_obs = float(s_rec["first_obs"]) if s_rec["first_obs"] is not None else None
                last_obs = float(s_rec["last_obs"]) if s_rec["last_obs"] is not None else None
            else:
                mode = "mixed"
                total_pkts = int(s_rec["total_pkts"]) if s_rec["total_pkts"] is not None else None
                total_bytes = int(s_rec["total_bytes"]) if s_rec["total_bytes"] is not None else None
                first_obs = float(s_rec["first_obs"]) if s_rec["first_obs"] is not None else None
                last_obs = float(s_rec["last_obs"]) if s_rec["last_obs"] is not None else None

            # 2. Protocol Distribution
            proto_cypher = """
            MATCH ()-[c:COMMUNICATED_TO]->()
            RETURN c.protocol AS protocol,
                   count(c) AS agg_count,
                   count(CASE WHEN c.observed_packet_count IS NOT NULL
                                   AND c.observed_bytes IS NOT NULL
                                   AND c.first_seen IS NOT NULL
                                   AND c.last_seen IS NOT NULL
                                   AND c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS enriched_count,
                   sum(c.observed_packet_count) AS pkts,
                   sum(c.observed_bytes) AS bytes
            ORDER BY agg_count DESC, protocol ASC
            """
            proto_res = tx.run(proto_cypher)
            proto_dist = []
            for r in proto_res:
                enr_count = int(r.get('enriched_count', r.get('enr_count', 0)))
                proto_dist.append({
                    "protocol": r["protocol"],
                    "communication_aggregate_count": int(r["agg_count"]),
                    "observed_packet_count": int(r["pkts"]) if enr_count > 0 and r["pkts"] is not None else None,
                    "observed_bytes": int(r["bytes"]) if enr_count > 0 and r["bytes"] is not None else None,
                })

            # 3. Destination Port Distribution
            port_cypher = """
            MATCH ()-[c:COMMUNICATED_TO]->()
            WHERE c.dst_port IS NOT NULL
            RETURN c.dst_port AS dst_port,
                   count(c) AS agg_count,
                   count(CASE WHEN c.observed_packet_count IS NOT NULL
                                   AND c.observed_bytes IS NOT NULL
                                   AND c.first_seen IS NOT NULL
                                   AND c.last_seen IS NOT NULL
                                   AND c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS enriched_count,
                   sum(c.observed_packet_count) AS pkts,
                   sum(c.observed_bytes) AS bytes
            ORDER BY agg_count DESC, dst_port ASC
            LIMIT 10
            """
            port_res = tx.run(port_cypher)
            port_dist = []
            for r in port_res:
                enr_count = int(r.get('enriched_count', r.get('enr_count', 0)))
                port_dist.append({
                    "dst_port": int(r["dst_port"]),
                    "communication_aggregate_count": int(r["agg_count"]),
                    "observed_packet_count": int(r["pkts"]) if enr_count > 0 and r["pkts"] is not None else None,
                    "observed_bytes": int(r["bytes"]) if enr_count > 0 and r["bytes"] is not None else None,
                })

            # 4. Top Fan-out (grouped per scoped IPAddress node so overlapping domains are never merged)
            fan_out_cypher = """
            MATCH (src:IPAddress)-[:COMMUNICATED_TO]->(dst:IPAddress)
            WITH src, count(DISTINCT dst) AS distinct_destination_ips
            ORDER BY distinct_destination_ips DESC, src.address ASC, src.scoped_id ASC
            LIMIT 10
            RETURN src.address AS address, distinct_destination_ips
            """
            fan_out_res = tx.run(fan_out_cypher)
            top_fan_out = [
                {"address": r["address"], "distinct_destination_ips": int(r["distinct_destination_ips"])}
                for r in fan_out_res
            ]

            # 5. Top Fan-in (grouped per scoped IPAddress node so overlapping domains are never merged)
            fan_in_cypher = """
            MATCH (src:IPAddress)-[:COMMUNICATED_TO]->(dst:IPAddress)
            WITH dst, count(DISTINCT src) AS distinct_source_ips
            ORDER BY distinct_source_ips DESC, dst.address ASC, dst.scoped_id ASC
            LIMIT 10
            RETURN dst.address AS address, distinct_source_ips
            """
            fan_in_res = tx.run(fan_in_cypher)
            top_fan_in = [
                {"address": r["address"], "distinct_source_ips": int(r["distinct_source_ips"])}
                for r in fan_in_res
            ]

            return {
                "traffic_metrics_mode": mode,
                "total_communication_aggregates": total_aggs,
                "enriched_communication_aggregates": enriched_aggs,
                "basic_communication_aggregates": basic_aggs,
                "total_observed_packets": total_pkts,
                "total_observed_bytes": total_bytes,
                "first_observed": first_obs,
                "last_observed": last_obs,
                "protocol_distribution": proto_dist,
                "destination_port_distribution": port_dist,
                "top_fan_out": top_fan_out,
                "top_fan_in": top_fan_in,
            }

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_endpoints_analytics(
        self,
        sort_by: str = "fan_out",
        limit: int = 50,
        offset: int = 0,
        domain: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Retrieve factual endpoint analytics and flow metrics with flexible sorting and pagination."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        sort_clauses = {
            "fan_out": "ORDER BY distinct_outbound_peers DESC, address ASC, scoped_id ASC",
            "fan_in": "ORDER BY distinct_inbound_peers DESC, address ASC, scoped_id ASC",
            "observed_bytes_sent": "ORDER BY CASE WHEN observed_bytes_sent IS NULL THEN 1 ELSE 0 END, observed_bytes_sent DESC, address ASC, scoped_id ASC",
            "observed_bytes_received": "ORDER BY CASE WHEN observed_bytes_received IS NULL THEN 1 ELSE 0 END, observed_bytes_received DESC, address ASC, scoped_id ASC",
            "observed_packets_sent": "ORDER BY CASE WHEN observed_packets_sent IS NULL THEN 1 ELSE 0 END, observed_packets_sent DESC, address ASC, scoped_id ASC",
            "observed_packets_received": "ORDER BY CASE WHEN observed_packets_received IS NULL THEN 1 ELSE 0 END, observed_packets_received DESC, address ASC, scoped_id ASC",
            "first_observed": "ORDER BY CASE WHEN first_observed IS NULL THEN 1 ELSE 0 END, first_observed ASC, address ASC, scoped_id ASC",
            "last_observed": "ORDER BY CASE WHEN last_observed IS NULL THEN 1 ELSE 0 END, last_observed DESC, address ASC, scoped_id ASC",
        }
        order_clause = sort_clauses.get(sort_by, sort_clauses["fan_out"])

        norm_domain = domain.strip().lower() if domain and domain.strip() else None
        where_clause = "WHERE ip.routing_domain_id = $domain" if norm_domain else ""
        count_cypher = f"MATCH (ip:IPAddress) {where_clause} RETURN count(ip) AS total"

        page_cypher = f"""
        MATCH (ip:IPAddress)
        {where_clause}
        CALL {{
            WITH ip
            OPTIONAL MATCH (ip)-[out_c:COMMUNICATED_TO]->(out_peer:IPAddress)
            RETURN count(out_c) AS outbound_aggs,
                   count(DISTINCT out_peer) AS distinct_outbound_peers,
                   count(DISTINCT out_c.dst_port) AS distinct_destination_ports,
                   count(CASE WHEN out_c.observed_packet_count IS NOT NULL
                                   AND out_c.observed_bytes IS NOT NULL
                                   AND out_c.first_seen IS NOT NULL
                                   AND out_c.last_seen IS NOT NULL
                                   AND out_c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS outbound_enriched_aggs,
                   sum(out_c.observed_packet_count) AS raw_pkts_sent,
                   sum(out_c.observed_bytes) AS raw_bytes_sent,
                   min(out_c.first_seen) AS min_out_first,
                   max(out_c.last_seen) AS max_out_last
        }}
        CALL {{
            WITH ip
            OPTIONAL MATCH (in_peer:IPAddress)-[in_c:COMMUNICATED_TO]->(ip)
            RETURN count(in_c) AS inbound_aggs,
                   count(DISTINCT in_peer) AS distinct_inbound_peers,
                   count(CASE WHEN in_c.observed_packet_count IS NOT NULL
                                   AND in_c.observed_bytes IS NOT NULL
                                   AND in_c.first_seen IS NOT NULL
                                   AND in_c.last_seen IS NOT NULL
                                   AND in_c.observed_window_seconds IS NOT NULL
                              THEN 1 END) AS inbound_enriched_aggs,
                   sum(in_c.observed_packet_count) AS raw_pkts_recv,
                   sum(in_c.observed_bytes) AS raw_bytes_recv,
                   min(in_c.first_seen) AS min_in_first,
                   max(in_c.last_seen) AS max_in_last
        }}
        WITH ip,
             outbound_aggs, inbound_aggs,
             distinct_outbound_peers, distinct_inbound_peers, distinct_destination_ports,
             outbound_enriched_aggs, inbound_enriched_aggs,
             CASE WHEN outbound_enriched_aggs > 0 THEN raw_pkts_sent ELSE null END AS observed_packets_sent,
             CASE WHEN inbound_enriched_aggs > 0 THEN raw_pkts_recv ELSE null END AS observed_packets_received,
             CASE WHEN outbound_enriched_aggs > 0 THEN raw_bytes_sent ELSE null END AS observed_bytes_sent,
             CASE WHEN inbound_enriched_aggs > 0 THEN raw_bytes_recv ELSE null END AS observed_bytes_received,
             CASE WHEN outbound_enriched_aggs > 0 OR inbound_enriched_aggs > 0
                  THEN (CASE WHEN min_out_first IS NOT NULL AND min_in_first IS NOT NULL
                             THEN (CASE WHEN min_out_first < min_in_first THEN min_out_first ELSE min_in_first END)
                             ELSE coalesce(min_out_first, min_in_first) END)
                  ELSE null END AS first_observed,
             CASE WHEN outbound_enriched_aggs > 0 OR inbound_enriched_aggs > 0
                  THEN (CASE WHEN max_out_last IS NOT NULL AND max_in_last IS NOT NULL
                             THEN (CASE WHEN max_out_last > max_in_last THEN max_out_last ELSE max_in_last END)
                             ELSE coalesce(max_out_last, max_in_last) END)
                  ELSE null END AS last_observed
        RETURN ip.address AS address,
               ip.scoped_id AS scoped_id,
               ip.routing_domain_id AS routing_domain_id,
               outbound_aggs,
               inbound_aggs,
               distinct_outbound_peers,
               distinct_inbound_peers,
               distinct_destination_ports,
               outbound_enriched_aggs,
               inbound_enriched_aggs,
               observed_packets_sent,
               observed_packets_received,
               observed_bytes_sent,
               observed_bytes_received,
               first_observed,
               last_observed
        {order_clause}
        SKIP $offset LIMIT $limit
        """

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            params: Dict[str, Any] = {"offset": offset, "limit": limit}
            if norm_domain:
                params["domain"] = norm_domain
            total = tx.run(count_cypher, **params).single()["total"]
            page_res = tx.run(page_cypher, **params)
            items = []
            for record in page_res:
                out_aggs = int(record["outbound_aggs"])
                in_aggs = int(record["inbound_aggs"])
                tot_aggs = out_aggs + in_aggs
                enr_aggs = int(record["outbound_enriched_aggs"]) + int(record["inbound_enriched_aggs"])

                if tot_aggs == 0:
                    mode = "none"
                elif enr_aggs == 0:
                    mode = "basic"
                elif enr_aggs == tot_aggs:
                    mode = "enriched"
                else:
                    mode = "mixed"

                items.append({
                    "address": record["address"],
                    "scoped_id": record.get("scoped_id"),
                    "routing_domain_id": record.get("routing_domain_id"),
                    "outbound_communication_aggregates": out_aggs,
                    "inbound_communication_aggregates": in_aggs,
                    "distinct_outbound_peers": int(record["distinct_outbound_peers"]),
                    "distinct_inbound_peers": int(record["distinct_inbound_peers"]),
                    "distinct_destination_ports": int(record["distinct_destination_ports"]),
                    "observed_packets_sent": int(record["observed_packets_sent"]) if record["observed_packets_sent"] is not None else None,
                    "observed_packets_received": int(record["observed_packets_received"]) if record["observed_packets_received"] is not None else None,
                    "observed_bytes_sent": int(record["observed_bytes_sent"]) if record["observed_bytes_sent"] is not None else None,
                    "observed_bytes_received": int(record["observed_bytes_received"]) if record["observed_bytes_received"] is not None else None,
                    "first_observed": float(record["first_observed"]) if record["first_observed"] is not None else None,
                    "last_observed": float(record["last_observed"]) if record["last_observed"] is not None else None,
                    "traffic_metrics_mode": mode,
                })
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_ip_peers(
        self,
        address: str,
        direction: str = "all",
        limit: int = 50,
        offset: int = 0,
        domain: Optional[str] = None,
        scoped_id: Optional[str] = None,
    ) -> Optional[Tuple[List[Dict[str, Any]], int]]:
        """List communicating peers and observed protocols for an IP address.
        
        Returns None if the specified IP is not found in the graph.
        """
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        def _work(tx) -> Optional[Tuple[List[Dict[str, Any]], int]]:
            scoped_id_val, addr_val, _ = self._resolve_endpoint(tx, address=address, domain=domain, scoped_id=scoped_id)
            if addr_val is None:
                return None

            match_clause = (
                "MATCH (src:IPAddress {scoped_id: $scoped_id})-[c:COMMUNICATED_TO]->(peer:IPAddress)"
                if scoped_id_val
                else "MATCH (src:IPAddress {address: $address})-[c:COMMUNICATED_TO]->(peer:IPAddress)"
            )
            match_inbound = (
                "MATCH (peer:IPAddress)-[c:COMMUNICATED_TO]->(dst:IPAddress {scoped_id: $scoped_id})"
                if scoped_id_val
                else "MATCH (peer:IPAddress)-[c:COMMUNICATED_TO]->(dst:IPAddress {address: $address})"
            )

            if direction == "outbound":
                subquery = f"""
                {match_clause}
                WITH peer.address AS peer_address, 'outbound' AS dir, collect(DISTINCT c.protocol) AS raw_proto
                RETURN peer_address, dir AS direction, raw_proto
                """
            elif direction == "inbound":
                subquery = f"""
                {match_inbound}
                WITH peer.address AS peer_address, 'inbound' AS dir, collect(DISTINCT c.protocol) AS raw_proto
                RETURN peer_address, dir AS direction, raw_proto
                """
            else:  # "all"
                subquery = f"""
                {match_clause}
                WITH peer.address AS peer_address, 'outbound' AS dir, collect(DISTINCT c.protocol) AS raw_proto
                RETURN peer_address, dir AS direction, raw_proto
                UNION ALL
                {match_inbound}
                WITH peer.address AS peer_address, 'inbound' AS dir, collect(DISTINCT c.protocol) AS raw_proto
                RETURN peer_address, dir AS direction, raw_proto
                """

            params: Dict[str, Any] = {"address": addr_val, "scoped_id": scoped_id_val}
            count_cypher = f"CALL {{ {subquery} }} RETURN count(*) AS total"
            total = tx.run(count_cypher, **params).single()["total"]

            page_cypher = f"""
            CALL {{ {subquery} }}
            RETURN peer_address, direction, raw_proto
            ORDER BY peer_address ASC, direction ASC
            SKIP $offset LIMIT $limit
            """
            params["offset"] = offset
            params["limit"] = limit
            page_res = tx.run(page_cypher, **params)
            items = []
            for r in page_res:
                sorted_protos = sorted(list(set(r["raw_proto"])))
                items.append({
                    "peer_address": r["peer_address"],
                    "direction": r["direction"],
                    "protocols": sorted_protos,
                })
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_ip_layer2(
        self,
        address: str,
        limit: int = 50,
        offset: int = 0,
        domain: Optional[str] = None,
        scoped_id: Optional[str] = None,
    ) -> Optional[Tuple[List[Dict[str, Any]], int]]:
        """List Layer 2 identifiers associated with a specific IP address.
        
        Returns None if the specified IP is not found in the graph.
        """
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        def _work(tx) -> Optional[Tuple[List[Dict[str, Any]], int]]:
            scoped_id_val, addr_val, _ = self._resolve_endpoint(tx, address=address, domain=domain, scoped_id=scoped_id)
            if addr_val is None:
                return None

            match_part = (
                "MATCH (ip:IPAddress {scoped_id: $scoped_id})-[:OBSERVED_WITH]->(l2:Layer2Identifier)"
                if scoped_id_val
                else "MATCH (ip:IPAddress {address: $address})-[:OBSERVED_WITH]->(l2:Layer2Identifier)"
            )
            count_cypher = f"{match_part} RETURN count(l2) AS total"
            params: Dict[str, Any] = {"address": addr_val, "scoped_id": scoped_id_val}
            total = tx.run(count_cypher, **params).single()["total"]

            page_cypher = f"""
            {match_part}
            RETURN l2.identifier AS identifier
            ORDER BY l2.identifier ASC
            SKIP $offset LIMIT $limit
            """
            params["offset"] = offset
            params["limit"] = limit
            page_res = tx.run(page_cypher, **params)
            items = [{"identifier": r["identifier"]} for r in page_res]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_layer2_identifiers(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List all observed Layer 2 identifiers with pagination."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            count_res = tx.run("MATCH (l2:Layer2Identifier) RETURN count(l2) AS total")
            total = count_res.single()["total"]

            page_res = tx.run(
                "MATCH (l2:Layer2Identifier) "
                "RETURN l2.identifier AS identifier "
                "ORDER BY l2.identifier ASC "
                "SKIP $offset LIMIT $limit",
                offset=offset,
                limit=limit,
            )
            items = [{"identifier": record["identifier"]} for record in page_res]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_communications(
        self,
        source_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        protocol: Optional[str] = None,
        src_port: Optional[int] = None,
        dst_port: Optional[int] = None,
        sort_by: str = "identity",
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List Layer 3 directional communications with optional exact-match filtering, sorting, and pagination."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        proto_upper = protocol.strip().upper() if protocol and protocol.strip() else None

        conditions = []
        params: Dict[str, Any] = {"limit": limit, "offset": offset}

        if source_ip is not None:
            conditions.append("src.address = $source_ip")
            params["source_ip"] = source_ip
        if target_ip is not None:
            conditions.append("dst.address = $target_ip")
            params["target_ip"] = target_ip
        if proto_upper is not None:
            conditions.append("c.protocol = $protocol")
            params["protocol"] = proto_upper
        if src_port is not None:
            conditions.append("c.src_port = $src_port")
            params["src_port"] = src_port
        if dst_port is not None:
            conditions.append("c.dst_port = $dst_port")
            params["dst_port"] = dst_port

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        sort_clauses = {
            "identity": """
            ORDER BY src.address ASC, dst.address ASC, c.protocol ASC,
                     CASE WHEN c.src_port IS NULL THEN 1 ELSE 0 END, c.src_port ASC,
                     CASE WHEN c.dst_port IS NULL THEN 1 ELSE 0 END, c.dst_port ASC,
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC,
                     src.scoped_id ASC, dst.scoped_id ASC
            """,
            "observed_bytes": """
            ORDER BY CASE WHEN c.observed_bytes IS NULL THEN 1 ELSE 0 END, c.observed_bytes DESC,
                     src.address ASC, dst.address ASC, c.protocol ASC,
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC,
                     src.scoped_id ASC, dst.scoped_id ASC
            """,
            "observed_packets": """
            ORDER BY CASE WHEN c.observed_packet_count IS NULL THEN 1 ELSE 0 END, c.observed_packet_count DESC,
                     src.address ASC, dst.address ASC, c.protocol ASC,
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC,
                     src.scoped_id ASC, dst.scoped_id ASC
            """,
            "first_seen": """
            ORDER BY CASE WHEN c.first_seen IS NULL THEN 1 ELSE 0 END, c.first_seen ASC,
                     src.address ASC, dst.address ASC, c.protocol ASC,
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC,
                     src.scoped_id ASC, dst.scoped_id ASC
            """,
        }
        order_clause = sort_clauses.get(sort_by, sort_clauses["identity"])

        count_cypher = f"MATCH (src:IPAddress)-[c:COMMUNICATED_TO]->(dst:IPAddress) {where_clause} RETURN count(c) AS total"
        page_cypher = f"""
        MATCH (src:IPAddress)-[c:COMMUNICATED_TO]->(dst:IPAddress)
        {where_clause}
        RETURN src.address AS source_ip,
               dst.address AS target_ip,
               c.protocol AS protocol,
               c.flow_key AS flow_key,
               c.src_port AS src_port,
               c.dst_port AS dst_port,
               c.observed_packet_count AS observed_packet_count,
               c.observed_bytes AS observed_bytes,
               c.first_seen AS first_seen,
               c.last_seen AS last_seen,
               c.observed_window_seconds AS observed_window_seconds
        {order_clause}
        SKIP $offset LIMIT $limit
        """

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            total = tx.run(count_cypher, **params).single()["total"]
            page_res = tx.run(page_cypher, **params)
            items = [
                {
                    "source_ip": r["source_ip"],
                    "target_ip": r["target_ip"],
                    "protocol": r["protocol"],
                    "flow_key": r["flow_key"],
                    "src_port": r["src_port"],
                    "dst_port": r["dst_port"],
                    "observed_packet_count": r["observed_packet_count"],
                    "observed_bytes": r["observed_bytes"],
                    "first_seen": r["first_seen"],
                    "last_seen": r["last_seen"],
                    "observed_window_seconds": r["observed_window_seconds"],
                }
                for r in page_res
            ]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_alert_facts(
        self,
        source_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        priority: Optional[int] = None,
        sid: Optional[int] = None,
        protocol: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List normalized AlertFact entities with optional filtering, deterministic sorting, and pagination."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        proto_upper = protocol.strip().upper() if protocol and protocol.strip() else None

        conditions = []
        params: Dict[str, Any] = {"limit": limit, "offset": offset}

        if source_ip is not None:
            conditions.append("src.address = $source_ip")
            params["source_ip"] = source_ip
        if target_ip is not None:
            conditions.append("dst.address = $target_ip")
            params["target_ip"] = target_ip
        if priority is not None:
            conditions.append("fact.priority = $priority")
            params["priority"] = priority
        if sid is not None:
            conditions.append("fact.sid = $sid")
            params["sid"] = sid
        if proto_upper is not None:
            conditions.append("fact.protocol = $protocol")
            params["protocol"] = proto_upper

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        count_cypher = f"""
        MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress)
        {where_clause}
        RETURN count(fact) AS total
        """

        page_cypher = f"""
        MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress)
        {where_clause}
        RETURN fact.fact_key AS fact_key,
               src.address AS source_ip,
               dst.address AS target_ip,
               fact.sid AS sid,
               fact.gid AS gid,
               fact.rev AS rev,
               fact.message AS message,
               fact.priority AS priority,
               fact.protocol AS protocol,
               fact.src_port AS src_port,
               fact.dst_port AS dst_port
        ORDER BY CASE WHEN fact.priority IS NULL THEN 1 ELSE 0 END, fact.priority ASC,
                 CASE WHEN fact.sid IS NULL THEN 1 ELSE 0 END, fact.sid ASC,
                 fact.fact_key ASC
        SKIP $offset LIMIT $limit
        """

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            total = tx.run(count_cypher, **params).single()["total"]
            page_res = tx.run(page_cypher, **params)
            items = [
                {
                    "fact_key": r["fact_key"],
                    "source_ip": r["source_ip"],
                    "target_ip": r["target_ip"],
                    "sid": r["sid"],
                    "gid": r["gid"],
                    "rev": r["rev"],
                    "message": r["message"],
                    "priority": r["priority"],
                    "protocol": r["protocol"],
                    "src_port": r["src_port"],
                    "dst_port": r["dst_port"],
                }
                for r in page_res
            ]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_alert_fact(self, fact_key: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single normalized AlertFact by its deterministic fact_key."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        cypher = """
        MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact {fact_key: $fact_key})-[:TARGETS]->(dst:IPAddress)
        RETURN fact.fact_key AS fact_key,
               src.address AS source_ip,
               dst.address AS target_ip,
               fact.sid AS sid,
               fact.gid AS gid,
               fact.rev AS rev,
               fact.message AS message,
               fact.priority AS priority,
               fact.protocol AS protocol,
               fact.src_port AS src_port,
               fact.dst_port AS dst_port
        """

        def _work(tx) -> Optional[Dict[str, Any]]:
            res = tx.run(cypher, fact_key=fact_key)
            record = res.single()
            if not record:
                return None
            return {
                "fact_key": record["fact_key"],
                "source_ip": record["source_ip"],
                "target_ip": record["target_ip"],
                "sid": record["sid"],
                "gid": record["gid"],
                "rev": record["rev"],
                "message": record["message"],
                "priority": record["priority"],
                "protocol": record["protocol"],
                "src_port": record["src_port"],
                "dst_port": record["dst_port"],
            }

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_traffic_alert_correlations(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List correlated pairs where traffic communication and an alert fact share endpoints."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        count_cypher = """
        MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress),
              (src)-[c:COMMUNICATED_TO]->(dst)
        WHERE (fact.routing_domain_id IS NULL OR src.routing_domain_id IS NULL OR fact.routing_domain_id = src.routing_domain_id)
        RETURN count(*) AS total
        """

        page_cypher = """
        MATCH (src:IPAddress)-[:SOURCE_OF]->(fact:AlertFact)-[:TARGETS]->(dst:IPAddress),
              (src)-[c:COMMUNICATED_TO]->(dst)
        WHERE (fact.routing_domain_id IS NULL OR src.routing_domain_id IS NULL OR fact.routing_domain_id = src.routing_domain_id)
        RETURN src.address AS source_ip,
               dst.address AS target_ip,
               c.protocol AS traffic_protocol,
               c.flow_key AS traffic_flow_key,
               c.src_port AS traffic_src_port,
               c.dst_port AS traffic_dst_port,
               fact.fact_key AS fact_key,
               fact.sid AS sid,
               fact.message AS message,
               fact.priority AS priority,
               fact.protocol AS alert_protocol
        ORDER BY src.address ASC, dst.address ASC, c.protocol ASC,
                 CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC,
                 fact.fact_key ASC
        SKIP $offset LIMIT $limit
        """

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            total = tx.run(count_cypher).single()["total"]
            page_res = tx.run(page_cypher, offset=offset, limit=limit)
            items = [
                {
                    "source_ip": r["source_ip"],
                    "target_ip": r["target_ip"],
                    "traffic_protocol": r["traffic_protocol"],
                    "traffic_flow_key": r["traffic_flow_key"],
                    "traffic_src_port": r["traffic_src_port"],
                    "traffic_dst_port": r["traffic_dst_port"],
                    "fact_key": r["fact_key"],
                    "sid": r["sid"],
                    "message": r["message"],
                    "priority": r["priority"],
                    "alert_protocol": r["alert_protocol"],
                }
                for r in page_res
            ]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_neighborhood(
        self,
        address: str,
        depth: int = 1,
        max_nodes: int = 50,
        domain: Optional[str] = None,
        scoped_id: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve bounded local graph neighborhood (depth 1 or 2) around an IP address.

        Parallel same-protocol flows with distinct flow_key are preserved.
        Returns None if center IP does not exist. Raises AmbiguousEndpointError if ambiguous.
        """
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        # Select safe fixed Cypher query by validated depth
        if depth == 1:
            cypher = """
            MATCH (center:IPAddress)
            WHERE (
                ($scoped_id IS NOT NULL AND center.scoped_id = $scoped_id)
                OR ($scoped_id IS NULL AND center.address = $address)
            )
            OPTIONAL MATCH (center)-[r1:COMMUNICATED_TO]->(out_ip:IPAddress)
            OPTIONAL MATCH (in_ip:IPAddress)-[r2:COMMUNICATED_TO]->(center)
            OPTIONAL MATCH (center)-[r3:OBSERVED_WITH]->(l2:Layer2Identifier)
            RETURN center.address AS center,
                   collect(DISTINCT {
                       id: CASE WHEN out_ip.routing_domain_id = 'default' OR out_ip.routing_domain_id IS NULL
                                THEN 'ip:' + out_ip.address
                                ELSE 'ip:' + coalesce(out_ip.scoped_id, out_ip.address) END,
                       type: 'IPAddress',
                       value: out_ip.address
                   }) AS out_ips,
                   collect(DISTINCT {
                       id: CASE WHEN in_ip.routing_domain_id = 'default' OR in_ip.routing_domain_id IS NULL
                                THEN 'ip:' + in_ip.address
                                ELSE 'ip:' + coalesce(in_ip.scoped_id, in_ip.address) END,
                       type: 'IPAddress',
                       value: in_ip.address
                   }) AS in_ips,
                   collect(DISTINCT {id: 'l2:' + l2.identifier, type: 'Layer2Identifier', value: l2.identifier}) AS l2_nodes,
                   collect(DISTINCT {
                       source: CASE WHEN center.routing_domain_id = 'default' OR center.routing_domain_id IS NULL
                                    THEN 'ip:' + center.address
                                    ELSE 'ip:' + coalesce(center.scoped_id, center.address) END,
                       target: CASE WHEN out_ip.routing_domain_id = 'default' OR out_ip.routing_domain_id IS NULL
                                    THEN 'ip:' + out_ip.address
                                    ELSE 'ip:' + coalesce(out_ip.scoped_id, out_ip.address) END,
                       type: 'COMMUNICATED_TO',
                       protocol: r1.protocol,
                       flow_key: r1.flow_key,
                       src_port: r1.src_port,
                       dst_port: r1.dst_port,
                       observed_packet_count: r1.observed_packet_count,
                       observed_bytes: r1.observed_bytes,
                       first_seen: r1.first_seen,
                       last_seen: r1.last_seen,
                       observed_window_seconds: r1.observed_window_seconds
                   }) AS out_edges,
                   collect(DISTINCT {
                       source: CASE WHEN in_ip.routing_domain_id = 'default' OR in_ip.routing_domain_id IS NULL
                                    THEN 'ip:' + in_ip.address
                                    ELSE 'ip:' + coalesce(in_ip.scoped_id, in_ip.address) END,
                       target: CASE WHEN center.routing_domain_id = 'default' OR center.routing_domain_id IS NULL
                                    THEN 'ip:' + center.address
                                    ELSE 'ip:' + coalesce(center.scoped_id, center.address) END,
                       type: 'COMMUNICATED_TO',
                       protocol: r2.protocol,
                       flow_key: r2.flow_key,
                       src_port: r2.src_port,
                       dst_port: r2.dst_port,
                       observed_packet_count: r2.observed_packet_count,
                       observed_bytes: r2.observed_bytes,
                       first_seen: r2.first_seen,
                       last_seen: r2.last_seen,
                       observed_window_seconds: r2.observed_window_seconds
                   }) AS in_edges,
                   collect(DISTINCT {
                       source: CASE WHEN center.routing_domain_id = 'default' OR center.routing_domain_id IS NULL
                                    THEN 'ip:' + center.address
                                    ELSE 'ip:' + coalesce(center.scoped_id, center.address) END,
                       target: 'l2:' + l2.identifier,
                       type: 'OBSERVED_WITH',
                       protocol: null,
                       flow_key: null,
                       src_port: null,
                       dst_port: null,
                       observed_packet_count: null,
                       observed_bytes: null,
                       first_seen: null,
                       last_seen: null,
                       observed_window_seconds: null
                   }) AS l2_edges
            """
        else:  # depth == 2
            cypher = """
            MATCH (center:IPAddress)
            WHERE (
                ($scoped_id IS NOT NULL AND center.scoped_id = $scoped_id)
                OR ($scoped_id IS NULL AND center.address = $address)
            )
            OPTIONAL MATCH p = (center)-[r:COMMUNICATED_TO|OBSERVED_WITH*1..2]-(target)
            WHERE ALL(
                n IN nodes(p)
                WHERE NOT n:IPAddress
                   OR center.routing_domain_id IS NULL
                   OR n.routing_domain_id IS NULL
                   OR n.routing_domain_id = center.routing_domain_id
            )
            WITH center, collect(DISTINCT p) AS paths
            RETURN center.address AS center, paths
            """

        def _work(tx) -> Optional[Dict[str, Any]]:
            scoped_id_val, addr_val, dom_val = self._resolve_endpoint(tx, address=address, domain=domain, scoped_id=scoped_id)
            if addr_val is None:
                return None

            center_id = f"ip:{scoped_id_val}" if (dom_val and dom_val != "default" and scoped_id_val) else f"ip:{addr_val}"
            nodes_map = {center_id: {"id": center_id, "type": "IPAddress", "value": addr_val}}
            candidate_edges = []

            if depth == 1:
                rec = tx.run(cypher, address=addr_val, scoped_id=scoped_id_val).single()
                for group in [rec["out_ips"], rec["in_ips"], rec["l2_nodes"]]:
                    for n in group:
                        if n.get("value") is not None:
                            nodes_map[n["id"]] = n

                for egroup in [rec["out_edges"], rec["in_edges"], rec["l2_edges"]]:
                    for e in egroup:
                        if e.get("source") and e.get("target") and "None" not in e["source"] and "None" not in e["target"]:
                            candidate_edges.append(e)
            else:
                rec = tx.run(cypher, address=addr_val, scoped_id=scoped_id_val).single()
                paths = rec["paths"]
                for p in paths:
                    if p is not None:
                        for n in p.nodes:
                            if "IPAddress" in n.labels:
                                r_dom = n.get("routing_domain_id")
                                r_scoped = n.get("scoped_id")
                                nid = f"ip:{r_scoped}" if (r_dom and r_dom != "default" and r_scoped) else f"ip:{n['address']}"
                                nodes_map[nid] = {"id": nid, "type": "IPAddress", "value": n["address"]}
                            elif "Layer2Identifier" in n.labels:
                                nid = f"l2:{n['identifier']}"
                                nodes_map[nid] = {"id": nid, "type": "Layer2Identifier", "value": n["identifier"]}
                        for rel in p.relationships:
                            src_node = rel.start_node
                            dst_node = rel.end_node
                            if "IPAddress" in src_node.labels:
                                s_dom = src_node.get("routing_domain_id")
                                s_scoped = src_node.get("scoped_id")
                                src_id = f"ip:{s_scoped}" if (s_dom and s_dom != "default" and s_scoped) else f"ip:{src_node['address']}"
                            else:
                                src_id = f"l2:{src_node['identifier']}"

                            if "IPAddress" in dst_node.labels:
                                d_dom = dst_node.get("routing_domain_id")
                                d_scoped = dst_node.get("scoped_id")
                                dst_id = f"ip:{d_scoped}" if (d_dom and d_dom != "default" and d_scoped) else f"ip:{dst_node['address']}"
                            else:
                                dst_id = f"l2:{dst_node['identifier']}"

                            candidate_edges.append({
                                "source": src_id,
                                "target": dst_id,
                                "type": rel.type,
                                "protocol": rel.get("protocol"),
                                "flow_key": rel.get("flow_key"),
                                "src_port": rel.get("src_port"),
                                "dst_port": rel.get("dst_port"),
                                "observed_packet_count": rel.get("observed_packet_count"),
                                "observed_bytes": rel.get("observed_bytes"),
                                "first_seen": rel.get("first_seen"),
                                "last_seen": rel.get("last_seen"),
                                "observed_window_seconds": rel.get("observed_window_seconds"),
                            })

            # Deterministic node trimming (always retaining center node)
            sorted_other_nodes = sorted(
                [n for nid, n in nodes_map.items() if nid != center_id],
                key=lambda x: (x["type"], x["value"], x["id"]),
            )
            retained_nodes = [nodes_map[center_id]] + sorted_other_nodes[: max_nodes - 1]
            retained_node_ids = {n["id"] for n in retained_nodes}

            # Filter edges to only those where both endpoints are in retained nodes
            valid_edges = []
            seen_edges = set()
            for e in candidate_edges:
                if e["source"] in retained_node_ids and e["target"] in retained_node_ids:
                    edge_key = (
                        e["source"],
                        e["target"],
                        e["type"],
                        e.get("protocol"),
                        e.get("flow_key"),
                        e.get("src_port"),
                        e.get("dst_port"),
                    )
                    if edge_key not in seen_edges:
                        seen_edges.add(edge_key)
                        valid_edges.append(e)

            # Sort edges deterministically
            sorted_edges = sorted(
                valid_edges,
                key=lambda x: (
                    x["source"],
                    x["target"],
                    x["type"],
                    x.get("protocol") or "",
                    x.get("flow_key") or "",
                    x.get("src_port") or 0,
                    x.get("dst_port") or 0,
                ),
            )

            return {
                "center": addr_val,
                "depth": depth,
                "nodes": retained_nodes,
                "edges": sorted_edges,
            }

        with self.driver.session() as session:
            return session.execute_read(_work)

    def get_shortest_path(
        self,
        source: str,
        target: str,
        max_hops: int = 5,
        source_domain: Optional[str] = None,
        target_domain: Optional[str] = None,
        source_scoped_id: Optional[str] = None,
        target_scoped_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Find the shortest directional communication path between two IP addresses.

        Returns dict with path details or error flag ('source_not_found', 'target_not_found', 'no_path').
        Raises AmbiguousEndpointError if source or target address is ambiguous across domains.
        """
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        def _work(tx) -> Dict[str, Any]:
            src_scoped, src_addr, _ = self._resolve_endpoint(
                tx, address=source, domain=source_domain, scoped_id=source_scoped_id
            )
            if src_addr is None:
                return {"error": "source_not_found"}

            dst_scoped, dst_addr, _ = self._resolve_endpoint(
                tx, address=target, domain=target_domain, scoped_id=target_scoped_id
            )
            if dst_addr is None:
                return {"error": "target_not_found"}

            if (src_scoped and dst_scoped and src_scoped == dst_scoped) or (not src_scoped and not dst_scoped and src_addr == dst_addr):
                return {
                    "source": src_addr,
                    "target": dst_addr,
                    "hops": [src_addr],
                    "protocols": [],
                    "length": 0,
                }

            src_match = "(src:IPAddress {scoped_id: $src_scoped})" if src_scoped else "(src:IPAddress {address: $source})"
            dst_match = "(dst:IPAddress {scoped_id: $dst_scoped})" if dst_scoped else "(dst:IPAddress {address: $target})"
            cypher = f"""
            MATCH {src_match}, {dst_match}
            MATCH p = shortestPath((src)-[:COMMUNICATED_TO*1..10]->(dst))
            WHERE length(p) <= $max_hops
            RETURN [n IN nodes(p) | n.address] AS hops,
                   [r IN relationships(p) | r.protocol] AS protocols,
                   length(p) AS length
            """
            res = tx.run(
                cypher,
                src_scoped=src_scoped,
                dst_scoped=dst_scoped,
                source=src_addr,
                target=dst_addr,
                max_hops=max_hops,
            )

            record = res.single()
            if not record:
                return {"error": "no_path"}

            return {
                "source": src_addr,
                "target": dst_addr,
                "hops": [str(h) for h in record["hops"]],
                "protocols": [str(p) for p in record["protocols"]],
                "length": int(record["length"]),
            }

        with self.driver.session() as session:
            return session.execute_read(_work)

    @staticmethod
    def _record_to_flow_observation(record) -> Dict[str, Any]:
        """Materialize a FlowObservation Cypher record into a plain Python dictionary."""
        return {
            "observation_id": record["observation_id"],
            "flow_key": record["flow_key"],
            "zeek_uid": record["zeek_uid"],
            "routing_domain_id": record["routing_domain_id"],
            "src_scoped_id": record["src_scoped_id"],
            "dst_scoped_id": record["dst_scoped_id"],
            "src_ip": record["src_ip"],
            "dst_ip": record["dst_ip"],
            "protocol": record["protocol"],
            "src_port": record["src_port"],
            "dst_port": record["dst_port"],
            "community_id": record["community_id"],
            "start_ts": record["start_ts"],
            "end_ts": record["end_ts"],
            "start_epoch_decimal": record["start_epoch_decimal"],
            "end_epoch_decimal": record["end_epoch_decimal"],
            "duration_decimal": record["duration_decimal"],
            "start_epoch_ns": record["start_epoch_ns"],
            "end_epoch_ns": record["end_epoch_ns"],
            "orig_bytes": record["orig_bytes"],
            "resp_bytes": record["resp_bytes"],
            "orig_pkts": record["orig_pkts"],
            "resp_pkts": record["resp_pkts"],
            "orig_ip_bytes": record["orig_ip_bytes"],
            "resp_ip_bytes": record["resp_ip_bytes"],
            "missed_bytes": record["missed_bytes"],
            "service": record["service"],
            "conn_state": record["conn_state"],
            "history": record["history"],
            "local_orig": record["local_orig"],
            "local_resp": record["local_resp"],
            "sensor_id": record["sensor_id"],
            "source_type": record["source_type"],
            "source_provenance": record["source_provenance"],
        }

    @staticmethod
    def _normalize_optional_filter_domain(routing_domain_id: Optional[str]) -> Optional[str]:
        """Validate and normalize an optional routing_domain_id filter, failing closed."""
        if routing_domain_id is None:
            return None
        if not isinstance(routing_domain_id, str):
            raise ValueError(f"routing_domain_id must be a string or None, got {routing_domain_id!r}")
        cleaned = routing_domain_id.strip().lower()
        if not cleaned:
            raise ValueError("routing_domain_id must not be empty or whitespace when specified")
        if "#" in cleaned:
            raise ValueError(f"routing_domain_id cannot contain delimiter '#': {routing_domain_id!r}")
        return cleaned

    @staticmethod
    def _normalize_optional_source_type(source_type: Optional[str]) -> Optional[str]:
        """Validate and normalize an optional source_type predicate."""
        if source_type is None:
            return None
        if not isinstance(source_type, str):
            raise ValueError(f"source_type must be a string or None, got {source_type!r}")
        cleaned = source_type.strip().lower()
        if not cleaned:
            raise ValueError("source_type must not be empty or whitespace when specified")
        return cleaned

    def get_flow_observation(
        self,
        observation_id: str,
        *,
        routing_domain_id: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a single discrete FlowObservation by its unique observation_id."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")
        if not isinstance(observation_id, str) or not observation_id.strip():
            raise ValueError("observation_id must be a non-empty string")

        clean_id = observation_id.strip()
        norm_domain = self._normalize_optional_filter_domain(routing_domain_id)
        norm_source_type = self._normalize_optional_source_type(source_type)
        cypher = """
        MATCH (fo:FlowObservation {observation_id: $observation_id})
        WHERE fo.routing_domain_id IS NOT NULL
          AND trim(fo.routing_domain_id) <> ''
          AND NOT fo.routing_domain_id CONTAINS '#'
          AND ($routing_domain_id IS NULL OR toLower(trim(fo.routing_domain_id)) = $routing_domain_id)
          AND ($source_type IS NULL OR fo.source_type = $source_type)
        OPTIONAL MATCH (fo)-[:HAS_ORIGINATOR]->(orig:IPAddress)
        WITH fo,
             collect(DISTINCT CASE WHEN orig IS NOT NULL THEN {scoped_id: orig.scoped_id, address: orig.address} END) AS orig_nodes
        OPTIONAL MATCH (fo)-[:HAS_RESPONDER]->(resp:IPAddress)
        WITH fo, orig_nodes[0] AS orig_ep,
             collect(DISTINCT CASE WHEN resp IS NOT NULL THEN {scoped_id: resp.scoped_id, address: resp.address} END) AS resp_nodes
        WITH fo, orig_ep, resp_nodes[0] AS resp_ep
        RETURN fo.observation_id AS observation_id,
               fo.flow_key AS flow_key,
               fo.zeek_uid AS zeek_uid,
               fo.routing_domain_id AS routing_domain_id,
               coalesce(orig_ep.scoped_id, fo.src_scoped_id) AS src_scoped_id,
               coalesce(resp_ep.scoped_id, fo.dst_scoped_id) AS dst_scoped_id,
               coalesce(orig_ep.address, fo.src_ip) AS src_ip,
               coalesce(resp_ep.address, fo.dst_ip) AS dst_ip,
               fo.protocol AS protocol,
               fo.src_port AS src_port,
               fo.dst_port AS dst_port,
               fo.community_id AS community_id,
               fo.start_ts AS start_ts,
               fo.end_ts AS end_ts,
               fo.start_epoch_decimal AS start_epoch_decimal,
               fo.end_epoch_decimal AS end_epoch_decimal,
               fo.duration_decimal AS duration_decimal,
               fo.start_epoch_ns AS start_epoch_ns,
               fo.end_epoch_ns AS end_epoch_ns,
               fo.orig_bytes AS orig_bytes,
               fo.resp_bytes AS resp_bytes,
               fo.orig_pkts AS orig_pkts,
               fo.resp_pkts AS resp_pkts,
               fo.orig_ip_bytes AS orig_ip_bytes,
               fo.resp_ip_bytes AS resp_ip_bytes,
               fo.missed_bytes AS missed_bytes,
               fo.service AS service,
               fo.conn_state AS conn_state,
               fo.history AS history,
               fo.local_orig AS local_orig,
               fo.local_resp AS local_resp,
               fo.sensor_id AS sensor_id,
               fo.source_type AS source_type,
               fo.source_provenance AS source_provenance
        """

        def _work(tx) -> Optional[Dict[str, Any]]:
            res = tx.run(
                cypher,
                observation_id=clean_id,
                routing_domain_id=norm_domain,
                source_type=norm_source_type,
            )
            rec = res.single()
            if not rec:
                return None
            return self._record_to_flow_observation(rec)

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_flow_observations(
        self,
        routing_domain_id: Optional[str] = None,
        sensor_id: Optional[str] = None,
        community_id: Optional[str] = None,
        start_epoch_ns_min: Optional[int] = None,
        start_epoch_ns_max: Optional[int] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List discrete FlowObservation nodes with deterministic pagination and exact filtering.

        Temporal range filters (`start_epoch_ns_min`, `start_epoch_ns_max`) operate strictly on
        the exact integer `start_epoch_ns` property (never lexicographic string comparisons).
        Observations sharing `flow_key` or `community_id` are never collapsed.
        """
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        if isinstance(limit, bool) or not isinstance(limit, int) or not (1 <= limit <= 1000):
            raise ValueError(f"limit must be an integer in 1..1000, got {limit!r}")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError(f"offset must be an integer >= 0, got {offset!r}")

        if start_epoch_ns_min is not None:
            if isinstance(start_epoch_ns_min, bool) or not isinstance(start_epoch_ns_min, int):
                raise ValueError(f"start_epoch_ns_min must be an integer or None, got {start_epoch_ns_min!r}")
            if not (_INT64_MIN <= start_epoch_ns_min <= _INT64_MAX):
                raise ValueError(
                    f"start_epoch_ns_min must fit in signed 64-bit integer range [{_INT64_MIN}, {_INT64_MAX}]"
                )
        if start_epoch_ns_max is not None:
            if isinstance(start_epoch_ns_max, bool) or not isinstance(start_epoch_ns_max, int):
                raise ValueError(f"start_epoch_ns_max must be an integer or None, got {start_epoch_ns_max!r}")
            if not (_INT64_MIN <= start_epoch_ns_max <= _INT64_MAX):
                raise ValueError(
                    f"start_epoch_ns_max must fit in signed 64-bit integer range [{_INT64_MIN}, {_INT64_MAX}]"
                )
        if (
            start_epoch_ns_min is not None
            and start_epoch_ns_max is not None
            and start_epoch_ns_min > start_epoch_ns_max
        ):
            raise ValueError("start_epoch_ns_min cannot be greater than start_epoch_ns_max")

        norm_domain = routing_domain_id.strip().lower() if routing_domain_id and routing_domain_id.strip() else None
        norm_sensor = sensor_id.strip().lower() if sensor_id and sensor_id.strip() else None
        norm_cid = community_id.strip() if community_id and community_id.strip() else None

        conditions: List[str] = []
        params: Dict[str, Any] = {"limit": limit, "offset": offset}

        if norm_domain is not None:
            conditions.append("fo.routing_domain_id = $routing_domain_id")
            params["routing_domain_id"] = norm_domain
        if norm_sensor is not None:
            conditions.append("fo.sensor_id = $sensor_id")
            params["sensor_id"] = norm_sensor
        if norm_cid is not None:
            conditions.append("fo.community_id = $community_id")
            params["community_id"] = norm_cid
        if start_epoch_ns_min is not None:
            conditions.append("fo.start_epoch_ns IS NOT NULL AND fo.start_epoch_ns >= $start_epoch_ns_min")
            params["start_epoch_ns_min"] = start_epoch_ns_min
        if start_epoch_ns_max is not None:
            conditions.append("fo.start_epoch_ns IS NOT NULL AND fo.start_epoch_ns <= $start_epoch_ns_max")
            params["start_epoch_ns_max"] = start_epoch_ns_max

        where_clause = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        count_cypher = f"MATCH (fo:FlowObservation) {where_clause} RETURN count(fo) AS total"
        page_cypher = f"""
        MATCH (fo:FlowObservation)
        {where_clause}
        OPTIONAL MATCH (fo)-[:HAS_ORIGINATOR]->(orig:IPAddress)
        OPTIONAL MATCH (fo)-[:HAS_RESPONDER]->(resp:IPAddress)
        RETURN fo.observation_id AS observation_id,
               fo.flow_key AS flow_key,
               fo.zeek_uid AS zeek_uid,
               fo.routing_domain_id AS routing_domain_id,
               coalesce(orig.scoped_id, fo.src_scoped_id) AS src_scoped_id,
               coalesce(resp.scoped_id, fo.dst_scoped_id) AS dst_scoped_id,
               coalesce(orig.address, fo.src_ip) AS src_ip,
               coalesce(resp.address, fo.dst_ip) AS dst_ip,
               fo.protocol AS protocol,
               fo.src_port AS src_port,
               fo.dst_port AS dst_port,
               fo.community_id AS community_id,
               fo.start_ts AS start_ts,
               fo.end_ts AS end_ts,
               fo.start_epoch_decimal AS start_epoch_decimal,
               fo.end_epoch_decimal AS end_epoch_decimal,
               fo.duration_decimal AS duration_decimal,
               fo.start_epoch_ns AS start_epoch_ns,
               fo.end_epoch_ns AS end_epoch_ns,
               fo.orig_bytes AS orig_bytes,
               fo.resp_bytes AS resp_bytes,
               fo.orig_pkts AS orig_pkts,
               fo.resp_pkts AS resp_pkts,
               fo.orig_ip_bytes AS orig_ip_bytes,
               fo.resp_ip_bytes AS resp_ip_bytes,
               fo.missed_bytes AS missed_bytes,
               fo.service AS service,
               fo.conn_state AS conn_state,
               fo.history AS history,
               fo.local_orig AS local_orig,
               fo.local_resp AS local_resp,
               fo.sensor_id AS sensor_id,
               fo.source_type AS source_type,
               fo.source_provenance AS source_provenance
        ORDER BY CASE WHEN fo.start_epoch_ns IS NULL THEN 1 ELSE 0 END ASC,
                 fo.start_epoch_ns ASC,
                 fo.observation_id ASC
        SKIP $offset LIMIT $limit
        """

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            total = int(tx.run(count_cypher, **params).single()["total"])
            page_res = tx.run(page_cypher, **params)
            items = [self._record_to_flow_observation(r) for r in page_res]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)

    @staticmethod
    def _record_to_alert_event(record) -> Dict[str, Any]:
        """Materialize an AlertEvent Cypher record into a plain Python dictionary."""
        return {
            "event_id": record["event_id"],
            "alert_definition_id": record["alert_definition_id"],
            "source_record_id": record["source_record_id"],
            "log_source_id": record["log_source_id"],
            "sensor_id": record["sensor_id"],
            "ruleset_namespace": record["ruleset_namespace"],
            "routing_domain_id": record["routing_domain_id"],
            "flow_key": record["flow_key"],
            "src_scoped_id": record["src_scoped_id"],
            "dst_scoped_id": record["dst_scoped_id"],
            "src_ip": record["src_ip"],
            "dst_ip": record["dst_ip"],
            "timestamp_source": record["timestamp_source"],
            "timestamp_epoch_decimal": record["timestamp_epoch_decimal"],
            "timestamp_epoch_ns": record["timestamp_epoch_ns"],
            "protocol": record["protocol"],
            "src_port": record["src_port"],
            "dst_port": record["dst_port"],
            "flow_id": record["flow_id"],
            "community_id": record["community_id"],
            "gid": record["gid"],
            "sid": record["sid"],
            "rev": record["rev"],
            "signature": record["signature"],
            "category": record["category"],
            "severity": record["severity"],
            "action": record["action"],
            "app_proto": record["app_proto"],
            "direction": record["direction"],
            "tx_id": record["tx_id"],
            "pcap_cnt": record["pcap_cnt"],
            "source_type": record["source_type"],
            "source_provenance": record["source_provenance"],
        }

    @staticmethod
    def _resolve_alert_definition_engine(
        alert_item: Dict[str, Any],
        raw_definitions: Any,
    ) -> Optional[str]:
        """Resolve AlertDefinition.engine factually without fabricating missing links.

        Raises ValueError (fail closed -> HTTP 500 at API boundary) if multiple or
        contradictory AlertDefinition relationships exist for the AlertEvent.
        """
        if raw_definitions is None:
            return None
        if not isinstance(raw_definitions, list):
            raise ValueError("Invalid alert_definitions structure returned from repository query")

        defs = [d for d in raw_definitions if d is not None]
        if not defs:
            return None
        if len(defs) > 1:
            raise ValueError(
                f"Contradictory AlertDefinition relationships ({len(defs)}) persisted for AlertEvent "
                f"'{alert_item.get('event_id')}'"
            )

        def_row = defs[0]
        if not isinstance(def_row, dict):
            raise ValueError("Invalid AlertDefinition metadata entry")

        def_id = def_row.get("definition_id")
        if not isinstance(def_id, str) or not def_id.strip() or def_id != alert_item.get("alert_definition_id"):
            raise ValueError(
                f"Contradictory AlertDefinition.definition_id {def_id!r} for AlertEvent "
                f"'{alert_item.get('event_id')}' (expected {alert_item.get('alert_definition_id')!r})"
            )

        def_ns = def_row.get("ruleset_namespace")
        if def_ns is not None:
            event_ns = alert_item.get("ruleset_namespace")
            if not isinstance(def_ns, str) or not def_ns.strip():
                raise ValueError("Invalid AlertDefinition.ruleset_namespace")
            if not isinstance(event_ns, str) or def_ns.strip().lower() != event_ns.strip().lower():
                raise ValueError(
                    f"Contradictory AlertDefinition.ruleset_namespace {def_ns!r} vs AlertEvent {event_ns!r}"
                )

        def_gid = def_row.get("gid")
        if def_gid is not None:
            if isinstance(def_gid, bool) or not isinstance(def_gid, int) or def_gid != alert_item.get("gid"):
                raise ValueError(
                    f"Contradictory AlertDefinition.gid {def_gid!r} vs AlertEvent {alert_item.get('gid')!r}"
                )

        def_sid = def_row.get("sid")
        if def_sid is not None:
            if isinstance(def_sid, bool) or not isinstance(def_sid, int) or def_sid != alert_item.get("sid"):
                raise ValueError(
                    f"Contradictory AlertDefinition.sid {def_sid!r} vs AlertEvent {alert_item.get('sid')!r}"
                )

        def_engine = def_row.get("engine")
        if def_engine is None:
            return None
        if not isinstance(def_engine, str) or not def_engine.strip():
            raise ValueError(f"Invalid AlertDefinition.engine {def_engine!r}")

        event_source_type = alert_item.get("source_type")
        if isinstance(event_source_type, str) and event_source_type.strip():
            if def_engine.strip().lower() != event_source_type.strip().lower():
                raise ValueError(
                    f"Contradictory AlertDefinition.engine {def_engine!r} vs AlertEvent.source_type "
                    f"{event_source_type!r}"
                )
        return def_engine

    def get_alert_event(
        self,
        event_id: str,
        *,
        routing_domain_id: Optional[str] = None,
        source_type: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Retrieve a single discrete AlertEvent by its unique event_id."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        norm_domain = self._normalize_optional_filter_domain(routing_domain_id)
        norm_source_type = self._normalize_optional_source_type(source_type)

        if not event_id or not str(event_id).strip():
            return None

        cleaned_id = str(event_id).strip()
        cypher = """
        MATCH (ae:AlertEvent {event_id: $event_id})
        WHERE ae.routing_domain_id IS NOT NULL
          AND trim(ae.routing_domain_id) <> ''
          AND NOT ae.routing_domain_id CONTAINS '#'
          AND ($routing_domain_id IS NULL OR toLower(trim(ae.routing_domain_id)) = $routing_domain_id)
          AND ($source_type IS NULL OR ae.source_type = $source_type)
        OPTIONAL MATCH (ae)-[:HAS_SOURCE]->(src_ip:IPAddress)
        WITH ae,
             collect(DISTINCT CASE WHEN src_ip IS NOT NULL THEN {scoped_id: src_ip.scoped_id, address: src_ip.address} END) AS src_nodes
        OPTIONAL MATCH (ae)-[:HAS_DESTINATION]->(dst_ip:IPAddress)
        WITH ae, src_nodes[0] AS src_ep,
             collect(DISTINCT CASE WHEN dst_ip IS NOT NULL THEN {scoped_id: dst_ip.scoped_id, address: dst_ip.address} END) AS dst_nodes
        OPTIONAL MATCH (ae)-[:TRIGGERED_RULE]->(ad:AlertDefinition)
        WITH ae, src_ep, dst_nodes[0] AS dst_ep,
             collect(DISTINCT CASE WHEN ad IS NOT NULL THEN {
                 definition_id: ad.definition_id,
                 engine: ad.engine,
                 ruleset_namespace: ad.ruleset_namespace,
                 gid: ad.gid,
                 sid: ad.sid
             } END) AS alert_definitions
        RETURN ae.event_id AS event_id,
               ae.alert_definition_id AS alert_definition_id,
               ae.source_record_id AS source_record_id,
               ae.log_source_id AS log_source_id,
               ae.sensor_id AS sensor_id,
               ae.ruleset_namespace AS ruleset_namespace,
               ae.routing_domain_id AS routing_domain_id,
               ae.flow_key AS flow_key,
               coalesce(src_ep.scoped_id, ae.src_scoped_id) AS src_scoped_id,
               coalesce(dst_ep.scoped_id, ae.dst_scoped_id) AS dst_scoped_id,
               coalesce(src_ep.address, ae.src_ip) AS src_ip,
               coalesce(dst_ep.address, ae.dst_ip) AS dst_ip,
               ae.timestamp_source AS timestamp_source,
               ae.timestamp_epoch_decimal AS timestamp_epoch_decimal,
               ae.timestamp_epoch_ns AS timestamp_epoch_ns,
               ae.protocol AS protocol,
               ae.src_port AS src_port,
               ae.dst_port AS dst_port,
               ae.flow_id AS flow_id,
               ae.community_id AS community_id,
               ae.gid AS gid,
               ae.sid AS sid,
               ae.rev AS rev,
               ae.signature AS signature,
               ae.category AS category,
               ae.severity AS severity,
               ae.action AS action,
               ae.app_proto AS app_proto,
               ae.direction AS direction,
               ae.tx_id AS tx_id,
               ae.pcap_cnt AS pcap_cnt,
               ae.source_type AS source_type,
               ae.source_provenance AS source_provenance,
               alert_definitions AS alert_definitions
        """

        def _work(tx) -> Optional[Dict[str, Any]]:
            record = tx.run(
                cypher,
                event_id=cleaned_id,
                routing_domain_id=norm_domain,
                source_type=norm_source_type,
            ).single()
            if not record:
                return None
            item = self._record_to_alert_event(record)
            raw_defs = record.get("alert_definitions") if hasattr(record, "get") else None
            item["engine"] = self._resolve_alert_definition_engine(item, raw_defs)
            return item

        with self.driver.session() as session:
            return session.execute_read(_work)

    def list_alert_events(
        self,
        *,
        routing_domain_id: Optional[str] = None,
        sensor_id: Optional[str] = None,
        flow_key: Optional[str] = None,
        community_id: Optional[str] = None,
        flow_id: Optional[Union[int, str]] = None,
        sid: Optional[int] = None,
        alert_definition_id: Optional[str] = None,
        severity: Optional[int] = None,
        start_epoch_ns: Optional[int] = None,
        end_epoch_ns: Optional[int] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List discrete Suricata AlertEvent nodes with optional indexed filtering and pagination.

        Supports optional exact-match filters on `routing_domain_id`, `sensor_id`,
        `flow_key`, `community_id`, `flow_id`, `sid`, `alert_definition_id`
        (resolved via `(:AlertEvent)-[:TRIGGERED_RULE]->(:AlertDefinition)` using the
        unique `AlertDefinition.definition_id` constraint), and `severity`.

        Temporal filtering operates strictly on lossless signed 64-bit integer
        nanosecond property `timestamp_epoch_ns`. Events missing a resolved epoch
        timestamp (e.g. timezone-naive timestamps) are excluded when temporal
        bounds are provided and ordered last (`NULLS LAST`) otherwise.
        """
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise ValueError(f"limit must be a positive integer, got {limit!r}")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError(f"offset must be a non-negative integer, got {offset!r}")

        if start_epoch_ns is not None:
            if isinstance(start_epoch_ns, bool) or not isinstance(start_epoch_ns, int):
                raise ValueError(f"start_epoch_ns must be an integer or None, got {start_epoch_ns!r}")
            if not (_INT64_MIN <= start_epoch_ns <= _INT64_MAX):
                raise ValueError(f"start_epoch_ns exceeds 64-bit signed integer range: {start_epoch_ns}")

        if end_epoch_ns is not None:
            if isinstance(end_epoch_ns, bool) or not isinstance(end_epoch_ns, int):
                raise ValueError(f"end_epoch_ns must be an integer or None, got {end_epoch_ns!r}")
            if not (_INT64_MIN <= end_epoch_ns <= _INT64_MAX):
                raise ValueError(f"end_epoch_ns exceeds 64-bit signed integer range: {end_epoch_ns}")

        if sid is not None:
            if isinstance(sid, bool) or not isinstance(sid, int) or not (0 <= sid <= _INT64_MAX):
                raise ValueError(f"sid must be an integer in 0..{_INT64_MAX} or None, got {sid!r}")

        if severity is not None:
            if isinstance(severity, bool) or not isinstance(severity, int) or not (0 <= severity <= _INT64_MAX):
                raise ValueError(f"severity must be an integer in 0..{_INT64_MAX} or None, got {severity!r}")

        norm_def_id: Optional[str] = None
        if alert_definition_id is not None:
            if not isinstance(alert_definition_id, str):
                raise ValueError(f"alert_definition_id must be a string or None, got {alert_definition_id!r}")
            cleaned_def_id = alert_definition_id.strip().lower()
            if cleaned_def_id:
                norm_def_id = cleaned_def_id

        flow_id_str: Optional[str] = None
        if flow_id is not None:
            if isinstance(flow_id, bool):
                raise ValueError(f"flow_id must be a non-negative integer or decimal string, got {flow_id!r}")
            if isinstance(flow_id, int):
                if flow_id < 0:
                    raise ValueError(f"flow_id must be non-negative, got {flow_id!r}")
                flow_id_str = str(flow_id)
            elif isinstance(flow_id, str):
                cleaned_flow_id = flow_id.strip()
                if not cleaned_flow_id or not cleaned_flow_id.isascii() or not cleaned_flow_id.isdigit():
                    raise ValueError(f"flow_id string must contain ASCII digits only, got {flow_id!r}")
                flow_id_str = str(int(cleaned_flow_id))
            else:
                raise ValueError(f"flow_id must be an int, str, or None, got {flow_id!r}")

        effective_limit = min(limit, 1000)
        clauses: List[str] = []
        params: Dict[str, Any] = {
            "limit": effective_limit,
            "offset": offset,
        }

        if norm_def_id is not None:
            match_clause = "MATCH (ae:AlertEvent)-[:TRIGGERED_RULE]->(ad:AlertDefinition)"
            clauses.append("ad.definition_id = $alert_definition_id")
            params["alert_definition_id"] = norm_def_id
        else:
            match_clause = "MATCH (ae:AlertEvent)"

        if routing_domain_id and routing_domain_id.strip():
            clauses.append("ae.routing_domain_id = $routing_domain_id")
            params["routing_domain_id"] = routing_domain_id.strip().lower()
        if sensor_id and sensor_id.strip():
            clauses.append("ae.sensor_id = $sensor_id")
            params["sensor_id"] = sensor_id.strip().lower()
        if flow_key and flow_key.strip():
            clauses.append("ae.flow_key = $flow_key")
            params["flow_key"] = flow_key.strip()
        if community_id and community_id.strip():
            clauses.append("ae.community_id = $community_id")
            params["community_id"] = community_id.strip()
        if flow_id_str is not None:
            clauses.append("ae.flow_id = $flow_id")
            params["flow_id"] = flow_id_str
        if sid is not None:
            clauses.append("ae.sid = $sid")
            params["sid"] = sid
        if severity is not None:
            clauses.append("ae.severity = $severity")
            params["severity"] = severity
        if start_epoch_ns is not None:
            clauses.append("ae.timestamp_epoch_ns IS NOT NULL AND ae.timestamp_epoch_ns >= $start_epoch_ns")
            params["start_epoch_ns"] = start_epoch_ns
        if end_epoch_ns is not None:
            clauses.append("ae.timestamp_epoch_ns IS NOT NULL AND ae.timestamp_epoch_ns <= $end_epoch_ns")
            params["end_epoch_ns"] = end_epoch_ns

        where_clause = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        count_cypher = f"""
        {match_clause}
        {where_clause}
        RETURN count(ae) AS total
        """

        page_cypher = f"""
        {match_clause}
        {where_clause}
        RETURN ae.event_id AS event_id,
               ae.alert_definition_id AS alert_definition_id,
               ae.source_record_id AS source_record_id,
               ae.log_source_id AS log_source_id,
               ae.sensor_id AS sensor_id,
               ae.ruleset_namespace AS ruleset_namespace,
               ae.routing_domain_id AS routing_domain_id,
               ae.flow_key AS flow_key,
               ae.src_scoped_id AS src_scoped_id,
               ae.dst_scoped_id AS dst_scoped_id,
               ae.src_ip AS src_ip,
               ae.dst_ip AS dst_ip,
               ae.timestamp_source AS timestamp_source,
               ae.timestamp_epoch_decimal AS timestamp_epoch_decimal,
               ae.timestamp_epoch_ns AS timestamp_epoch_ns,
               ae.protocol AS protocol,
               ae.src_port AS src_port,
               ae.dst_port AS dst_port,
               ae.flow_id AS flow_id,
               ae.community_id AS community_id,
               ae.gid AS gid,
               ae.sid AS sid,
               ae.rev AS rev,
               ae.signature AS signature,
               ae.category AS category,
               ae.severity AS severity,
               ae.action AS action,
               ae.app_proto AS app_proto,
               ae.direction AS direction,
               ae.tx_id AS tx_id,
               ae.pcap_cnt AS pcap_cnt,
               ae.source_type AS source_type,
               ae.source_provenance AS source_provenance
        ORDER BY CASE WHEN ae.timestamp_epoch_ns IS NULL THEN 1 ELSE 0 END ASC,
                 ae.timestamp_epoch_ns ASC,
                 ae.event_id ASC
        SKIP $offset
        LIMIT $limit
        """

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            total = int(tx.run(count_cypher, **params).single()["total"])
            page_res = tx.run(page_cypher, **params)
            items = [self._record_to_alert_event(r) for r in page_res]
            return items, total

        with self.driver.session() as session:
            return session.execute_read(_work)
