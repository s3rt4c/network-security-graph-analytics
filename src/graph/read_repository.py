"""
Neo4j Graph Read Repository.

Implements query execution for the Phase 4 FastAPI backend using managed read
transactions (session.execute_read) on a shared Neo4j Driver. All Cypher queries
are parameterized, fully materialized within transaction callbacks, and return
plain Python primitives/dictionaries.
Supports V2 scoped IP identities and explicit ambiguity detection across RoutingDomains.
"""

import logging
from typing import List, Dict, Any, Optional, Tuple

from src.ingestion.v2_models import scoped_ip_id

logger = logging.getLogger(__name__)


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
            return rec.get("scoped_id"), rec.get("address", address), rec.get("domain_id")

        if domain:
            target_scoped = scoped_ip_id(domain, address)
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
                    domain=domain,
                )
                rec2 = res2.single()
                if not rec2:
                    return None, None, None
                return rec2.get("scoped_id", target_scoped), rec2.get("address", address), rec2.get("domain_id", domain)
            return rec.get("scoped_id", target_scoped), rec.get("address", address), rec.get("domain_id", domain)

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

        def _work(tx) -> Tuple[List[Dict[str, Any]], int]:
            if domain:
                count_res = tx.run(
                    "MATCH (ip:IPAddress) WHERE ip.routing_domain_id = $domain RETURN count(ip) AS total",
                    domain=domain,
                )
                total = count_res.single()["total"]

                page_res = tx.run(
                    "MATCH (ip:IPAddress) "
                    "WHERE ip.routing_domain_id = $domain "
                    "RETURN ip.address AS address, ip.scoped_id AS scoped_id, ip.routing_domain_id AS routing_domain_id "
                    "ORDER BY ip.address ASC "
                    "SKIP $offset LIMIT $limit",
                    domain=domain,
                    offset=offset,
                    limit=limit,
                )
            else:
                count_res = tx.run("MATCH (ip:IPAddress) RETURN count(ip) AS total")
                total = count_res.single()["total"]

                page_res = tx.run(
                    "MATCH (ip:IPAddress) "
                    "RETURN ip.address AS address, ip.scoped_id AS scoped_id, ip.routing_domain_id AS routing_domain_id "
                    "ORDER BY ip.address ASC "
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
            OR ($scoped_id IS NULL AND ip.address = $address)
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
            scoped_id_val, addr_val, _ = self._resolve_endpoint(tx, address=address, domain=domain, scoped_id=scoped_id)
            if addr_val is None:
                return None

            res = tx.run(cypher, address=address, scoped_id=scoped_id_val)
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
                   count(CASE WHEN c.observed_packet_count IS NOT NULL THEN 1 END) AS enriched_count,
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
                   count(CASE WHEN c.observed_packet_count IS NOT NULL THEN 1 END) AS enriched_count,
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

            # 4. Top Fan-out
            fan_out_cypher = """
            MATCH (src:IPAddress)-[:COMMUNICATED_TO]->(dst:IPAddress)
            RETURN src.address AS address, count(DISTINCT dst) AS distinct_destination_ips
            ORDER BY distinct_destination_ips DESC, address ASC
            LIMIT 10
            """
            fan_out_res = tx.run(fan_out_cypher)
            top_fan_out = [
                {"address": r["address"], "distinct_destination_ips": int(r["distinct_destination_ips"])}
                for r in fan_out_res
            ]

            # 5. Top Fan-in
            fan_in_cypher = """
            MATCH (src:IPAddress)-[:COMMUNICATED_TO]->(dst:IPAddress)
            RETURN dst.address AS address, count(DISTINCT src) AS distinct_source_ips
            ORDER BY distinct_source_ips DESC, address ASC
            LIMIT 10
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
            "fan_out": "ORDER BY distinct_outbound_peers DESC, ip.address ASC",
            "fan_in": "ORDER BY distinct_inbound_peers DESC, ip.address ASC",
            "observed_packets_sent": "ORDER BY CASE WHEN observed_packets_sent IS NULL THEN 1 ELSE 0 END, observed_packets_sent DESC, ip.address ASC",
            "observed_bytes_sent": "ORDER BY CASE WHEN observed_bytes_sent IS NULL THEN 1 ELSE 0 END, observed_bytes_sent DESC, ip.address ASC",
            "first_observed": "ORDER BY CASE WHEN first_observed IS NULL THEN 1 ELSE 0 END, first_observed ASC, ip.address ASC",
            "last_observed": "ORDER BY CASE WHEN last_observed IS NULL THEN 1 ELSE 0 END, last_observed DESC, ip.address ASC",
        }
        order_clause = sort_clauses.get(sort_by, sort_clauses["fan_out"])

        where_clause = "WHERE ip.routing_domain_id = $domain" if domain else ""
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
            if domain:
                params["domain"] = domain
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

            params: Dict[str, Any] = {"address": address, "scoped_id": scoped_id_val}
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
            params: Dict[str, Any] = {"address": address, "scoped_id": scoped_id_val}
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

        conditions = []
        params: Dict[str, Any] = {"limit": limit, "offset": offset}

        if source_ip is not None:
            conditions.append("src.address = $source_ip")
            params["source_ip"] = source_ip
        if target_ip is not None:
            conditions.append("dst.address = $target_ip")
            params["target_ip"] = target_ip
        if protocol is not None:
            conditions.append("c.protocol = $protocol")
            params["protocol"] = protocol
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
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC
            """,
            "observed_bytes": """
            ORDER BY CASE WHEN c.observed_bytes IS NULL THEN 1 ELSE 0 END, c.observed_bytes DESC,
                     src.address ASC, dst.address ASC, c.protocol ASC,
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC
            """,
            "observed_packets": """
            ORDER BY CASE WHEN c.observed_packet_count IS NULL THEN 1 ELSE 0 END, c.observed_packet_count DESC,
                     src.address ASC, dst.address ASC, c.protocol ASC,
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC
            """,
            "first_seen": """
            ORDER BY CASE WHEN c.first_seen IS NULL THEN 1 ELSE 0 END, c.first_seen ASC,
                     src.address ASC, dst.address ASC, c.protocol ASC,
                     CASE WHEN c.flow_key IS NULL THEN 1 ELSE 0 END, c.flow_key ASC
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
        sid: Optional[int] = None,
        priority: Optional[int] = None,
        protocol: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """List normalized AlertFact entities with optional filtering, deterministic sorting, and pagination."""
        if self.driver is None:
            raise ConnectionError("Database driver unavailable")

        conditions = []
        params: Dict[str, Any] = {"limit": limit, "offset": offset}

        if sid is not None:
            conditions.append("fact.sid = $sid")
            params["sid"] = sid
        if priority is not None:
            conditions.append("fact.priority = $priority")
            params["priority"] = priority
        if protocol is not None:
            conditions.append("fact.protocol = $protocol")
            params["protocol"] = protocol

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
        ORDER BY fact.priority ASC, fact.sid ASC, fact.fact_key ASC
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
            WITH center, collect(DISTINCT p) AS paths
            RETURN center.address AS center, paths
            """

        def _work(tx) -> Optional[Dict[str, Any]]:
            scoped_id_val, addr_val, dom_val = self._resolve_endpoint(tx, address=address, domain=domain, scoped_id=scoped_id)
            if addr_val is None:
                return None

            center_id = f"ip:{scoped_id_val}" if (dom_val and dom_val != "default" and scoped_id_val) else f"ip:{address}"
            nodes_map = {center_id: {"id": center_id, "type": "IPAddress", "value": address}}
            candidate_edges = []

            if depth == 1:
                rec = tx.run(cypher, address=address, scoped_id=scoped_id_val).single()
                for group in [rec["out_ips"], rec["in_ips"], rec["l2_nodes"]]:
                    for n in group:
                        if n.get("value") is not None:
                            nodes_map[n["id"]] = n

                for egroup in [rec["out_edges"], rec["in_edges"], rec["l2_edges"]]:
                    for e in egroup:
                        if e.get("source") and e.get("target") and "None" not in e["source"] and "None" not in e["target"]:
                            candidate_edges.append(e)
            else:
                rec = tx.run(cypher, address=address, scoped_id=scoped_id_val).single()
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
                key=lambda x: (x["type"], x["value"]),
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
                "center": address,
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

            if (src_scoped and dst_scoped and src_scoped == dst_scoped) or (not src_scoped and not dst_scoped and source == target):
                return {
                    "source": source,
                    "target": target,
                    "hops": [source],
                    "protocols": [],
                    "length": 0,
                }

            if src_scoped and dst_scoped:
                cypher = """
                MATCH (src:IPAddress {scoped_id: $src_scoped}), (dst:IPAddress {scoped_id: $dst_scoped})
                MATCH p = shortestPath((src)-[:COMMUNICATED_TO*1..10]->(dst))
                WHERE length(p) <= $max_hops
                RETURN [n IN nodes(p) | n.address] AS hops,
                       [r IN relationships(p) | r.protocol] AS protocols,
                       length(p) AS length
                """
                res = tx.run(cypher, src_scoped=src_scoped, dst_scoped=dst_scoped, max_hops=max_hops)
            else:
                cypher = """
                MATCH (src:IPAddress {address: $source}), (dst:IPAddress {address: $target})
                MATCH p = shortestPath((src)-[:COMMUNICATED_TO*1..10]->(dst))
                WHERE length(p) <= $max_hops
                RETURN [n IN nodes(p) | n.address] AS hops,
                       [r IN relationships(p) | r.protocol] AS protocols,
                       length(p) AS length
                """
                res = tx.run(cypher, source=source, target=target, max_hops=max_hops)

            record = res.single()
            if not record:
                return {"error": "no_path"}

            return {
                "source": source,
                "target": target,
                "hops": [str(h) for h in record["hops"]],
                "protocols": [str(p) for p in record["protocols"]],
                "length": int(record["length"]),
            }

        with self.driver.session() as session:
            return session.execute_read(_work)
