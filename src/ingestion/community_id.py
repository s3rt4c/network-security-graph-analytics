"""
Community ID v1 calculation adapter.

Wraps the standard `communityid` package (corelight/pycommunityid) to provide a
clean, typed interface for computing and resolving Community ID v1 flow hashes.

SEMANTIC BOUNDARIES:
    - Community ID is an open-standard INTEROPERABILITY and CORRELATION identifier.
    - It is BIDIRECTIONAL (A -> B and B -> A produce the exact same Community ID).
    - It is NOT our primary graph database identity or FlowObservation primary key.
    - It does NOT incorporate RoutingDomain, VLAN tags, SecurityZones, or Sensor IDs.
    - Multiple independent sessions over time may legitimately share the same Community ID.
"""

import logging
from typing import Optional, Union

try:
    import communityid
    from communityid.error import FlowTupleError
except ImportError:  # pragma: no cover
    communityid = None
    FlowTupleError = Exception

logger = logging.getLogger(__name__)

# Protocol mappings to IANA protocol numbers
_PROTO_MAP = {
    "TCP": 6,
    "UDP": 17,
    "ICMP": 1,
    "ICMP6": 58,
    "ICMPV6": 58,
    "SCTP": 132,
}


def _normalize_protocol_number(protocol: Union[str, int]) -> Optional[int]:
    """Normalize a protocol name or number to its IANA integer value."""
    if isinstance(protocol, bool):
        return None
    if isinstance(protocol, int):
        return protocol if 0 <= protocol <= 255 else None
    if isinstance(protocol, str):
        cleaned = protocol.strip().upper()
        if cleaned.isdigit():
            val = int(cleaned)
            return val if 0 <= val <= 255 else None
        return _PROTO_MAP.get(cleaned)
    return None


def compute_community_id(
    ip_src: str,
    ip_dst: str,
    protocol: Union[str, int],
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    seed: int = 0,
) -> Optional[str]:
    """Compute standard Community ID v1 from network 5-tuple components.

    Args:
        ip_src: Source IPv4 or IPv6 address string.
        ip_dst: Destination IPv4 or IPv6 address string.
        protocol: Transport protocol string (e.g. 'TCP', 'UDP', 'ICMP') or IANA integer (6, 17, 1).
        src_port: Source transport port (required for TCP/UDP; ICMP message type).
        dst_port: Destination transport port (required for TCP/UDP; ICMP message code).
        seed: 16-bit integer seed value (default: 0).

    Returns:
        Standard Community ID v1 string (e.g. '1:LQU9qZlK+B5F3KDmev6m5PMibrg='),
        or None if inputs are insufficient, malformed, or protocol is unsupported.
    """
    if communityid is None:  # pragma: no cover
        logger.warning("communityid package is not installed; cannot compute Community ID")
        return None

    if not ip_src or not ip_dst or protocol is None:
        return None

    proto_num = _normalize_protocol_number(protocol)
    if proto_num is None:
        logger.debug("Unsupported or invalid protocol for Community ID: %r", protocol)
        return None

    try:
        clean_src = str(ip_src).strip()
        clean_dst = str(ip_dst).strip()

        if proto_num == 6:  # TCP
            if src_port is None or dst_port is None or isinstance(src_port, bool) or isinstance(dst_port, bool):
                return None
            s_port = int(src_port)
            d_port = int(dst_port)
            if not (0 <= s_port <= 65535 and 0 <= d_port <= 65535):
                return None
            tpl = communityid.FlowTuple.make_tcp(clean_src, clean_dst, s_port, d_port)
        elif proto_num == 17:  # UDP
            if src_port is None or dst_port is None or isinstance(src_port, bool) or isinstance(dst_port, bool):
                return None
            s_port = int(src_port)
            d_port = int(dst_port)
            if not (0 <= s_port <= 65535 and 0 <= d_port <= 65535):
                return None
            tpl = communityid.FlowTuple.make_udp(clean_src, clean_dst, s_port, d_port)
        elif proto_num == 132:  # SCTP
            if src_port is None or dst_port is None or isinstance(src_port, bool) or isinstance(dst_port, bool):
                return None
            s_port = int(src_port)
            d_port = int(dst_port)
            if not (0 <= s_port <= 65535 and 0 <= d_port <= 65535):
                return None
            tpl = communityid.FlowTuple.make_sctp(clean_src, clean_dst, s_port, d_port)
        elif proto_num == 1:  # ICMP
            if isinstance(src_port, bool) or isinstance(dst_port, bool):
                return None
            mtype = int(src_port) if src_port is not None else 0
            mcode = int(dst_port) if dst_port is not None else 0
            tpl = communityid.FlowTuple.make_icmp(clean_src, clean_dst, mtype, mcode)
        elif proto_num == 58:  # ICMPv6
            if isinstance(src_port, bool) or isinstance(dst_port, bool):
                return None
            mtype = int(src_port) if src_port is not None else 0
            mcode = int(dst_port) if dst_port is not None else 0
            tpl = communityid.FlowTuple.make_icmp6(clean_src, clean_dst, mtype, mcode)
        else:
            tpl = communityid.FlowTuple.make_ip(clean_src, clean_dst, proto_num)

        cid = communityid.CommunityID(seed=seed)
        return cid.calc(tpl)

    except (FlowTupleError, ValueError, TypeError, OSError) as exc:
        logger.debug("Community ID calculation failed for (%s, %s, %s, %s, %s): %s",
                     ip_src, ip_dst, protocol, src_port, dst_port, exc)
        return None


def resolve_community_id(
    existing_id: Optional[str] = None,
    ip_src: Optional[str] = None,
    ip_dst: Optional[str] = None,
    protocol: Optional[Union[str, int]] = None,
    src_port: Optional[int] = None,
    dst_port: Optional[int] = None,
    seed: int = 0,
) -> Optional[str]:
    """Resolve Community ID by preserving an existing ID or computing from tuple.

    If `existing_id` is present as a non-empty string, it is trimmed and preserved
    as an opaque correlation identifier (supporting any Community ID version without
    rewriting). Empty or whitespace-only strings are treated as unavailable.
    If `existing_id` is unavailable, Community ID is computed from tuple parameters.

    Returns:
        Preserved or computed Community ID string, or None if unavailable.
    """
    if existing_id is not None:
        trimmed = str(existing_id).strip()
        if trimmed:
            return trimmed

    if not (ip_src and ip_dst and protocol is not None):
        return None

    return compute_community_id(
        ip_src=ip_src,
        ip_dst=ip_dst,
        protocol=protocol,
        src_port=src_port,
        dst_port=dst_port,
        seed=seed,
    )
