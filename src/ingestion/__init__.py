"""
Ingestion module for network traffic and security alert data.
"""

from src.ingestion.models import TrafficRecord, AlertRecord, IngestionSummary
from src.ingestion.traffic_parser import parse_traffic_file
from src.ingestion.alert_parser import parse_alert_file
from src.ingestion.v2_models import ZeekConnectionObservation
from src.ingestion.zeek_conn_parser import (
    ZeekConnStream,
    iter_zeek_conn_lines,
    stream_zeek_conn_file,
    parse_zeek_conn_file,
)

__all__ = [
    "TrafficRecord",
    "AlertRecord",
    "IngestionSummary",
    "parse_traffic_file",
    "parse_alert_file",
    "ZeekConnectionObservation",
    "ZeekConnStream",
    "iter_zeek_conn_lines",
    "stream_zeek_conn_file",
    "parse_zeek_conn_file",
]
