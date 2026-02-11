#!/usr/bin/env python3
"""Normalize Zeek logs into a unified schema for security analytics.

Why normalization matters in cybersecurity:
──────────────────────────────────────────────────────────────────────────────
1. MULTI-SOURCE CORRELATION
   Security data comes from many tools (Zeek, Suricata, firewall logs, EDR).
   Each uses different field names: "src_ip" vs "id.orig_h" vs "source_address".
   Normalization enables JOIN operations across sources without field gymnastics.

2. DETECTION RULE PORTABILITY
   A detection rule like "src_ip in watchlist AND dst_port == 443" works on any
   normalized log, regardless of origin. Without normalization, you need N rules
   for N data sources—a maintenance nightmare that leads to coverage gaps.

3. ENRICHMENT PIPELINES
   Threat intel enrichment (IP reputation, ASN lookup, geolocation) expects
   consistent input fields. Normalization lets you build one enrichment pipeline
   that works for all log types.

4. ANALYST EFFICIENCY
   Analysts shouldn't need to remember that Zeek calls it "id.orig_h" while
   Suricata calls it "src_ip". A unified schema reduces cognitive load and
   training time.

5. STORAGE OPTIMIZATION
   Consistent schemas enable columnar storage (Parquet, ClickHouse) to achieve
   better compression ratios and faster analytical queries.
──────────────────────────────────────────────────────────────────────────────
"""

from typing import Literal

import pandas as pd

# ---------------------------------------------------------------------------
# Unified schema definition
# ---------------------------------------------------------------------------

# These are the canonical field names for network telemetry.
# Matches the Elastic Common Schema (ECS) naming conventions.
UNIFIED_SCHEMA: dict[str, str] = {
    "timestamp": "datetime64[ns, UTC]",
    "log_type": "string",           # "conn", "dns", "http", etc.
    "uid": "string",                # Zeek connection UID (join key)
    "src_ip": "string",
    "src_port": "Int64",
    "dst_ip": "string",
    "dst_port": "Int64",
    "protocol": "string",           # "tcp", "udp", "icmp"
    "service": "string",            # detected application protocol
    "duration_sec": "Float64",
    "bytes_sent": "Int64",
    "bytes_recv": "Int64",
    "packets_sent": "Int64",
    "packets_recv": "Int64",
    "conn_state": "string",         # Zeek connection state (SF, S0, etc.)
    # DNS-specific fields (null for non-DNS)
    "dns_query": "string",
    "dns_qtype": "string",
    "dns_rcode": "string",
    "dns_answers": "object",        # list[str]
}

# ---------------------------------------------------------------------------
# Source-specific field mappings
# ---------------------------------------------------------------------------

# Maps Zeek field names → unified field names
_CONN_FIELD_MAP: dict[str, str] = {
    "ts": "timestamp",
    "uid": "uid",
    "id.orig_h": "src_ip",
    "id.orig_p": "src_port",
    "id.resp_h": "dst_ip",
    "id.resp_p": "dst_port",
    "proto": "protocol",
    "service": "service",
    "duration": "duration_sec",
    "orig_bytes": "bytes_sent",
    "resp_bytes": "bytes_recv",
    "orig_pkts": "packets_sent",
    "resp_pkts": "packets_recv",
    "conn_state": "conn_state",
}

_DNS_FIELD_MAP: dict[str, str] = {
    "ts": "timestamp",
    "uid": "uid",
    "id.orig_h": "src_ip",
    "id.orig_p": "src_port",
    "id.resp_h": "dst_ip",
    "id.resp_p": "dst_port",
    "proto": "protocol",
    "query": "dns_query",
    "qtype_name": "dns_qtype",
    "rcode_name": "dns_rcode",
    "answers": "dns_answers",
}


# ---------------------------------------------------------------------------
# Normalization functions
# ---------------------------------------------------------------------------

def normalize_conn(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize a Zeek conn.log DataFrame to the unified schema."""
    return _normalize(df, _CONN_FIELD_MAP, log_type="conn")


def normalize_dns(df: pd.DataFrame) -> pd.DataFrame:
    """Normalize a Zeek dns.log DataFrame to the unified schema."""
    return _normalize(df, _DNS_FIELD_MAP, log_type="dns")


def _normalize(
    df: pd.DataFrame,
    field_map: dict[str, str],
    log_type: Literal["conn", "dns", "http"],
) -> pd.DataFrame:
    """Apply field mapping and enforce unified schema types."""
    # Rename columns that exist in the source DataFrame
    rename_map = {k: v for k, v in field_map.items() if k in df.columns}
    out = df.rename(columns=rename_map)

    # Add log_type column
    out["log_type"] = log_type

    # Ensure all unified schema columns exist (fill missing with NA)
    for col, dtype in UNIFIED_SCHEMA.items():
        if col not in out.columns:
            out[col] = pd.NA

    # Apply dtypes from unified schema
    for col, dtype in UNIFIED_SCHEMA.items():
        if col not in out.columns:
            continue
        # Skip datetime — should already be converted by loader
        if "datetime" in dtype:
            continue
        # Skip object columns (lists like dns_answers)
        if dtype == "object":
            continue
        try:
            out[col] = out[col].astype(dtype)
        except (ValueError, TypeError):
            pass

    # Select only unified schema columns, in order
    schema_cols = list(UNIFIED_SCHEMA.keys())
    return out[[c for c in schema_cols if c in out.columns]]


def merge_normalized(*dfs: pd.DataFrame) -> pd.DataFrame:
    """Concatenate multiple normalized DataFrames and sort by timestamp.

    Example:
        conn_norm = normalize_conn(conn)
        dns_norm = normalize_dns(dns)
        unified = merge_normalized(conn_norm, dns_norm)
    """
    if not dfs:
        raise ValueError("At least one DataFrame required")

    combined = pd.concat(dfs, ignore_index=True)
    combined = combined.sort_values("timestamp", ignore_index=True)
    return combined


# ---------------------------------------------------------------------------
# Convenience function: load + normalize in one step
# ---------------------------------------------------------------------------

def load_and_normalize(
    path: str,
    log_type: Literal["conn", "dns"],
) -> pd.DataFrame:
    """Load a Zeek log and normalize it to the unified schema.

    Example:
        conn = load_and_normalize("data/zeek_logs/sample/conn.log", "conn")
    """
    from scripts.zeek_to_dataframe import load_zeek_log, CONN_SCHEMA, DNS_SCHEMA

    if log_type == "conn":
        df = load_zeek_log(path, schema=CONN_SCHEMA)
        return normalize_conn(df)
    elif log_type == "dns":
        df = load_zeek_log(path, schema=DNS_SCHEMA)
        return normalize_dns(df)
    else:
        raise ValueError(f"Unknown log_type: {log_type}")
