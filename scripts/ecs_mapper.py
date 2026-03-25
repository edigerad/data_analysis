#!/usr/bin/env python3
"""Elastic Common Schema (ECS) mapper for Zeek network logs.

This module converts Zeek log fields to ECS-compliant field names and validates
data types according to the ECS specification.

ECS Reference: https://www.elastic.co/guide/en/ecs/current/

Field Mapping (Zeek → ECS):
    id.orig_h     → source.ip
    id.resp_h     → destination.ip
    id.orig_p     → source.port
    id.resp_p     → destination.port
    proto         → network.transport
    ts            → @timestamp (UTC)
    uid           → event.id
    service       → network.protocol
    duration      → event.duration
    orig_bytes    → source.bytes
    resp_bytes    → destination.bytes

Usage:
    python scripts/standardize_to_ecs.py

Why ECS Mapping Matters:
──────────────────────────────────────────────────────────────────────────────
1. CROSS-TOOL COMPATIBILITY
   ECS is the standard schema for Elastic Stack (Elasticsearch, Kibana, SIEM).
   Properly mapped data enables out-of-box dashboards and detection rules.

2. CORRELATION ACROSS SOURCES
   When firewall, EDR, and network logs all use source.ip and destination.ip,
   correlation queries become trivial: no field gymnastics required.

3. FUTURE-PROOFING
   Investing in ECS compliance now means your data works with future Elastic
   features, community detection rules, and third-party integrations.

4. ANALYST EFFICIENCY
   Security analysts trained on ECS can immediately understand your data.
   No documentation hunting to find "what does id.orig_h mean?"
──────────────────────────────────────────────────────────────────────────────
"""

import ipaddress
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# =============================================================================
# ECS Field Definitions
# =============================================================================

# Core ECS field mapping: Zeek field → ECS field
ZEEK_TO_ECS_MAPPING: dict[str, str] = {
    # Network connection fields
    "id.orig_h": "source.ip",
    "id.resp_h": "destination.ip",
    "id.orig_p": "source.port",
    "id.resp_p": "destination.port",
    "proto": "network.transport",
    "ts": "@timestamp",
    "uid": "event.id",
    "service": "network.protocol",
    "duration": "event.duration",
    # Byte counts
    "orig_bytes": "source.bytes",
    "resp_bytes": "destination.bytes",
    "orig_pkts": "source.packets",
    "resp_pkts": "destination.packets",
    # Connection state
    "conn_state": "zeek.connection.state",
    "history": "zeek.connection.history",
    "missed_bytes": "zeek.connection.missed_bytes",
    # DNS-specific fields
    "query": "dns.question.name",
    "qtype_name": "dns.question.type",
    "rcode_name": "dns.response_code",
    "answers": "dns.answers.name",
    # HTTP-specific fields
    "method": "http.request.method",
    "host": "url.domain",
    "uri": "url.path",
    "status_code": "http.response.status_code",
    "user_agent": "user_agent.original",
    # SSL/TLS fields
    "server_name": "tls.client.server_name",
    "version": "tls.version",
    "cipher": "tls.cipher",
}

# Normalized field names from our internal schema → ECS
NORMALIZED_TO_ECS_MAPPING: dict[str, str] = {
    "src_ip": "source.ip",
    "dst_ip": "destination.ip",
    "src_port": "source.port",
    "dst_port": "destination.port",
    "protocol": "network.transport",
    "timestamp": "@timestamp",
    "uid": "event.id",
    "service": "network.protocol",
    "duration_sec": "event.duration",
    "bytes_sent": "source.bytes",
    "bytes_recv": "destination.bytes",
    "packets_sent": "source.packets",
    "packets_recv": "destination.packets",
    "conn_state": "zeek.connection.state",
    "log_type": "event.dataset",
    # DNS fields
    "dns_query": "dns.question.name",
    "dns_qtype": "dns.question.type",
    "dns_rcode": "dns.response_code",
    "dns_answers": "dns.answers.name",
    # TI enrichment
    "ti_match": "threat.indicator.matched",
}

# ECS field data types for validation
ECS_FIELD_TYPES: dict[str, str] = {
    "source.ip": "ip",
    "destination.ip": "ip",
    "source.port": "port",
    "destination.port": "port",
    "network.transport": "keyword",
    "@timestamp": "date",
    "event.id": "keyword",
    "network.protocol": "keyword",
    "event.duration": "float",
    "source.bytes": "long",
    "destination.bytes": "long",
    "source.packets": "long",
    "destination.packets": "long",
    "event.dataset": "keyword",
    "event.category": "keyword",
    "event.kind": "keyword",
    "event.type": "keyword",
    "dns.question.name": "keyword",
    "dns.question.type": "keyword",
    "dns.response_code": "keyword",
    "threat.indicator.matched": "boolean",
}

# Default values for missing fields
ECS_DEFAULTS: dict[str, Any] = {
    "event.kind": "event",
    "event.category": "network",
    "event.type": "connection",
}

# Event category mapping based on log type
LOG_TYPE_TO_EVENT_CATEGORY: dict[str, dict[str, str]] = {
    "conn": {"event.category": "network", "event.type": "connection"},
    "dns": {"event.category": "network", "event.type": "protocol"},
    "http": {"event.category": "web", "event.type": "access"},
    "ssl": {"event.category": "network", "event.type": "protocol"},
    "files": {"event.category": "file", "event.type": "info"},
}


# =============================================================================
# Validation Classes
# =============================================================================

@dataclass
class ValidationError:
    """Represents a field validation error."""
    field: str
    value: Any
    expected_type: str
    error_message: str
    row_index: int | None = None


@dataclass
class MappingReport:
    """Summary report of the ECS mapping process."""
    total_rows: int = 0
    total_source_fields: int = 0
    mapped_fields: int = 0
    unmapped_fields: list[str] = field(default_factory=list)
    fields_with_defaults: list[str] = field(default_factory=list)
    validation_errors: list[ValidationError] = field(default_factory=list)
    type_coercion_warnings: list[str] = field(default_factory=list)
    timestamp_range: tuple[str, str] | None = None
    mapping_coverage_pct: float = 0.0

    def to_dict(self) -> dict:
        """Convert report to dictionary for JSON export."""
        return {
            "summary": {
                "total_rows": self.total_rows,
                "total_source_fields": self.total_source_fields,
                "mapped_fields": self.mapped_fields,
                "mapping_coverage_pct": round(self.mapping_coverage_pct, 2),
            },
            "field_analysis": {
                "unmapped_fields": self.unmapped_fields,
                "fields_with_defaults": self.fields_with_defaults,
            },
            "validation": {
                "error_count": len(self.validation_errors),
                "errors": [
                    {
                        "field": e.field,
                        "expected_type": e.expected_type,
                        "message": e.error_message,
                        "sample_value": str(e.value)[:100],
                    }
                    for e in self.validation_errors[:50]  # Limit to 50 samples
                ],
                "type_coercion_warnings": self.type_coercion_warnings[:20],
            },
            "timestamp_range": {
                "earliest": self.timestamp_range[0] if self.timestamp_range else None,
                "latest": self.timestamp_range[1] if self.timestamp_range else None,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }


# =============================================================================
# Validation Functions
# =============================================================================

def validate_ip(value: Any) -> tuple[bool, str | None]:
    """Validate that a value is a valid IP address (IPv4 or IPv6)."""
    if pd.isna(value):
        return True, None  # NA is valid (missing data)

    try:
        ipaddress.ip_address(str(value))
        return True, None
    except ValueError:
        return False, f"Invalid IP address format: {value}"


def validate_port(value: Any) -> tuple[bool, str | None]:
    """Validate that a value is a valid port number (0-65535)."""
    if pd.isna(value):
        return True, None

    try:
        port = int(value)
        if 0 <= port <= 65535:
            return True, None
        return False, f"Port out of range (0-65535): {port}"
    except (ValueError, TypeError):
        return False, f"Invalid port value: {value}"


def validate_timestamp(value: Any) -> tuple[bool, str | None]:
    """Validate and parse timestamp to ISO 8601 UTC format."""
    if pd.isna(value):
        return True, None

    # Already a datetime
    if isinstance(value, (datetime, pd.Timestamp)):
        return True, None

    # Try parsing string formats
    if isinstance(value, str):
        try:
            pd.to_datetime(value)
            return True, None
        except Exception:
            return False, f"Cannot parse timestamp: {value}"

    # Try epoch timestamp
    try:
        float(value)
        return True, None
    except (ValueError, TypeError):
        return False, f"Invalid timestamp format: {value}"


def validate_keyword(value: Any) -> tuple[bool, str | None]:
    """Validate keyword field (string, reasonable length)."""
    if pd.isna(value):
        return True, None

    str_val = str(value)
    if len(str_val) > 10000:
        return False, f"Keyword too long ({len(str_val)} chars, max 10000)"
    return True, None


# Type validator dispatch
def validate_long(v: Any) -> tuple[bool, str | None]:
    """Validate long (integer) values including pandas Int64."""
    if pd.isna(v):
        return True, None
    if isinstance(v, (int, float, np.integer, np.floating)):
        return True, None
    # Try conversion
    try:
        int(v)
        return True, None
    except (ValueError, TypeError):
        return False, f"Expected numeric: {v}"


def validate_float_value(v: Any) -> tuple[bool, str | None]:
    """Validate float values."""
    if pd.isna(v):
        return True, None
    if isinstance(v, (int, float, np.integer, np.floating)):
        return True, None
    try:
        float(v)
        return True, None
    except (ValueError, TypeError):
        return False, f"Expected float: {v}"


def validate_boolean(v: Any) -> tuple[bool, str | None]:
    """Validate boolean values."""
    if pd.isna(v):
        return True, None
    if isinstance(v, (bool, np.bool_)):
        return True, None
    if isinstance(v, (int, np.integer)) and v in (0, 1):
        return True, None
    return False, f"Expected boolean: {v}"


TYPE_VALIDATORS = {
    "ip": validate_ip,
    "port": validate_port,
    "date": validate_timestamp,
    "keyword": validate_keyword,
    "long": validate_long,
    "float": validate_float_value,
    "boolean": validate_boolean,
}


# =============================================================================
# ECS Mapper Class
# =============================================================================

class ECSMapper:
    """Maps Zeek/normalized network logs to Elastic Common Schema (ECS).

    Features:
    - Handles missing fields with configurable defaults
    - Validates data types (IP, port, timestamp)
    - Logs mapping coverage statistics
    - Generates validation report

    Example:
        mapper = ECSMapper()
        ecs_df, report = mapper.transform(df, source_type="normalized")
        ecs_df.to_csv("outputs/ecs_events.csv", index=False)
        report.to_json("outputs/validation_report.json")
    """

    def __init__(
        self,
        strict_validation: bool = False,
        add_defaults: bool = True,
        warn_unmapped: bool = True,
    ):
        """Initialize the ECS mapper.

        Parameters
        ----------
        strict_validation : bool
            If True, raise ValueError on validation errors. Default False.
        add_defaults : bool
            If True, add default ECS fields (event.kind, event.category).
        warn_unmapped : bool
            If True, log warnings for unmapped source fields.
        """
        self.strict_validation = strict_validation
        self.add_defaults = add_defaults
        self.warn_unmapped = warn_unmapped
        self.report = MappingReport()

    def transform(
        self,
        df: pd.DataFrame,
        source_type: str = "normalized",
        log_type: str | None = None,
    ) -> tuple[pd.DataFrame, MappingReport]:
        """Transform DataFrame to ECS schema.

        Parameters
        ----------
        df : pd.DataFrame
            Input DataFrame with Zeek or normalized fields.
        source_type : str
            "zeek" for raw Zeek fields, "normalized" for internal schema.
        log_type : str | None
            Log type (conn, dns, http) for event.category inference.
            If None, attempts to read from 'log_type' column.

        Returns
        -------
        tuple[pd.DataFrame, MappingReport]
            Transformed ECS-compliant DataFrame and validation report.
        """
        logger.info(f"Starting ECS transformation: {len(df)} rows, source_type={source_type}")

        # Reset report
        self.report = MappingReport(
            total_rows=len(df),
            total_source_fields=len(df.columns),
        )

        # Select mapping based on source type
        mapping = ZEEK_TO_ECS_MAPPING if source_type == "zeek" else NORMALIZED_TO_ECS_MAPPING

        # Track which fields were mapped
        mapped_cols = []
        unmapped_cols = []

        # Create output DataFrame
        ecs_df = pd.DataFrame(index=df.index)

        # Apply field mapping
        for src_col in df.columns:
            if src_col in mapping:
                ecs_col = mapping[src_col]
                ecs_df[ecs_col] = df[src_col]
                mapped_cols.append(src_col)
            else:
                unmapped_cols.append(src_col)
                if self.warn_unmapped:
                    logger.debug(f"Unmapped field: {src_col}")

        self.report.mapped_fields = len(mapped_cols)
        self.report.unmapped_fields = unmapped_cols

        # Calculate mapping coverage
        if self.report.total_source_fields > 0:
            self.report.mapping_coverage_pct = (
                self.report.mapped_fields / self.report.total_source_fields * 100
            )

        logger.info(
            f"Field mapping: {self.report.mapped_fields}/{self.report.total_source_fields} "
            f"({self.report.mapping_coverage_pct:.1f}% coverage)"
        )

        # Add default ECS fields
        if self.add_defaults:
            ecs_df = self._add_defaults(ecs_df, df, log_type)

        # Validate and coerce types
        ecs_df = self._validate_and_coerce(ecs_df)

        # Extract timestamp range
        if "@timestamp" in ecs_df.columns:
            try:
                ts_series = pd.to_datetime(ecs_df["@timestamp"], utc=True, errors="coerce")
                valid_ts = ts_series.dropna()
                if len(valid_ts) > 0:
                    self.report.timestamp_range = (
                        valid_ts.min().isoformat(),
                        valid_ts.max().isoformat(),
                    )
            except Exception:
                pass

        # Reorder columns: standard ECS fields first
        ecs_df = self._reorder_columns(ecs_df)

        logger.info(f"ECS transformation complete: {len(ecs_df.columns)} output fields")

        return ecs_df, self.report

    def _add_defaults(
        self,
        ecs_df: pd.DataFrame,
        source_df: pd.DataFrame,
        log_type: str | None,
    ) -> pd.DataFrame:
        """Add default ECS fields based on log type."""
        # event.kind is always "event" for network telemetry
        ecs_df["event.kind"] = "event"
        self.report.fields_with_defaults.append("event.kind")

        # Determine log type from source data or parameter
        if log_type is None and "log_type" in source_df.columns:
            log_types = source_df["log_type"].unique()
            if len(log_types) == 1:
                log_type = str(log_types[0])

        # Set event.category and event.type based on log type
        if log_type and log_type in LOG_TYPE_TO_EVENT_CATEGORY:
            category_info = LOG_TYPE_TO_EVENT_CATEGORY[log_type]
            for field_name, value in category_info.items():
                if field_name not in ecs_df.columns:
                    ecs_df[field_name] = value
                    self.report.fields_with_defaults.append(field_name)
        else:
            # Default network event
            if "event.category" not in ecs_df.columns:
                ecs_df["event.category"] = "network"
                self.report.fields_with_defaults.append("event.category")

        # Infer event.category per row if we have mixed log types
        if "event.dataset" in ecs_df.columns and log_type is None:
            def infer_category(dataset):
                if pd.isna(dataset):
                    return "network"
                ds = str(dataset).lower()
                if ds in LOG_TYPE_TO_EVENT_CATEGORY:
                    return LOG_TYPE_TO_EVENT_CATEGORY[ds].get("event.category", "network")
                return "network"

            ecs_df["event.category"] = ecs_df["event.dataset"].apply(infer_category)

        return ecs_df

    def _validate_and_coerce(self, ecs_df: pd.DataFrame) -> pd.DataFrame:
        """Validate field types and coerce where possible."""
        for col in ecs_df.columns:
            if col not in ECS_FIELD_TYPES:
                continue

            expected_type = ECS_FIELD_TYPES[col]
            validator = TYPE_VALIDATORS.get(expected_type)

            if validator is None:
                continue

            # Sample validation (check first 100 non-null values)
            sample = ecs_df[col].dropna().head(100)

            for idx, value in sample.items():
                is_valid, error_msg = validator(value)
                if not is_valid:
                    self.report.validation_errors.append(
                        ValidationError(
                            field=col,
                            value=value,
                            expected_type=expected_type,
                            error_message=error_msg or "Validation failed",
                            row_index=idx,
                        )
                    )
                    if self.strict_validation:
                        raise ValueError(f"Validation error in {col}: {error_msg}")

            # Type coercion
            if expected_type == "date" and col == "@timestamp":
                try:
                    ecs_df[col] = pd.to_datetime(ecs_df[col], utc=True, errors="coerce")
                    ecs_df[col] = ecs_df[col].dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
                except Exception as e:
                    self.report.type_coercion_warnings.append(
                        f"Timestamp coercion warning for {col}: {e}"
                    )

            elif expected_type in ("long", "port"):
                try:
                    ecs_df[col] = pd.to_numeric(ecs_df[col], errors="coerce").astype("Int64")
                except Exception as e:
                    self.report.type_coercion_warnings.append(
                        f"Numeric coercion warning for {col}: {e}"
                    )

            elif expected_type == "float":
                try:
                    ecs_df[col] = pd.to_numeric(ecs_df[col], errors="coerce")
                except Exception as e:
                    self.report.type_coercion_warnings.append(
                        f"Float coercion warning for {col}: {e}"
                    )

        if self.report.validation_errors:
            logger.warning(
                f"Validation completed with {len(self.report.validation_errors)} errors"
            )
        else:
            logger.info("All field validations passed")

        return ecs_df

    def _reorder_columns(self, ecs_df: pd.DataFrame) -> pd.DataFrame:
        """Reorder columns with standard ECS fields first."""
        # Priority order for ECS fields
        priority_fields = [
            "@timestamp",
            "event.kind",
            "event.category",
            "event.type",
            "event.dataset",
            "event.id",
            "event.duration",
            "source.ip",
            "source.port",
            "source.bytes",
            "source.packets",
            "destination.ip",
            "destination.port",
            "destination.bytes",
            "destination.packets",
            "network.transport",
            "network.protocol",
            "dns.question.name",
            "dns.question.type",
            "dns.response_code",
            "threat.indicator.matched",
        ]

        ordered_cols = []
        for col in priority_fields:
            if col in ecs_df.columns:
                ordered_cols.append(col)

        # Add remaining columns
        for col in ecs_df.columns:
            if col not in ordered_cols:
                ordered_cols.append(col)

        return ecs_df[ordered_cols]


# =============================================================================
# Convenience Functions
# =============================================================================

def map_to_ecs(
    df: pd.DataFrame,
    source_type: str = "normalized",
    log_type: str | None = None,
    strict: bool = False,
) -> tuple[pd.DataFrame, MappingReport]:
    """Convenience function to map DataFrame to ECS.

    Parameters
    ----------
    df : pd.DataFrame
        Input DataFrame.
    source_type : str
        "zeek" for raw Zeek fields, "normalized" for internal schema.
    log_type : str | None
        Log type for event.category inference.
    strict : bool
        If True, raise on validation errors.

    Returns
    -------
    tuple[pd.DataFrame, MappingReport]
        ECS DataFrame and validation report.
    """
    mapper = ECSMapper(strict_validation=strict)
    return mapper.transform(df, source_type=source_type, log_type=log_type)


def save_validation_report(report: MappingReport, path: str | Path) -> None:
    """Save validation report as JSON."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, "w") as f:
        json.dump(report.to_dict(), f, indent=2, default=str)

    logger.info(f"Validation report saved to {path}")


def print_mapping_summary(report: MappingReport) -> None:
    """Print a summary of the mapping process."""
    print("\n" + "=" * 60)
    print("ECS MAPPING SUMMARY")
    print("=" * 60)
    print(f"Total rows processed:     {report.total_rows:,}")
    print(f"Source fields:            {report.total_source_fields}")
    print(f"Mapped to ECS:            {report.mapped_fields}")
    print(f"Mapping coverage:         {report.mapping_coverage_pct:.1f}%")
    print(f"Fields with defaults:     {len(report.fields_with_defaults)}")
    print(f"Validation errors:        {len(report.validation_errors)}")

    if report.timestamp_range:
        print(f"\nTimestamp range:")
        print(f"  From: {report.timestamp_range[0]}")
        print(f"  To:   {report.timestamp_range[1]}")

    if report.unmapped_fields:
        print(f"\nUnmapped fields ({len(report.unmapped_fields)}):")
        for field in report.unmapped_fields[:10]:
            print(f"  - {field}")
        if len(report.unmapped_fields) > 10:
            print(f"  ... and {len(report.unmapped_fields) - 10} more")

    print("=" * 60 + "\n")


# =============================================================================
# Before/After Example Generation
# =============================================================================

def generate_before_after_example(
    source_df: pd.DataFrame,
    ecs_df: pd.DataFrame,
    n_rows: int = 3,
) -> str:
    """Generate a markdown table showing before/after field mapping.

    Returns a formatted markdown string for documentation.
    """
    lines = ["### Before/After Field Mapping Example\n"]

    # Field mapping table
    lines.append("**Field Name Mapping:**\n")
    lines.append("| Zeek/Normalized Field | ECS Field |")
    lines.append("|----------------------|-----------|")

    for src, ecs in NORMALIZED_TO_ECS_MAPPING.items():
        lines.append(f"| `{src}` | `{ecs}` |")

    lines.append("\n**Sample Data Transformation:**\n")

    # Data example
    lines.append("*Before (Normalized Schema):*")
    lines.append("```")
    sample = source_df.head(n_rows).to_string(max_colwidth=30)
    lines.append(sample)
    lines.append("```\n")

    lines.append("*After (ECS Schema):*")
    lines.append("```")
    sample_ecs = ecs_df.head(n_rows).to_string(max_colwidth=30)
    lines.append(sample_ecs)
    lines.append("```")

    return "\n".join(lines)
