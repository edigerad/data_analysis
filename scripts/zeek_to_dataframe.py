#!/usr/bin/env python3
"""Parse Zeek logs (TSV or JSON) into pandas DataFrames.

Designed for offline PCAP analysis where Zeek produces newline-delimited JSON
(LogAscii::use_json=T) with ISO 8601 timestamps (LogAscii::json_timestamps=JSON::TS_ISO8601).

Also supports Zeek's default TSV format for backward compatibility.
"""

import json
import sys
from pathlib import Path

import pandas as pd

# ---------------------------------------------------------------------------
# Zeek-specific constants
# ---------------------------------------------------------------------------

# Columns that carry epoch or ISO 8601 timestamps in Zeek JSON output.
# Zeek always names the primary timestamp "ts"; some logs have secondary ones.
_TIMESTAMP_COLUMNS = {"ts", "start_time", "end_time"}

# Zeek TSV sentinel values for missing data
_TSV_NA_VALUES = ["-", "(empty)"]

# conn.log column ordering and expected types — used to enforce a stable schema
# even when the PCAP produces only a subset of fields.
CONN_SCHEMA: dict[str, str] = {
    "ts": "datetime64[ns, UTC]",
    "uid": "string",
    "id.orig_h": "string",
    "id.orig_p": "Int64",
    "id.resp_h": "string",
    "id.resp_p": "Int64",
    "proto": "string",
    "service": "string",
    "duration": "Float64",
    "orig_bytes": "Int64",
    "resp_bytes": "Int64",
    "conn_state": "string",
    "missed_bytes": "Int64",
    "history": "string",
    "orig_pkts": "Int64",
    "resp_pkts": "Int64",
    "orig_ip_bytes": "Int64",
    "resp_ip_bytes": "Int64",
}

DNS_SCHEMA: dict[str, str] = {
    "ts": "datetime64[ns, UTC]",
    "uid": "string",
    "id.orig_h": "string",
    "id.orig_p": "Int64",
    "id.resp_h": "string",
    "id.resp_p": "Int64",
    "proto": "string",
    "trans_id": "Int64",
    "rtt": "Float64",
    "query": "string",
    "qclass": "Int64",
    "qclass_name": "string",
    "qtype": "Int64",
    "qtype_name": "string",
    "rcode": "Int64",
    "rcode_name": "string",
    "AA": "boolean",
    "TC": "boolean",
    "RD": "boolean",
    "RA": "boolean",
    "Z": "Int64",
    "answers": "object",  # list[str] — stays as Python list
    "TTLs": "object",  # list[float]
    "rejected": "boolean",
}


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------

def _detect_format(path: Path) -> str:
    """Return 'json' or 'tsv' by inspecting the first line of a Zeek log."""
    with open(path) as f:
        first_line = f.readline()
    if first_line.startswith("#"):
        return "tsv"
    try:
        json.loads(first_line)
        return "json"
    except (json.JSONDecodeError, ValueError):
        return "tsv"


# ---------------------------------------------------------------------------
# JSON loader (primary path)
# ---------------------------------------------------------------------------

def load_zeek_json(
    path: str | Path,
    schema: dict[str, str] | None = None,
) -> pd.DataFrame:
    """Load a Zeek newline-delimited JSON log into a DataFrame.

    Parameters
    ----------
    path : str | Path
        Path to a Zeek JSON log file (one JSON object per line).
    schema : dict[str, str] | None
        Optional column-name-to-dtype mapping.  When provided:
        - Missing columns are added and filled with pd.NA.
        - Columns are cast to the specified nullable dtypes.
        - Column order follows the schema key order.
        Pass ``CONN_SCHEMA`` or ``DNS_SCHEMA`` for the two primary log types.

    Returns
    -------
    pd.DataFrame
    """
    path = Path(path)
    df = pd.read_json(path, lines=True)

    # -- Timestamps ----------------------------------------------------------
    # Zeek JSON timestamps are either epoch floats (default) or ISO 8601
    # strings (when json_timestamps = JSON::TS_ISO8601).  Handle both.
    for col in df.columns:
        if col in _TIMESTAMP_COLUMNS:
            df[col] = pd.to_datetime(df[col], utc=True, errors="coerce")

    # -- Schema enforcement --------------------------------------------------
    if schema is not None:
        df = _apply_schema(df, schema)

    return df


# ---------------------------------------------------------------------------
# TSV loader (backward compatibility)
# ---------------------------------------------------------------------------

def _load_zeek_tsv(path: Path) -> pd.DataFrame:
    """Parse Zeek's native tab-separated format with #fields/#types headers."""
    columns: list[str] = []
    types_line: list[str] = []

    with open(path) as f:
        for line in f:
            if not line.startswith("#"):
                break
            if line.startswith("#fields"):
                columns = line.strip().split("\t")[1:]
            elif line.startswith("#types"):
                types_line = line.strip().split("\t")[1:]

    df = pd.read_csv(
        path,
        sep="\t",
        comment="#",
        header=None,
        names=columns if columns else None,
        na_values=_TSV_NA_VALUES,
        low_memory=False,
    )

    for col, ztype in zip(columns, types_line, strict=False):
        if ztype == "time" and col in df.columns:
            df[col] = pd.to_datetime(df[col], unit="s", utc=True, errors="coerce")

    return df


# ---------------------------------------------------------------------------
# Schema enforcement
# ---------------------------------------------------------------------------

def _apply_schema(df: pd.DataFrame, schema: dict[str, str]) -> pd.DataFrame:
    """Ensure every column in *schema* exists with the correct nullable dtype.

    Columns present in the DataFrame but absent from the schema are kept
    (appended after the schema columns).
    """
    for col, dtype in schema.items():
        if col not in df.columns:
            df[col] = pd.NA

        # Skip datetime columns — already converted above
        if "datetime" in dtype:
            continue

        try:
            df[col] = df[col].astype(dtype)
        except (ValueError, TypeError):
            pass  # keep original dtype if cast fails

    # Reorder: schema columns first, then any extras
    ordered = [c for c in schema if c in df.columns]
    extras = [c for c in df.columns if c not in schema]
    return df[ordered + extras]


# ---------------------------------------------------------------------------
# Unified entry point
# ---------------------------------------------------------------------------

def load_zeek_log(
    path: str | Path,
    schema: dict[str, str] | None = None,
) -> pd.DataFrame:
    """Read a Zeek log file (TSV or JSON) into a DataFrame.

    Auto-detects the format by inspecting the first line.
    """
    path = Path(path)
    fmt = _detect_format(path)
    if fmt == "json":
        return load_zeek_json(path, schema=schema)
    return _load_zeek_tsv(path)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <zeek_log> [output.parquet]")
        sys.exit(1)

    input_path = Path(sys.argv[1])
    output_path = (
        Path(sys.argv[2]) if len(sys.argv) > 2 else input_path.with_suffix(".parquet")
    )

    df = load_zeek_log(input_path)
    df.to_parquet(output_path, index=False)
    print(f"Wrote {len(df)} rows to {output_path}")


if __name__ == "__main__":
    main()
