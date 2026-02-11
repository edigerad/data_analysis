#!/usr/bin/env python3
"""Reproducible cybersecurity data analysis pipeline.

This script orchestrates the complete pipeline from raw PCAP-derived Zeek logs
to enriched, analysis-ready datasets. Designed for academic evaluation with
emphasis on reproducibility and clear data lineage.

Pipeline Stages:
    1. LOAD      - Parse raw Zeek JSON logs
    2. NORMALIZE - Standardize field names and types
    3. ENRICH    - Add threat intelligence flags
    4. ANALYZE   - Generate statistical findings
    5. EXPORT    - Save final datasets with metadata

Output Structure:
    outputs/
    ├── intermediate/
    │   ├── 01_conn_raw.parquet
    │   ├── 01_dns_raw.parquet
    │   ├── 02_conn_normalized.parquet
    │   ├── 02_dns_normalized.parquet
    │   └── 03_unified_enriched.parquet
    ├── final/
    │   ├── enriched_network_events.csv
    │   ├── investigation_priorities.csv
    │   └── analysis_summary.json
    └── metadata/
        ├── pipeline_manifest.json
        └── data_checksums.json

Usage:
    python scripts/pipeline.py

    # Or with custom paths:
    python scripts/pipeline.py --zeek-dir data/zeek_logs/my_capture --output-dir outputs/run_001
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd

# Ensure project root is in path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from scripts.zeek_to_dataframe import load_zeek_log, CONN_SCHEMA, DNS_SCHEMA
from scripts.normalize import normalize_conn, normalize_dns, merge_normalized, UNIFIED_SCHEMA
from scripts.enrich_ti import ThreatIntel, enrich_ti
from scripts.security_eda import run_analysis, SecurityFindings


# =============================================================================
# Configuration
# =============================================================================

DEFAULT_ZEEK_DIR = PROJECT_ROOT / "data" / "zeek_logs" / "sample"
DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "outputs"
DEFAULT_TI_DIR = PROJECT_ROOT / "data" / "ti"


# =============================================================================
# Utility Functions
# =============================================================================

def compute_checksum(path: Path) -> str:
    """Compute SHA-256 checksum of a file."""
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_dataframe_signature(df: pd.DataFrame) -> dict:
    """Generate a signature for a DataFrame (for reproducibility verification)."""
    return {
        "rows": len(df),
        "columns": len(df.columns),
        "column_names": list(df.columns),
        "dtypes": {col: str(dtype) for col, dtype in df.dtypes.items()},
        "null_counts": df.isna().sum().to_dict(),
    }


def log_stage(stage: str, message: str) -> None:
    """Print a formatted log message."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{stage:10s}] {message}")


# =============================================================================
# Pipeline Stages
# =============================================================================

def stage_load(zeek_dir: Path) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Stage 1: Load raw Zeek JSON logs."""
    log_stage("LOAD", f"Loading Zeek logs from {zeek_dir}")

    conn_path = zeek_dir / "conn.log"
    dns_path = zeek_dir / "dns.log"

    if not conn_path.exists():
        raise FileNotFoundError(f"conn.log not found at {conn_path}")
    if not dns_path.exists():
        raise FileNotFoundError(f"dns.log not found at {dns_path}")

    conn_raw = load_zeek_log(conn_path, schema=CONN_SCHEMA)
    dns_raw = load_zeek_log(dns_path, schema=DNS_SCHEMA)

    log_stage("LOAD", f"Loaded conn.log: {len(conn_raw)} rows, {len(conn_raw.columns)} columns")
    log_stage("LOAD", f"Loaded dns.log: {len(dns_raw)} rows, {len(dns_raw.columns)} columns")

    return conn_raw, dns_raw


def stage_normalize(
    conn_raw: pd.DataFrame,
    dns_raw: pd.DataFrame,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Stage 2: Normalize to unified schema."""
    log_stage("NORMALIZE", "Applying unified schema transformations")

    conn_norm = normalize_conn(conn_raw)
    dns_norm = normalize_dns(dns_raw)
    unified = merge_normalized(conn_norm, dns_norm)

    log_stage("NORMALIZE", f"Normalized conn: {len(conn_norm)} rows")
    log_stage("NORMALIZE", f"Normalized dns: {len(dns_norm)} rows")
    log_stage("NORMALIZE", f"Unified timeline: {len(unified)} rows")

    return conn_norm, dns_norm, unified


def stage_enrich(
    conn: pd.DataFrame,
    dns: pd.DataFrame,
    unified: pd.DataFrame,
    ti_dir: Path,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame, dict]:
    """Stage 3: Enrich with threat intelligence."""
    log_stage("ENRICH", f"Loading threat intelligence from {ti_dir}")

    ti = ThreatIntel()
    ti_stats = {"ip_files": 0, "domain_files": 0, "total_ips": 0, "total_domains": 0}

    # Load all TI files
    for ip_file in ti_dir.glob("*_ips.txt"):
        count = ti.load_ip_blacklist(ip_file)
        ti_stats["ip_files"] += 1
        ti_stats["total_ips"] += count
        log_stage("ENRICH", f"Loaded {count} IPs from {ip_file.name}")

    for domain_file in ti_dir.glob("*_domains.txt"):
        count = ti.load_domain_blacklist(domain_file)
        ti_stats["domain_files"] += 1
        ti_stats["total_domains"] += count
        log_stage("ENRICH", f"Loaded {count} domains from {domain_file.name}")

    # Apply enrichment
    conn_enriched = enrich_ti(conn.copy(), ti, ip_column="dst_ip", domain_column=None)
    dns_enriched = enrich_ti(dns.copy(), ti, ip_column="dst_ip", domain_column="dns_query")
    unified_enriched = merge_normalized(conn_enriched, dns_enriched)

    ti_matches = unified_enriched["ti_match"].sum()
    log_stage("ENRICH", f"TI enrichment complete: {ti_matches} matches found")

    return conn_enriched, dns_enriched, unified_enriched, ti_stats


def stage_analyze(
    conn: pd.DataFrame,
    dns: pd.DataFrame,
    unified: pd.DataFrame,
) -> SecurityFindings:
    """Stage 4: Run security analysis."""
    log_stage("ANALYZE", "Running statistical security analysis")

    findings = run_analysis(conn, dns, unified)

    log_stage("ANALYZE", f"Failed connection rate: {findings.failed_connection_rate}%")
    log_stage("ANALYZE", f"NXDOMAIN rate: {findings.nxdomain_rate}%")
    log_stage("ANALYZE", f"Hosts to investigate: {len(findings.hosts_to_investigate)}")

    return findings


def stage_export(
    conn_raw: pd.DataFrame,
    dns_raw: pd.DataFrame,
    conn_norm: pd.DataFrame,
    dns_norm: pd.DataFrame,
    unified_enriched: pd.DataFrame,
    findings: SecurityFindings,
    ti_stats: dict,
    output_dir: Path,
    zeek_dir: Path,
) -> dict:
    """Stage 5: Export all outputs with metadata."""
    log_stage("EXPORT", f"Saving outputs to {output_dir}")

    # Create directory structure
    intermediate_dir = output_dir / "intermediate"
    final_dir = output_dir / "final"
    metadata_dir = output_dir / "metadata"

    for d in [intermediate_dir, final_dir, metadata_dir]:
        d.mkdir(parents=True, exist_ok=True)

    checksums = {}

    # --- Intermediate outputs (Parquet for efficiency) ---
    intermediate_files = [
        ("01_conn_raw.parquet", conn_raw),
        ("01_dns_raw.parquet", dns_raw),
        ("02_conn_normalized.parquet", conn_norm),
        ("02_dns_normalized.parquet", dns_norm),
        ("03_unified_enriched.parquet", unified_enriched),
    ]

    for filename, df in intermediate_files:
        path = intermediate_dir / filename
        df.to_parquet(path, index=False)
        checksums[f"intermediate/{filename}"] = compute_checksum(path)
        log_stage("EXPORT", f"Saved {filename} ({len(df)} rows)")

    # --- Final outputs (CSV for portability) ---

    # Main enriched dataset
    csv_path = final_dir / "enriched_network_events.csv"
    unified_enriched.to_csv(csv_path, index=False)
    checksums["final/enriched_network_events.csv"] = compute_checksum(csv_path)
    log_stage("EXPORT", f"Saved enriched_network_events.csv ({len(unified_enriched)} rows)")

    # Investigation priorities
    if findings.hosts_to_investigate:
        priorities_df = pd.DataFrame(findings.hosts_to_investigate)
        priorities_df["flags"] = priorities_df["flags"].apply(lambda x: ", ".join(x))
        priorities_path = final_dir / "investigation_priorities.csv"
        priorities_df.to_csv(priorities_path, index=False)
        checksums["final/investigation_priorities.csv"] = compute_checksum(priorities_path)
        log_stage("EXPORT", f"Saved investigation_priorities.csv ({len(priorities_df)} rows)")

    # Analysis summary (JSON)
    summary = {
        "dataset_stats": {
            "total_connections": findings.total_connections,
            "total_dns_queries": findings.total_dns_queries,
            "total_events": len(unified_enriched),
        },
        "protocol_distribution": findings.protocol_distribution,
        "anomaly_indicators": {
            "failed_connection_rate_pct": findings.failed_connection_rate,
            "nxdomain_rate_pct": findings.nxdomain_rate,
            "ti_matches": findings.ti_matches,
        },
        "hosts_flagged": len(findings.hosts_to_investigate),
        "ti_sources": ti_stats,
    }
    summary_path = final_dir / "analysis_summary.json"
    with open(summary_path, "w") as f:
        json.dump(summary, f, indent=2, default=str)
    checksums["final/analysis_summary.json"] = compute_checksum(summary_path)
    log_stage("EXPORT", "Saved analysis_summary.json")

    # --- Metadata for reproducibility ---

    # Pipeline manifest
    manifest = {
        "pipeline_version": "1.0.0",
        "execution_timestamp": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "input_paths": {
            "zeek_dir": str(zeek_dir),
            "ti_dir": str(DEFAULT_TI_DIR),
        },
        "output_path": str(output_dir),
        "stages_completed": ["LOAD", "NORMALIZE", "ENRICH", "ANALYZE", "EXPORT"],
        "unified_schema": UNIFIED_SCHEMA,
    }
    manifest_path = metadata_dir / "pipeline_manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2, default=str)

    # Checksums
    checksums_path = metadata_dir / "data_checksums.json"
    with open(checksums_path, "w") as f:
        json.dump(checksums, f, indent=2)

    log_stage("EXPORT", "Saved pipeline metadata")

    return checksums


# =============================================================================
# Main Pipeline
# =============================================================================

def run_pipeline(zeek_dir: Path, output_dir: Path) -> None:
    """Execute the complete pipeline."""
    print("=" * 60)
    print("CYBERSECURITY DATA ANALYSIS PIPELINE")
    print("=" * 60)
    print()

    start_time = datetime.now()

    # Stage 1: Load
    conn_raw, dns_raw = stage_load(zeek_dir)
    print()

    # Stage 2: Normalize
    conn_norm, dns_norm, unified = stage_normalize(conn_raw, dns_raw)
    print()

    # Stage 3: Enrich
    conn_enriched, dns_enriched, unified_enriched, ti_stats = stage_enrich(
        conn_norm, dns_norm, unified, DEFAULT_TI_DIR
    )
    print()

    # Stage 4: Analyze
    findings = stage_analyze(conn_enriched, dns_enriched, unified_enriched)
    print()

    # Stage 5: Export
    checksums = stage_export(
        conn_raw, dns_raw,
        conn_norm, dns_norm,
        unified_enriched,
        findings,
        ti_stats,
        output_dir,
        zeek_dir,
    )
    print()

    # Summary
    elapsed = (datetime.now() - start_time).total_seconds()
    print("=" * 60)
    print("PIPELINE COMPLETE")
    print("=" * 60)
    print(f"Duration: {elapsed:.2f} seconds")
    print(f"Output directory: {output_dir}")
    print()
    print("Final outputs:")
    print(f"  - {output_dir}/final/enriched_network_events.csv")
    print(f"  - {output_dir}/final/investigation_priorities.csv")
    print(f"  - {output_dir}/final/analysis_summary.json")
    print()
    print("To verify reproducibility, compare checksums in:")
    print(f"  - {output_dir}/metadata/data_checksums.json")


def main():
    parser = argparse.ArgumentParser(
        description="Reproducible cybersecurity data analysis pipeline"
    )
    parser.add_argument(
        "--zeek-dir",
        type=Path,
        default=DEFAULT_ZEEK_DIR,
        help="Directory containing Zeek logs (conn.log, dns.log)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Output directory for results",
    )
    args = parser.parse_args()

    run_pipeline(args.zeek_dir, args.output_dir)


if __name__ == "__main__":
    main()
