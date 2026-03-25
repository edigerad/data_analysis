#!/usr/bin/env python3
"""ECS Standardization Pipeline Entry Point.

This script orchestrates the complete process of converting Zeek network logs
to Elastic Common Schema (ECS) format with robust validation and reporting.

Pipeline Stages:
    1. RAW        - Load Zeek JSON logs
    2. NORMALIZE  - Apply unified internal schema
    3. ENRICH     - Add threat intelligence flags
    4. STANDARDIZE - Convert to ECS fields
    5. VALIDATE   - Check data types and constraints
    6. EXPORT     - Save ECS dataset and validation report

Output Structure:
    outputs/
    ├── ecs/
    │   ├── ecs_events.csv              # Final ECS-compliant dataset
    │   ├── ecs_events.parquet          # Binary format for efficiency
    │   └── ecs_conn_only.csv           # Connection logs only (ECS)
    ├── validation/
    │   ├── validation_report.json      # Detailed validation results
    │   └── mapping_coverage.json       # Field mapping statistics
    └── versioned/
        └── v{timestamp}/               # Timestamped pipeline runs
            ├── ecs_events.csv
            └── validation_report.json

Usage:
    # Standard run
    python scripts/standardize_to_ecs.py

    # Custom paths
    python scripts/standardize_to_ecs.py --zeek-dir data/zeek_logs/my_capture

    # Strict validation mode
    python scripts/standardize_to_ecs.py --strict

    # Output specific log type only
    python scripts/standardize_to_ecs.py --log-type conn
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
from scripts.normalize import normalize_conn, normalize_dns, merge_normalized
from scripts.enrich_ti import ThreatIntel, enrich_ti_fast
from scripts.ecs_mapper import (
    ECSMapper,
    MappingReport,
    save_validation_report,
    print_mapping_summary,
    generate_before_after_example,
    NORMALIZED_TO_ECS_MAPPING,
)


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


def log_stage(stage: str, message: str) -> None:
    """Print a formatted log message."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{stage:12s}] {message}")


def create_output_dirs(output_dir: Path) -> dict[str, Path]:
    """Create output directory structure."""
    dirs = {
        "ecs": output_dir / "ecs",
        "validation": output_dir / "validation",
        "versioned": output_dir / "versioned" / f"v{datetime.now().strftime('%Y%m%d_%H%M%S')}",
    }
    for d in dirs.values():
        d.mkdir(parents=True, exist_ok=True)
    return dirs


# =============================================================================
# Pipeline Stages
# =============================================================================

def stage_raw_load(zeek_dir: Path) -> tuple[pd.DataFrame | None, pd.DataFrame | None]:
    """Stage 1: Load raw Zeek JSON logs."""
    log_stage("RAW", f"Loading Zeek logs from {zeek_dir}")

    conn_path = zeek_dir / "conn.log"
    dns_path = zeek_dir / "dns.log"

    conn_raw = None
    dns_raw = None

    if conn_path.exists():
        conn_raw = load_zeek_log(conn_path, schema=CONN_SCHEMA)
        log_stage("RAW", f"Loaded conn.log: {len(conn_raw)} rows")
    else:
        log_stage("RAW", f"Warning: conn.log not found at {conn_path}")

    if dns_path.exists():
        dns_raw = load_zeek_log(dns_path, schema=DNS_SCHEMA)
        log_stage("RAW", f"Loaded dns.log: {len(dns_raw)} rows")
    else:
        log_stage("RAW", f"Warning: dns.log not found at {dns_path}")

    if conn_raw is None and dns_raw is None:
        raise FileNotFoundError(f"No Zeek logs found in {zeek_dir}")

    return conn_raw, dns_raw


def stage_normalize(
    conn_raw: pd.DataFrame | None,
    dns_raw: pd.DataFrame | None,
) -> pd.DataFrame:
    """Stage 2: Normalize to unified internal schema."""
    log_stage("NORMALIZE", "Applying unified schema transformations")

    dfs = []

    if conn_raw is not None:
        conn_norm = normalize_conn(conn_raw)
        dfs.append(conn_norm)
        log_stage("NORMALIZE", f"Normalized conn: {len(conn_norm)} rows")

    if dns_raw is not None:
        dns_norm = normalize_dns(dns_raw)
        dfs.append(dns_norm)
        log_stage("NORMALIZE", f"Normalized dns: {len(dns_norm)} rows")

    unified = merge_normalized(*dfs)
    log_stage("NORMALIZE", f"Unified timeline: {len(unified)} rows")

    return unified


def stage_enrich(unified: pd.DataFrame, ti_dir: Path) -> pd.DataFrame:
    """Stage 3: Enrich with threat intelligence."""
    log_stage("ENRICH", f"Loading threat intelligence from {ti_dir}")

    ti = ThreatIntel()
    ti_count = 0

    for ip_file in ti_dir.glob("*_ips.txt"):
        count = ti.load_ip_blacklist(ip_file)
        ti_count += count
        log_stage("ENRICH", f"Loaded {count} IPs from {ip_file.name}")

    for domain_file in ti_dir.glob("*_domains.txt"):
        count = ti.load_domain_blacklist(domain_file)
        ti_count += count
        log_stage("ENRICH", f"Loaded {count} domains from {domain_file.name}")

    if ti_count == 0:
        log_stage("ENRICH", "Warning: No threat intelligence indicators loaded")
        unified["ti_match"] = False
    else:
        # Use vectorized fast enrichment (handles NA values properly)
        unified = enrich_ti_fast(
            unified.copy(),
            ti,
            ip_column="dst_ip",
            domain_column="dns_query" if "dns_query" in unified.columns else None,
        )
        ti_matches = unified["ti_match"].sum()
        log_stage("ENRICH", f"TI enrichment complete: {ti_matches} matches found")

    return unified


def stage_standardize(
    unified: pd.DataFrame,
    strict: bool = False,
) -> tuple[pd.DataFrame, MappingReport]:
    """Stage 4: Convert to ECS schema."""
    log_stage("STANDARDIZE", "Converting to Elastic Common Schema (ECS)")

    mapper = ECSMapper(
        strict_validation=strict,
        add_defaults=True,
        warn_unmapped=True,
    )

    ecs_df, report = mapper.transform(unified, source_type="normalized")

    log_stage(
        "STANDARDIZE",
        f"ECS mapping: {report.mapped_fields}/{report.total_source_fields} fields "
        f"({report.mapping_coverage_pct:.1f}% coverage)"
    )

    return ecs_df, report


def stage_export(
    unified: pd.DataFrame,
    ecs_df: pd.DataFrame,
    report: MappingReport,
    output_dirs: dict[str, Path],
) -> dict[str, str]:
    """Stage 5: Export all outputs with metadata."""
    log_stage("EXPORT", "Saving outputs")

    checksums = {}

    # --- ECS outputs ---
    ecs_csv = output_dirs["ecs"] / "ecs_events.csv"
    ecs_df.to_csv(ecs_csv, index=False)
    checksums["ecs_events.csv"] = compute_checksum(ecs_csv)
    log_stage("EXPORT", f"Saved {ecs_csv.name} ({len(ecs_df)} rows)")

    ecs_parquet = output_dirs["ecs"] / "ecs_events.parquet"
    ecs_df.to_parquet(ecs_parquet, index=False)
    checksums["ecs_events.parquet"] = compute_checksum(ecs_parquet)
    log_stage("EXPORT", f"Saved {ecs_parquet.name}")

    # Connection-only export (for network analysis)
    if "event.dataset" in ecs_df.columns:
        conn_only = ecs_df[ecs_df["event.dataset"] == "conn"]
        if len(conn_only) > 0:
            conn_csv = output_dirs["ecs"] / "ecs_conn_only.csv"
            conn_only.to_csv(conn_csv, index=False)
            log_stage("EXPORT", f"Saved {conn_csv.name} ({len(conn_only)} rows)")

    # --- Validation outputs ---
    report_path = output_dirs["validation"] / "validation_report.json"
    save_validation_report(report, report_path)

    # Mapping coverage summary
    coverage = {
        "field_mapping": {
            src: ecs for src, ecs in NORMALIZED_TO_ECS_MAPPING.items()
        },
        "coverage_statistics": {
            "total_source_fields": report.total_source_fields,
            "mapped_fields": report.mapped_fields,
            "coverage_pct": report.mapping_coverage_pct,
            "unmapped_fields": report.unmapped_fields,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    coverage_path = output_dirs["validation"] / "mapping_coverage.json"
    with open(coverage_path, "w") as f:
        json.dump(coverage, f, indent=2)
    log_stage("EXPORT", f"Saved mapping_coverage.json")

    # --- Versioned outputs ---
    versioned_csv = output_dirs["versioned"] / "ecs_events.csv"
    ecs_df.to_csv(versioned_csv, index=False)

    versioned_report = output_dirs["versioned"] / "validation_report.json"
    save_validation_report(report, versioned_report)

    # Manifest for versioned run
    manifest = {
        "pipeline_version": "2.0.0",
        "schema": "ECS",
        "execution_timestamp": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version,
        "input_rows": report.total_rows,
        "output_rows": len(ecs_df),
        "mapping_coverage_pct": report.mapping_coverage_pct,
        "validation_errors": len(report.validation_errors),
        "checksums": checksums,
    }
    manifest_path = output_dirs["versioned"] / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)

    log_stage("EXPORT", f"Versioned outputs saved to {output_dirs['versioned']}")

    return checksums


# =============================================================================
# Before/After Example Export
# =============================================================================

def export_before_after_example(
    unified: pd.DataFrame,
    ecs_df: pd.DataFrame,
    output_dir: Path,
) -> None:
    """Generate and save before/after mapping example."""
    example_md = generate_before_after_example(unified, ecs_df, n_rows=3)

    example_path = output_dir / "validation" / "before_after_example.md"
    with open(example_path, "w") as f:
        f.write(example_md)

    log_stage("EXPORT", f"Saved before_after_example.md")


# =============================================================================
# Main Pipeline
# =============================================================================

def run_ecs_pipeline(
    zeek_dir: Path,
    output_dir: Path,
    ti_dir: Path,
    strict: bool = False,
    log_type: str | None = None,
) -> None:
    """Execute the complete ECS standardization pipeline."""
    print()
    print("=" * 70)
    print("ECS STANDARDIZATION PIPELINE")
    print("=" * 70)
    print(f"Schema: Elastic Common Schema (ECS)")
    print(f"Reference: https://www.elastic.co/guide/en/ecs/current/")
    print("=" * 70)
    print()

    start_time = datetime.now()

    # Create output directories
    output_dirs = create_output_dirs(output_dir)

    # Stage 1: Load raw Zeek logs
    conn_raw, dns_raw = stage_raw_load(zeek_dir)
    print()

    # Filter by log type if specified
    if log_type == "conn":
        dns_raw = None
        log_stage("FILTER", "Processing connection logs only")
    elif log_type == "dns":
        conn_raw = None
        log_stage("FILTER", "Processing DNS logs only")
    print()

    # Stage 2: Normalize
    unified = stage_normalize(conn_raw, dns_raw)
    print()

    # Stage 3: Enrich with TI
    unified = stage_enrich(unified, ti_dir)
    print()

    # Stage 4: Standardize to ECS
    ecs_df, report = stage_standardize(unified, strict=strict)
    print()

    # Stage 5: Export
    checksums = stage_export(unified, ecs_df, report, output_dirs)
    print()

    # Generate before/after example
    export_before_after_example(unified, ecs_df, output_dir)
    print()

    # Print summary
    elapsed = (datetime.now() - start_time).total_seconds()
    print_mapping_summary(report)

    print("=" * 70)
    print("PIPELINE COMPLETE")
    print("=" * 70)
    print(f"Duration:          {elapsed:.2f} seconds")
    print(f"Input rows:        {report.total_rows:,}")
    print(f"Output rows:       {len(ecs_df):,}")
    print(f"Mapping coverage:  {report.mapping_coverage_pct:.1f}%")
    print(f"Validation errors: {len(report.validation_errors)}")
    print()
    print("Output files:")
    print(f"  - {output_dirs['ecs']}/ecs_events.csv")
    print(f"  - {output_dirs['validation']}/validation_report.json")
    print(f"  - {output_dirs['versioned']}/")
    print()
    print("Checksum (ecs_events.csv):")
    print(f"  {checksums.get('ecs_events.csv', 'N/A')}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="ECS Standardization Pipeline for Zeek Network Logs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Standard run with sample data
    python scripts/standardize_to_ecs.py

    # Custom input directory
    python scripts/standardize_to_ecs.py --zeek-dir /path/to/zeek/logs

    # Strict validation (fails on type errors)
    python scripts/standardize_to_ecs.py --strict

    # Process only connection logs
    python scripts/standardize_to_ecs.py --log-type conn
        """,
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
    parser.add_argument(
        "--ti-dir",
        type=Path,
        default=DEFAULT_TI_DIR,
        help="Directory containing threat intelligence files",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Enable strict validation (raise errors on type mismatches)",
    )
    parser.add_argument(
        "--log-type",
        choices=["conn", "dns"],
        default=None,
        help="Process only specified log type",
    )
    args = parser.parse_args()

    run_ecs_pipeline(
        zeek_dir=args.zeek_dir,
        output_dir=args.output_dir,
        ti_dir=args.ti_dir,
        strict=args.strict,
        log_type=args.log_type,
    )


if __name__ == "__main__":
    main()
