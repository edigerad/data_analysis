#!/usr/bin/env python3
"""Time series construction with SMA-based anomaly detection.

Simple Moving Average (SMA) as a Baseline for Anomaly Detection
──────────────────────────────────────────────────────────────────────────────

SMA smooths short-term fluctuations by averaging the last W observations.
An anomaly is flagged when the current value exceeds the SMA by a factor K,
indicating a sudden departure from recent normal behavior.

Why SMA:
  - Transparent and interpretable: analysts can verify results manually.
  - No distributional assumptions (unlike z-score which assumes normality).
  - Computationally trivial — runs in O(n) with constant memory.

Limitations:
  - Assumes local stationarity within the window; non-stationary traffic
    (e.g., business-hours vs. night) may cause false positives.
  - Equal weighting of all W points — exponential moving average (EMA) may
    be more responsive for real-time detection.
  - Seasonality (daily/weekly patterns) is not modeled; dedicated seasonal
    decomposition (STL, SARIMA) would be required for production.

Usage:
    python scripts/time_series_sma_anomaly.py
    python scripts/time_series_sma_anomaly.py --input outputs/ecs/ecs_events.csv
    python scripts/time_series_sma_anomaly.py --window 5 --multiplier 1.5 --bucket 30s
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

import matplotlib
matplotlib.use("Agg")  # non-interactive backend for headless environments
import matplotlib.pyplot as plt
import pandas as pd

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).parent.parent

DEFAULT_INPUT_PATHS = [
    PROJECT_ROOT / "outputs" / "ecs" / "ecs_events.csv",
    PROJECT_ROOT / "outputs" / "final" / "enriched_network_events.csv",
]

DEFAULT_OUTPUT_DIR = PROJECT_ROOT / "outputs"

DEFAULT_BUCKET = "1min"
DEFAULT_WINDOW = 10
DEFAULT_MULTIPLIER = 2.0

# Zeek failed-connection states (incomplete handshake, reset, rejected)
FAILED_CONN_STATES = {"S0", "REJ", "RSTO", "RSTR", "S1", "S2", "S3"}

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def _resolve_input(path: Path | None) -> Path:
    """Return the first existing CSV among candidates."""
    if path is not None:
        if path.exists():
            return path
        raise FileNotFoundError(f"Specified input not found: {path}")

    for candidate in DEFAULT_INPUT_PATHS:
        if candidate.exists():
            return candidate

    raise FileNotFoundError(
        "No input CSV found. Tried: "
        + ", ".join(str(p) for p in DEFAULT_INPUT_PATHS)
    )


def load_events(path: Path) -> pd.DataFrame:
    """Load CSV and parse the timestamp column as UTC datetime."""
    df = pd.read_csv(path)

    # Detect timestamp column
    ts_col: str | None = None
    for candidate in ("@timestamp", "timestamp"):
        if candidate in df.columns:
            ts_col = candidate
            break

    if ts_col is None:
        raise ValueError(
            f"No timestamp column found in {path}. "
            f"Expected '@timestamp' or 'timestamp'. Got: {list(df.columns)}"
        )

    df[ts_col] = pd.to_datetime(df[ts_col], utc=True)
    df = df.rename(columns={ts_col: "timestamp"})
    return df


# ---------------------------------------------------------------------------
# Time-series aggregation
# ---------------------------------------------------------------------------

def build_time_series(
    df: pd.DataFrame,
    bucket: str = DEFAULT_BUCKET,
) -> pd.DataFrame:
    """Aggregate raw events into fixed-width time buckets.

    Returns a DataFrame indexed by ``time_bucket`` with columns:
        connections, nxdomain, failed
    """
    ts = df.set_index("timestamp").sort_index()

    # --- connections per bucket (all rows) ---
    connections = ts.resample(bucket).size().rename("connections")

    # --- nxdomain per bucket ---
    nxdomain: pd.Series | None = None
    rcode_col = _find_column(df, ["dns.response_code", "dns_rcode"])
    if rcode_col is not None:
        nxdomain = (
            ts[rcode_col]
            .eq("NXDOMAIN")
            .resample(bucket)
            .sum()
            .rename("nxdomain")
            .astype(int)
        )
    else:
        logger.warning("No DNS response-code column found; nxdomain metric skipped.")

    # --- failed connections per bucket ---
    failed: pd.Series | None = None
    state_col = _find_column(df, ["zeek.connection.state", "conn_state"])
    if state_col is not None:
        failed = (
            ts[state_col]
            .isin(FAILED_CONN_STATES)
            .resample(bucket)
            .sum()
            .rename("failed")
            .astype(int)
        )
    else:
        logger.warning("No connection-state column found; failed metric skipped.")

    # --- assemble ---
    parts = [connections]
    if nxdomain is not None:
        parts.append(nxdomain)
    if failed is not None:
        parts.append(failed)

    result = pd.concat(parts, axis=1).fillna(0).astype(int)
    result.index.name = "time_bucket"

    # Ensure columns always present (even if zero-filled)
    for col in ("nxdomain", "failed"):
        if col not in result.columns:
            result[col] = 0

    return result


def _find_column(df: pd.DataFrame, candidates: list[str]) -> str | None:
    """Return the first column name present in *df*, or None."""
    for c in candidates:
        if c in df.columns:
            return c
    return None


# ---------------------------------------------------------------------------
# SMA + anomaly detection
# ---------------------------------------------------------------------------

def add_sma_and_anomalies(
    ts_df: pd.DataFrame,
    window: int = DEFAULT_WINDOW,
    multiplier: float = DEFAULT_MULTIPLIER,
) -> pd.DataFrame:
    """Add SMA and anomaly flag for the ``connections`` column.

    New columns:
        sma_connections      – rolling mean with window *W*
        anomaly_connections  – True when connections > sma * K
    """
    result = ts_df.copy()

    result["sma_connections"] = (
        result["connections"]
        .rolling(window=window, min_periods=1)
        .mean()
    )

    # Anomaly: value exceeds SMA * K.  First W-1 buckets where the SMA
    # hasn't fully stabilised use min_periods=1 so they still get an SMA
    # value; the comparison is therefore valid for every row.
    result["anomaly_connections"] = (
        result["connections"] > result["sma_connections"] * multiplier
    )

    # For the very first bucket SMA == connections, so the condition
    # connections > connections * K (K>=1) is always False — which is the
    # desired conservative behaviour.
    return result


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def save_csv(ts_df: pd.DataFrame, output_dir: Path) -> Path:
    """Save the time series DataFrame to CSV."""
    out = output_dir / "time_series_1min.csv"
    ts_df.to_csv(out)
    logger.info("Saved time series CSV → %s", out)
    return out


def save_anomaly_summary(
    ts_df: pd.DataFrame,
    params: dict,
    output_dir: Path,
) -> Path:
    """Write anomaly_summary.json."""
    anomaly_mask = ts_df["anomaly_connections"]
    anomaly_times = ts_df.index[anomaly_mask]

    summary = {
        "total_buckets": int(len(ts_df)),
        "total_anomalies": int(anomaly_mask.sum()),
        "top_anomaly_times": [
            t.isoformat() for t in anomaly_times[:10]
        ],
        "parameters_used": params,
    }

    out = output_dir / "anomaly_summary.json"
    out.write_text(json.dumps(summary, indent=2, ensure_ascii=False))
    logger.info("Saved anomaly summary → %s", out)
    return out


def save_plot(ts_df: pd.DataFrame, output_dir: Path) -> Path:
    """Plot connections + SMA with anomaly markers and save to PNG."""
    fig, ax = plt.subplots(figsize=(12, 5))

    ax.plot(
        ts_df.index, ts_df["connections"],
        label="Connections per bucket",
        color="#1f77b4", linewidth=1.2,
    )
    ax.plot(
        ts_df.index, ts_df["sma_connections"],
        label="SMA",
        color="#ff7f0e", linewidth=1.5, linestyle="--",
    )

    # Mark anomaly points
    anomalies = ts_df[ts_df["anomaly_connections"]]
    if len(anomalies) > 0:
        ax.scatter(
            anomalies.index, anomalies["connections"],
            color="red", zorder=5, s=60, label="Anomaly",
        )

    ax.set_xlabel("Time")
    ax.set_ylabel("Event count")
    ax.set_title("Network Connections with SMA Baseline & Anomaly Detection")
    ax.legend()
    fig.tight_layout()

    out = output_dir / "sma_anomalies.png"
    fig.savefig(out, dpi=150)
    plt.close(fig)
    logger.info("Saved plot → %s", out)
    return out


# ---------------------------------------------------------------------------
# CLI entry-point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build time series from network events, compute SMA, detect anomalies.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Path to input CSV (default: auto-detect in outputs/)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Output directory for results",
    )
    parser.add_argument(
        "--bucket",
        type=str,
        default=DEFAULT_BUCKET,
        help="Time bucket size as pandas offset string (default: 1min)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=DEFAULT_WINDOW,
        help="SMA window size in number of buckets (default: 10)",
    )
    parser.add_argument(
        "--multiplier",
        type=float,
        default=DEFAULT_MULTIPLIER,
        help="Anomaly multiplier K: flag when value > SMA * K (default: 2.0)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)-8s %(message)s",
        datefmt="%H:%M:%S",
    )

    # 1. Load
    input_path = _resolve_input(args.input)
    logger.info("Loading events from %s", input_path)
    events = load_events(input_path)
    logger.info("Loaded %d events (%s → %s)",
                len(events),
                events["timestamp"].min(),
                events["timestamp"].max())

    # 2. Aggregate into time buckets
    ts_df = build_time_series(events, bucket=args.bucket)
    logger.info("Aggregated into %d time buckets (%s)", len(ts_df), args.bucket)

    # 3. SMA + anomaly detection
    ts_df = add_sma_and_anomalies(ts_df, window=args.window, multiplier=args.multiplier)
    n_anomalies = ts_df["anomaly_connections"].sum()
    logger.info("Detected %d anomalous buckets (W=%d, K=%.1f)",
                n_anomalies, args.window, args.multiplier)

    # 4. Save outputs
    args.output_dir.mkdir(parents=True, exist_ok=True)

    save_csv(ts_df, args.output_dir)

    params = {
        "input": str(input_path),
        "bucket": args.bucket,
        "window": args.window,
        "multiplier": args.multiplier,
    }
    save_anomaly_summary(ts_df, params, args.output_dir)

    save_plot(ts_df, args.output_dir)

    # 5. Console summary
    print()
    print("=" * 60)
    print("TIME SERIES SMA ANOMALY DETECTION — SUMMARY")
    print("=" * 60)
    print(f"  Input file:         {input_path.name}")
    print(f"  Total events:       {len(events)}")
    print(f"  Bucket size:        {args.bucket}")
    print(f"  Time buckets:       {len(ts_df)}")
    print(f"  SMA window (W):     {args.window}")
    print(f"  Multiplier (K):     {args.multiplier}")
    print(f"  Anomalies found:    {n_anomalies}")
    print("=" * 60)
    print()
    print(ts_df.to_string())
    print()


if __name__ == "__main__":
    main()
