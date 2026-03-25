#!/usr/bin/env python3
"""Time series preparation for network traffic analysis.

Time Series Concepts for Security Analytics
──────────────────────────────────────────────────────────────────────────────

NONSTATIONARITY

A time series is stationary if its statistical properties (mean, variance,
autocorrelation) don't change over time. Most real-world network traffic
is NON-STATIONARY:

- Business hours have higher traffic than nights/weekends (daily seasonality)
- Month-end processing increases financial traffic (monthly pattern)
- New application deployments change baseline behavior (structural breaks)
- Attack campaigns create sudden shifts in malicious traffic

Why this matters:
- Models trained on stationary data may fail when patterns shift
- Baseline statistics computed over non-stationary data are misleading
- Anomaly thresholds must adapt to time-varying behavior


SEASONALITY

Seasonality refers to predictable, repeating patterns at fixed intervals:

- HOURLY: DNS queries spike at the start of each hour (cron jobs)
- DAILY: Web traffic peaks during business hours, drops at night
- WEEKLY: Monday morning has highest email traffic
- MONTHLY: Financial transactions spike at month-end

In security contexts:
- Attackers may time activities to blend with seasonal spikes
- Baseline models must account for expected variation
- Alerts during high-traffic periods may be normal; same activity at 3 AM is suspicious


WHY RANDOM TRAIN/TEST SPLIT IS INVALID FOR TIME SERIES

Standard ML practice: randomly split data into train (80%) and test (20%).

For time series, this is WRONG because:

1. TEMPORAL LEAKAGE
   Random splitting means training data may contain samples from AFTER test
   samples. The model learns future patterns and applies them to "past" data,
   creating artificially high accuracy that won't replicate in production.

2. AUTOCORRELATION IGNORED
   Adjacent time points are correlated (if traffic is high at 10:00, it's
   likely high at 10:01). Random splitting treats them as independent,
   underestimating variance and overfitting.

3. DISTRIBUTION SHIFT
   The test set should represent FUTURE data the model will see. Random
   sampling mixes past and future, failing to evaluate forward prediction.

CORRECT APPROACH: Temporal Split
   - Train on first 70-80% of timeline
   - Validate on next 10-15%
   - Test on final 10-15%

This simulates real deployment: train on historical data, deploy to detect
anomalies in future traffic.


Rolling Statistics
──────────────────

Rolling (moving) statistics compute metrics over a sliding window:

- ROLLING MEAN: Smooths noise, reveals trends
- ROLLING VARIANCE: Detects volatility changes (attack may increase variance)
- ROLLING Z-SCORE: Compares current value to recent history

Window size selection:
- Too short (e.g., 5 min): noisy, reacts to every fluctuation
- Too long (e.g., 24 hours): slow to detect changes, misses attacks
- Typical: 15 min to 1 hour for real-time detection

Usage:
    from scripts.timeseries_prep import TimeSeriesPreprocessor

    preprocessor = TimeSeriesPreprocessor(bucket_size="1min", window_size=15)
    ts_data = preprocessor.transform(conn_df, dns_df)
"""

from dataclasses import dataclass
from typing import Optional, Tuple

import numpy as np
import pandas as pd


@dataclass
class TimeSeriesStats:
    """Summary statistics for a time series."""
    name: str
    length: int
    start_time: pd.Timestamp
    end_time: pd.Timestamp
    mean: float
    std: float
    variance: float
    adf_statistic: Optional[float]  # Augmented Dickey-Fuller test
    is_stationary: Optional[bool]


class TimeSeriesPreprocessor:
    """Transform network telemetry into time-bucketed metrics.

    Aggregates raw connection and DNS logs into fixed time windows,
    computing security-relevant metrics per bucket.

    Attributes:
        bucket_size: Size of time buckets (pandas offset string).
        window_size: Number of buckets for rolling statistics.
        metrics: List of metric names computed.

    Example:
        >>> prep = TimeSeriesPreprocessor(bucket_size="1min", window_size=15)
        >>> ts_data = prep.transform(conn_df, dns_df)
        >>> print(ts_data.columns)
        Index(['conn_count', 'failed_count', 'failed_rate', 'dns_count',
               'nxdomain_count', 'nxdomain_rate', 'bytes_sent', 'bytes_recv',
               'failed_rate_rolling_mean', 'failed_rate_rolling_std', ...])
    """

    def __init__(
        self,
        bucket_size: str = "1min",
        window_size: int = 15,
    ):
        """Initialize preprocessor.

        Args:
            bucket_size: Pandas offset string for time bucket size.
                         Common values: "1min", "5min", "15min", "1h"
            window_size: Number of buckets for rolling window calculations.
                         For 1-minute buckets, window_size=15 gives 15-minute
                         rolling statistics.
        """
        self.bucket_size = bucket_size
        self.window_size = window_size
        self.metrics = [
            "conn_count", "failed_count", "failed_rate",
            "dns_count", "nxdomain_count", "nxdomain_rate",
            "bytes_sent", "bytes_recv", "bytes_ratio",
        ]

    def transform(
        self,
        conn: pd.DataFrame,
        dns: pd.DataFrame,
    ) -> pd.DataFrame:
        """Transform raw data into time-bucketed metrics.

        Args:
            conn: Connection DataFrame with normalized schema.
            dns: DNS DataFrame with normalized schema.

        Returns:
            DataFrame indexed by time bucket, containing:
            - Raw metrics (counts, rates)
            - Rolling mean for each metric
            - Rolling standard deviation for each metric
            - Rolling z-score for each metric
        """
        # Aggregate into time buckets
        conn_ts = self._aggregate_connections(conn)
        dns_ts = self._aggregate_dns(dns)

        # Merge on time index
        if len(conn_ts) > 0 and len(dns_ts) > 0:
            ts_data = conn_ts.join(dns_ts, how="outer")
        elif len(conn_ts) > 0:
            ts_data = conn_ts
        else:
            ts_data = dns_ts

        # Fill missing values
        ts_data = ts_data.fillna(0)

        # Add rolling statistics
        ts_data = self._add_rolling_stats(ts_data)

        return ts_data

    def _aggregate_connections(self, conn: pd.DataFrame) -> pd.DataFrame:
        """Aggregate connection data into time buckets."""
        if len(conn) == 0:
            return pd.DataFrame()

        # Get timestamp column
        ts_col = "timestamp" if "timestamp" in conn.columns else "ts"

        if ts_col not in conn.columns:
            return pd.DataFrame()

        df = conn.copy()
        df[ts_col] = pd.to_datetime(df[ts_col])
        df = df.set_index(ts_col)

        # Define failed states
        failed_states = ["S0", "REJ", "RSTO", "RSTR", "S1", "S2", "S3"]
        state_col = "conn_state" if "conn_state" in df.columns else "conn_state"
        df["is_failed"] = df[state_col].isin(failed_states)

        # Get bytes columns
        bytes_sent_col = "bytes_sent" if "bytes_sent" in df.columns else "orig_bytes"
        bytes_recv_col = "bytes_recv" if "bytes_recv" in df.columns else "resp_bytes"

        # Resample
        resampled = df.resample(self.bucket_size).agg({
            "is_failed": ["sum", "count"],
            bytes_sent_col: "sum",
            bytes_recv_col: "sum",
        })

        # Flatten column names
        resampled.columns = ["failed_count", "conn_count", "bytes_sent", "bytes_recv"]

        # Compute rates
        resampled["failed_rate"] = np.where(
            resampled["conn_count"] > 0,
            resampled["failed_count"] / resampled["conn_count"] * 100,
            0
        )

        resampled["bytes_ratio"] = np.where(
            resampled["bytes_recv"] > 0,
            resampled["bytes_sent"] / resampled["bytes_recv"],
            0
        )

        return resampled

    def _aggregate_dns(self, dns: pd.DataFrame) -> pd.DataFrame:
        """Aggregate DNS data into time buckets."""
        if len(dns) == 0:
            return pd.DataFrame()

        ts_col = "timestamp" if "timestamp" in dns.columns else "ts"

        if ts_col not in dns.columns:
            return pd.DataFrame()

        df = dns.copy()
        df[ts_col] = pd.to_datetime(df[ts_col])
        df = df.set_index(ts_col)

        # NXDOMAIN indicator
        rcode_col = "dns_rcode" if "dns_rcode" in df.columns else "rcode_name"
        df["is_nxdomain"] = df[rcode_col] == "NXDOMAIN"

        # Resample
        resampled = df.resample(self.bucket_size).agg({
            "is_nxdomain": ["sum", "count"],
        })

        resampled.columns = ["nxdomain_count", "dns_count"]

        # Compute rates
        resampled["nxdomain_rate"] = np.where(
            resampled["dns_count"] > 0,
            resampled["nxdomain_count"] / resampled["dns_count"] * 100,
            0
        )

        return resampled

    def _add_rolling_stats(self, ts_data: pd.DataFrame) -> pd.DataFrame:
        """Add rolling mean, std, and z-score for each metric."""
        result = ts_data.copy()

        # Metrics to compute rolling stats for
        rate_metrics = ["failed_rate", "nxdomain_rate", "bytes_ratio"]

        for metric in rate_metrics:
            if metric not in result.columns:
                continue

            # Rolling mean
            result[f"{metric}_rolling_mean"] = (
                result[metric].rolling(window=self.window_size, min_periods=1).mean()
            )

            # Rolling standard deviation
            result[f"{metric}_rolling_std"] = (
                result[metric].rolling(window=self.window_size, min_periods=1).std()
            )

            # Rolling variance
            result[f"{metric}_rolling_var"] = (
                result[metric].rolling(window=self.window_size, min_periods=1).var()
            )

            # Rolling z-score (how far current value is from rolling mean)
            rolling_mean = result[f"{metric}_rolling_mean"]
            rolling_std = result[f"{metric}_rolling_std"]

            result[f"{metric}_rolling_zscore"] = np.where(
                rolling_std > 0,
                (result[metric] - rolling_mean) / rolling_std,
                0
            )

        return result

    def analyze_stationarity(
        self,
        ts_data: pd.DataFrame,
        metric: str,
    ) -> TimeSeriesStats:
        """Analyze stationarity of a time series using ADF test.

        The Augmented Dickey-Fuller (ADF) test checks for unit roots.
        Null hypothesis: series has a unit root (is non-stationary).

        If p-value < 0.05, we reject H0 and conclude the series is stationary.

        Args:
            ts_data: Time series DataFrame from transform().
            metric: Column name to analyze.

        Returns:
            TimeSeriesStats with stationarity analysis.
        """
        from scipy import stats as scipy_stats

        if metric not in ts_data.columns:
            raise ValueError(f"Metric '{metric}' not in data")

        series = ts_data[metric].dropna()

        if len(series) < 10:
            return TimeSeriesStats(
                name=metric,
                length=len(series),
                start_time=ts_data.index.min(),
                end_time=ts_data.index.max(),
                mean=float(series.mean()),
                std=float(series.std()),
                variance=float(series.var()),
                adf_statistic=None,
                is_stationary=None,
            )

        # Simple stationarity check using rolling statistics
        # Full ADF test requires statsmodels; we use a simplified approach
        n = len(series)
        split = n // 2

        mean_first = series.iloc[:split].mean()
        mean_second = series.iloc[split:].mean()
        var_first = series.iloc[:split].var()
        var_second = series.iloc[split:].var()

        # Check if mean and variance are approximately constant
        mean_ratio = abs(mean_first - mean_second) / (mean_first + 1e-10)
        var_ratio = max(var_first, var_second) / (min(var_first, var_second) + 1e-10)

        is_stationary = mean_ratio < 0.5 and var_ratio < 2.0

        return TimeSeriesStats(
            name=metric,
            length=len(series),
            start_time=ts_data.index.min(),
            end_time=ts_data.index.max(),
            mean=float(series.mean()),
            std=float(series.std()),
            variance=float(series.var()),
            adf_statistic=None,  # Would require statsmodels
            is_stationary=is_stationary,
        )


def temporal_train_test_split(
    ts_data: pd.DataFrame,
    train_ratio: float = 0.7,
    val_ratio: float = 0.15,
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Split time series data temporally (NOT randomly).

    Maintains temporal ordering: train < validation < test.
    This is critical for proper evaluation of time series models.

    Args:
        ts_data: Time series DataFrame (indexed by time).
        train_ratio: Fraction of data for training.
        val_ratio: Fraction of data for validation.
                   Test gets remaining (1 - train_ratio - val_ratio).

    Returns:
        Tuple of (train_df, val_df, test_df)

    Example:
        >>> train, val, test = temporal_train_test_split(ts_data, 0.7, 0.15)
        >>> # train: first 70%
        >>> # val: next 15%
        >>> # test: final 15%
    """
    n = len(ts_data)
    train_end = int(n * train_ratio)
    val_end = int(n * (train_ratio + val_ratio))

    train_df = ts_data.iloc[:train_end].copy()
    val_df = ts_data.iloc[train_end:val_end].copy()
    test_df = ts_data.iloc[val_end:].copy()

    return train_df, val_df, test_df


def detect_seasonality(
    ts_data: pd.DataFrame,
    metric: str,
    periods: list[int] = None,
) -> dict:
    """Detect seasonal patterns in a time series.

    Uses autocorrelation to identify repeating patterns at various lags.

    Args:
        ts_data: Time series DataFrame.
        metric: Column to analyze.
        periods: Lags to check (default: common periods).

    Returns:
        Dictionary with autocorrelation at each period.
    """
    if metric not in ts_data.columns:
        raise ValueError(f"Metric '{metric}' not in data")

    series = ts_data[metric].dropna()

    if periods is None:
        # Default: check hourly (60 min), daily (1440 min) for 1-min buckets
        periods = [5, 15, 30, 60, 120, 360, 720, 1440]

    # Filter periods that are too long for the series
    periods = [p for p in periods if p < len(series) // 2]

    results = {}
    for period in periods:
        # Compute autocorrelation at this lag
        autocorr = series.autocorr(lag=period)
        results[period] = float(autocorr) if not np.isnan(autocorr) else 0.0

    return {
        "metric": metric,
        "series_length": len(series),
        "autocorrelations": results,
        "strongest_period": max(results.items(), key=lambda x: abs(x[1]))[0] if results else None,
    }


def generate_timeseries_report(ts_data: pd.DataFrame) -> str:
    """Generate a human-readable report on time series characteristics."""
    lines = [
        "TIME SERIES ANALYSIS REPORT",
        "=" * 60,
        "",
        f"Time range: {ts_data.index.min()} to {ts_data.index.max()}",
        f"Number of time buckets: {len(ts_data)}",
        f"Bucket frequency: {pd.infer_freq(ts_data.index) or 'irregular'}",
        "",
        "METRIC SUMMARY",
        "-" * 60,
    ]

    for col in ["failed_rate", "nxdomain_rate", "bytes_ratio"]:
        if col in ts_data.columns:
            series = ts_data[col]
            lines.extend([
                f"\n{col}:",
                f"  Mean: {series.mean():.4f}",
                f"  Std:  {series.std():.4f}",
                f"  Min:  {series.min():.4f}",
                f"  Max:  {series.max():.4f}",
            ])

    # Check for rolling stats
    rolling_cols = [c for c in ts_data.columns if "rolling_zscore" in c]
    if rolling_cols:
        lines.extend([
            "",
            "ROLLING Z-SCORE ANOMALIES (|z| > 2)",
            "-" * 60,
        ])

        for col in rolling_cols:
            anomalies = ts_data[abs(ts_data[col]) > 2]
            if len(anomalies) > 0:
                metric = col.replace("_rolling_zscore", "")
                lines.append(f"\n{metric}: {len(anomalies)} anomalous buckets")
                for idx in anomalies.index[:5]:
                    z = anomalies.loc[idx, col]
                    lines.append(f"  {idx}: z={z:.2f}")

    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)


if __name__ == "__main__":
    # Demo usage
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    from scripts.zeek_to_dataframe import load_zeek_log, CONN_SCHEMA, DNS_SCHEMA
    from scripts.normalize import normalize_conn, normalize_dns

    # Load sample data
    zeek_dir = Path("data/zeek_logs/sample")
    conn = normalize_conn(load_zeek_log(zeek_dir / "conn.log", schema=CONN_SCHEMA))
    dns = normalize_dns(load_zeek_log(zeek_dir / "dns.log", schema=DNS_SCHEMA))

    # Transform to time series
    prep = TimeSeriesPreprocessor(bucket_size="5s", window_size=3)
    ts_data = prep.transform(conn, dns)

    print("Time Series Data:")
    print(ts_data)
    print()

    # Generate report
    print(generate_timeseries_report(ts_data))

    # Temporal split
    train, val, test = temporal_train_test_split(ts_data)
    print(f"\nTemporal split:")
    print(f"  Train: {len(train)} buckets ({train.index.min()} to {train.index.max()})")
    print(f"  Val:   {len(val)} buckets")
    print(f"  Test:  {len(test)} buckets ({test.index.min()} to {test.index.max()})")
