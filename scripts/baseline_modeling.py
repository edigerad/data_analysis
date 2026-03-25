#!/usr/bin/env python3
"""Statistical baseline modeling for network traffic anomaly detection.

Why Baseline Modeling is Necessary Before Machine Learning
──────────────────────────────────────────────────────────────────────────────

1. UNDERSTANDING NORMAL BEHAVIOR
   Before training ML models, you must understand what "normal" looks like.
   Baseline statistics (mean, std, percentiles) characterize typical patterns.
   Without this, ML models may learn to detect noise rather than true anomalies.

2. INTERPRETABILITY
   Z-scores provide intuitive anomaly scores: "this value is 4 standard
   deviations from the mean" is immediately actionable. Black-box ML scores
   like "0.87 probability" require calibration to be meaningful.

3. COMPUTATIONAL EFFICIENCY
   Statistical baselines compute in O(n) with minimal memory. They can run
   on resource-constrained systems (SIEM agents, edge sensors) where ML
   models are impractical.

4. FEATURE ENGINEERING GUIDANCE
   Baseline analysis reveals which metrics have useful variance. If failed
   connection rate has std=0.1%, it won't help classification. This informs
   feature selection for downstream ML.

5. THRESHOLD CALIBRATION
   ML models output probabilities; baselines help convert these to actionable
   thresholds. "Alert when z > 3" is grounded in statistical theory (99.7%
   confidence under normality).

6. DRIFT DETECTION
   Comparing live baselines to training baselines reveals concept drift—when
   the data distribution changes and ML models need retraining.

7. REGULATORY COMPLIANCE
   Many industries require explainable detection logic. "Flagged because
   z-score = 5.2 exceeds threshold of 3" satisfies auditors; "flagged because
   neural network said so" does not.

Metrics Computed
────────────────
- Failed connection rate: Percentage of connections in failed states (S0, REJ)
- NXDOMAIN rate: Percentage of DNS queries returning NXDOMAIN
- Bytes sent/received ratio: Indicator of data exfiltration

Usage:
    from scripts.baseline_modeling import BaselineModel

    model = BaselineModel()
    model.fit(conn_df, dns_df)
    anomalies = model.detect_anomalies(new_conn_df, new_dns_df)
"""

from dataclasses import dataclass, field
from typing import Optional

import numpy as np
import pandas as pd


@dataclass
class BaselineStats:
    """Statistics for a single metric."""
    name: str
    mean: float
    std: float
    min: float
    max: float
    median: float
    percentile_95: float
    percentile_99: float
    n_samples: int

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "mean": self.mean,
            "std": self.std,
            "min": self.min,
            "max": self.max,
            "median": self.median,
            "percentile_95": self.percentile_95,
            "percentile_99": self.percentile_99,
            "n_samples": self.n_samples,
        }


@dataclass
class AnomalyResult:
    """Result of anomaly detection for a single observation."""
    metric: str
    value: float
    z_score: float
    is_anomaly: bool
    threshold: float

    def to_dict(self) -> dict:
        return {
            "metric": self.metric,
            "value": self.value,
            "z_score": self.z_score,
            "is_anomaly": self.is_anomaly,
            "threshold": self.threshold,
        }


class BaselineModel:
    """Statistical baseline model for network traffic anomaly detection.

    This model computes baseline statistics for key security metrics and
    uses z-score analysis to flag anomalies.

    Attributes:
        z_threshold: Number of standard deviations for anomaly detection.
                     Default is 3.0 (covers 99.7% of normal data under
                     Gaussian assumption).
        baselines: Dictionary mapping metric names to BaselineStats.

    Example:
        >>> model = BaselineModel(z_threshold=2.5)
        >>> model.fit(conn_df, dns_df)
        >>> print(model.baselines['failed_conn_rate'].mean)
        0.15
        >>> anomalies = model.detect_anomalies(new_conn, new_dns)
    """

    def __init__(self, z_threshold: float = 3.0):
        """Initialize baseline model.

        Args:
            z_threshold: Z-score threshold for anomaly flagging.
                         Higher values = fewer alerts but may miss anomalies.
                         Lower values = more alerts but higher false positive rate.
        """
        self.z_threshold = z_threshold
        self.baselines: dict[str, BaselineStats] = {}
        self._is_fitted = False

    def fit(
        self,
        conn: pd.DataFrame,
        dns: pd.DataFrame,
        time_window: str = "1min",
    ) -> "BaselineModel":
        """Fit baseline model on historical data.

        Computes baseline statistics for each metric by aggregating data
        into time windows and computing per-window metrics.

        Args:
            conn: Connection DataFrame with normalized schema.
            dns: DNS DataFrame with normalized schema.
            time_window: Pandas time offset string for aggregation (e.g., "1min", "5min").

        Returns:
            self (for method chaining)
        """
        # Compute time-windowed metrics
        metrics_df = self._compute_time_metrics(conn, dns, time_window)

        if len(metrics_df) == 0:
            raise ValueError("No data to compute baselines. Check input DataFrames.")

        # Compute baseline statistics for each metric
        for col in ["failed_conn_rate", "nxdomain_rate", "bytes_ratio"]:
            if col in metrics_df.columns:
                values = metrics_df[col].dropna()
                if len(values) > 0:
                    self.baselines[col] = self._compute_stats(col, values)

        self._is_fitted = True
        return self

    def _compute_time_metrics(
        self,
        conn: pd.DataFrame,
        dns: pd.DataFrame,
        time_window: str,
    ) -> pd.DataFrame:
        """Aggregate raw data into time-windowed metrics."""
        # Ensure timestamp column exists
        ts_col = "timestamp" if "timestamp" in conn.columns else "ts"

        results = []

        # Process connection data
        if len(conn) > 0 and ts_col in conn.columns:
            conn_copy = conn.copy()
            conn_copy[ts_col] = pd.to_datetime(conn_copy[ts_col])
            conn_copy = conn_copy.set_index(ts_col)

            # Failed connection rate per window
            failed_states = ["S0", "REJ", "RSTO", "RSTR", "S1", "S2", "S3"]
            conn_copy["is_failed"] = conn_copy["conn_state"].isin(failed_states)

            # Bytes ratio per connection (handle division by zero)
            bytes_sent_col = "bytes_sent" if "bytes_sent" in conn_copy.columns else "orig_bytes"
            bytes_recv_col = "bytes_recv" if "bytes_recv" in conn_copy.columns else "resp_bytes"

            # Handle NA values before comparison
            bytes_recv = pd.to_numeric(conn_copy[bytes_recv_col], errors='coerce').fillna(0)
            bytes_sent = pd.to_numeric(conn_copy[bytes_sent_col], errors='coerce').fillna(0)
            conn_copy["bytes_ratio"] = np.where(
                bytes_recv > 0,
                bytes_sent / bytes_recv,
                np.nan
            )

            # Resample to time windows
            conn_resampled = conn_copy.resample(time_window).agg({
                "is_failed": ["sum", "count"],
                "bytes_ratio": "mean",
            })
            conn_resampled.columns = ["failed_count", "total_conn", "bytes_ratio"]
            conn_resampled["failed_conn_rate"] = np.where(
                conn_resampled["total_conn"] > 0,
                conn_resampled["failed_count"] / conn_resampled["total_conn"] * 100,
                np.nan
            )

            results.append(conn_resampled[["failed_conn_rate", "bytes_ratio"]])

        # Process DNS data
        if len(dns) > 0:
            dns_ts_col = "timestamp" if "timestamp" in dns.columns else "ts"
            if dns_ts_col in dns.columns:
                dns_copy = dns.copy()
                dns_copy[dns_ts_col] = pd.to_datetime(dns_copy[dns_ts_col])
                dns_copy = dns_copy.set_index(dns_ts_col)

                # NXDOMAIN rate per window
                rcode_col = "dns_rcode" if "dns_rcode" in dns_copy.columns else "rcode_name"
                dns_copy["is_nxdomain"] = dns_copy[rcode_col] == "NXDOMAIN"

                dns_resampled = dns_copy.resample(time_window).agg({
                    "is_nxdomain": ["sum", "count"],
                })
                dns_resampled.columns = ["nxdomain_count", "total_dns"]
                dns_resampled["nxdomain_rate"] = np.where(
                    dns_resampled["total_dns"] > 0,
                    dns_resampled["nxdomain_count"] / dns_resampled["total_dns"] * 100,
                    np.nan
                )

                results.append(dns_resampled[["nxdomain_rate"]])

        if not results:
            return pd.DataFrame()

        # Combine all metrics
        combined = pd.concat(results, axis=1)
        return combined.dropna(how="all")

    def _compute_stats(self, name: str, values: pd.Series) -> BaselineStats:
        """Compute statistical summary for a metric."""
        return BaselineStats(
            name=name,
            mean=float(values.mean()),
            std=float(values.std()) if len(values) > 1 else 0.0,
            min=float(values.min()),
            max=float(values.max()),
            median=float(values.median()),
            percentile_95=float(values.quantile(0.95)),
            percentile_99=float(values.quantile(0.99)),
            n_samples=len(values),
        )

    def compute_z_score(self, metric: str, value: float) -> float:
        """Compute z-score for a single value.

        Args:
            metric: Name of the metric (must be in fitted baselines).
            value: Observed value.

        Returns:
            Z-score (number of standard deviations from mean).

        Raises:
            ValueError: If model not fitted or metric not found.
        """
        if not self._is_fitted:
            raise ValueError("Model not fitted. Call fit() first.")

        if metric not in self.baselines:
            raise ValueError(f"Metric '{metric}' not in baselines. Available: {list(self.baselines.keys())}")

        baseline = self.baselines[metric]

        if baseline.std == 0:
            return 0.0 if value == baseline.mean else np.inf

        return (value - baseline.mean) / baseline.std

    def detect_anomalies(
        self,
        conn: pd.DataFrame,
        dns: pd.DataFrame,
        time_window: str = "1min",
    ) -> pd.DataFrame:
        """Detect anomalies in new data against fitted baselines.

        Args:
            conn: New connection data.
            dns: New DNS data.
            time_window: Time window for aggregation.

        Returns:
            DataFrame with columns: timestamp, metric, value, z_score, is_anomaly
        """
        if not self._is_fitted:
            raise ValueError("Model not fitted. Call fit() first.")

        # Compute metrics for new data
        metrics_df = self._compute_time_metrics(conn, dns, time_window)

        if len(metrics_df) == 0:
            return pd.DataFrame(columns=["timestamp", "metric", "value", "z_score", "is_anomaly"])

        # Compute z-scores and flag anomalies
        results = []
        for idx, row in metrics_df.iterrows():
            for metric in self.baselines.keys():
                if metric in row and pd.notna(row[metric]):
                    z_score = self.compute_z_score(metric, row[metric])
                    results.append({
                        "timestamp": idx,
                        "metric": metric,
                        "value": row[metric],
                        "z_score": z_score,
                        "is_anomaly": abs(z_score) > self.z_threshold,
                        "threshold": self.z_threshold,
                    })

        return pd.DataFrame(results)

    def get_baseline_report(self) -> str:
        """Generate human-readable baseline report."""
        if not self._is_fitted:
            return "Model not fitted."

        lines = [
            "STATISTICAL BASELINE REPORT",
            "=" * 50,
            "",
            f"Z-score threshold: {self.z_threshold}",
            f"(Flags values > {self.z_threshold} std from mean)",
            "",
        ]

        for name, stats in self.baselines.items():
            lines.extend([
                f"Metric: {name}",
                "-" * 40,
                f"  Mean:          {stats.mean:.4f}",
                f"  Std Dev:       {stats.std:.4f}",
                f"  Min:           {stats.min:.4f}",
                f"  Max:           {stats.max:.4f}",
                f"  Median:        {stats.median:.4f}",
                f"  95th %ile:     {stats.percentile_95:.4f}",
                f"  99th %ile:     {stats.percentile_99:.4f}",
                f"  N samples:     {stats.n_samples}",
                "",
            ])

        return "\n".join(lines)

    def to_dict(self) -> dict:
        """Export baselines as dictionary (for JSON serialization)."""
        return {
            "z_threshold": self.z_threshold,
            "is_fitted": self._is_fitted,
            "baselines": {k: v.to_dict() for k, v in self.baselines.items()},
        }

    @classmethod
    def from_dict(cls, data: dict) -> "BaselineModel":
        """Reconstruct model from dictionary."""
        model = cls(z_threshold=data["z_threshold"])
        model._is_fitted = data["is_fitted"]

        for name, stats_dict in data["baselines"].items():
            model.baselines[name] = BaselineStats(**stats_dict)

        return model


def compute_per_host_baselines(
    conn: pd.DataFrame,
    dns: pd.DataFrame,
    host_column: str = "src_ip",
) -> pd.DataFrame:
    """Compute baseline metrics per host.

    Useful for identifying hosts that deviate from their own baselines
    (behavioral anomaly detection).

    Args:
        conn: Connection DataFrame.
        dns: DNS DataFrame.
        host_column: Column containing host identifiers.

    Returns:
        DataFrame with per-host baseline statistics.
    """
    results = []

    # Per-host connection stats
    if len(conn) > 0 and host_column in conn.columns:
        failed_states = ["S0", "REJ", "RSTO", "RSTR"]
        state_col = "conn_state" if "conn_state" in conn.columns else "conn_state"

        for host, group in conn.groupby(host_column):
            total = len(group)
            failed = group[state_col].isin(failed_states).sum()

            bytes_sent_col = "bytes_sent" if "bytes_sent" in group.columns else "orig_bytes"
            bytes_recv_col = "bytes_recv" if "bytes_recv" in group.columns else "resp_bytes"

            sent = group[bytes_sent_col].sum()
            recv = group[bytes_recv_col].sum()

            results.append({
                "host": host,
                "total_connections": total,
                "failed_connections": failed,
                "failed_rate": failed / total * 100 if total > 0 else 0,
                "bytes_sent": sent,
                "bytes_recv": recv,
                "bytes_ratio": sent / recv if recv > 0 else np.nan,
            })

    # Per-host DNS stats
    if len(dns) > 0 and host_column in dns.columns:
        rcode_col = "dns_rcode" if "dns_rcode" in dns.columns else "rcode_name"

        host_dns = {}
        for host, group in dns.groupby(host_column):
            total = len(group)
            nxdomain = (group[rcode_col] == "NXDOMAIN").sum()
            host_dns[host] = {
                "total_dns": total,
                "nxdomain_count": nxdomain,
                "nxdomain_rate": nxdomain / total * 100 if total > 0 else 0,
            }

        # Merge DNS stats into results
        for r in results:
            if r["host"] in host_dns:
                r.update(host_dns[r["host"]])

    return pd.DataFrame(results) if results else pd.DataFrame()


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

    # Fit baseline model
    model = BaselineModel(z_threshold=2.0)
    model.fit(conn, dns, time_window="10s")

    # Print report
    print(model.get_baseline_report())

    # Detect anomalies
    anomalies = model.detect_anomalies(conn, dns, time_window="10s")
    print("\nDetected Anomalies:")
    print(anomalies[anomalies["is_anomaly"]])
