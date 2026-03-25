#!/usr/bin/env python3
"""CUSUM (Cumulative Sum) change-point detection for network traffic.

CUSUM Algorithm Overview
──────────────────────────────────────────────────────────────────────────────

CUSUM is a sequential analysis technique for detecting changes in the mean
of a process. Originally developed for quality control in manufacturing,
it's highly effective for detecting shifts in network traffic patterns.

Mathematical Formulation
────────────────────────

Given observations x₁, x₂, ..., xₙ with expected mean μ:

Upper CUSUM (detects increase):
    S⁺ₙ = max(0, S⁺ₙ₋₁ + (xₙ - μ) - k)

Lower CUSUM (detects decrease):
    S⁻ₙ = max(0, S⁻ₙ₋₁ - (xₙ - μ) - k)

where:
    k = allowance parameter (slack, typically 0.5 * σ)
    h = decision threshold (typically 4-5 * σ)

A change is detected when S⁺ₙ > h or S⁻ₙ > h.


Why CUSUM for Security?
───────────────────────

1. EARLY DETECTION
   CUSUM accumulates evidence across multiple observations. A persistent
   but subtle shift (e.g., failed rate increasing from 5% to 8%) triggers
   an alert faster than threshold-based methods that require large deviations.

2. LOW FALSE POSITIVE RATE
   Random noise tends to cancel out in the cumulative sum. Only persistent
   shifts accumulate enough to exceed the threshold.

3. INTERPRETABLE CHANGE POINTS
   CUSUM identifies WHEN the change occurred, not just that it happened.
   This helps incident responders pinpoint the start of an attack.

4. MINIMAL PARAMETERS
   Only two parameters (k and h) need tuning, unlike complex ML models.

5. ONLINE COMPUTATION
   O(1) update per observation—suitable for real-time stream processing.


Security Applications
─────────────────────

- Connection failure rate: Detect scanning, DDoS, firewall changes
- NXDOMAIN rate: Detect DGA malware, DNS tunneling
- Bytes sent/received: Detect exfiltration, C2 beaconing
- Inter-arrival time: Detect automated tools vs human activity

Usage:
    from scripts.cusum_detector import CUSUMDetector

    detector = CUSUMDetector(target_mean=0.05, std=0.02)
    for value in new_observations:
        result = detector.update(value)
        if result.change_detected:
            print(f"Change at {result.index}!")
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd


@dataclass
class CUSUMResult:
    """Result of CUSUM update for a single observation."""
    index: int
    value: float
    upper_cusum: float
    lower_cusum: float
    change_detected: bool
    direction: Optional[str]  # "increase" or "decrease" or None


@dataclass
class ChangePoint:
    """Detected change point."""
    index: int
    timestamp: Optional[pd.Timestamp]
    direction: str  # "increase" or "decrease"
    cusum_value: float
    pre_change_mean: float
    post_change_mean: float


class CUSUMDetector:
    """CUSUM change-point detector for sequential analysis.

    Implements the tabular CUSUM algorithm for detecting shifts in the
    mean of a time series.

    Attributes:
        target_mean: Expected mean under normal conditions.
        std: Standard deviation of the process.
        k: Allowance parameter (slack). Default is 0.5 * std.
        h: Decision threshold. Default is 5 * std.
        upper_cusum: Current upper cumulative sum.
        lower_cusum: Current lower cumulative sum.
        history: List of all CUSUMResult objects.

    Example:
        >>> detector = CUSUMDetector(target_mean=0.05, std=0.02)
        >>> detector.fit_from_data(baseline_data)  # Learn parameters
        >>> for value in new_data:
        ...     result = detector.update(value)
        ...     if result.change_detected:
        ...         print(f"Alert! Change detected at index {result.index}")
    """

    def __init__(
        self,
        target_mean: float = 0.0,
        std: float = 1.0,
        k: Optional[float] = None,
        h: Optional[float] = None,
    ):
        """Initialize CUSUM detector.

        Args:
            target_mean: Expected mean under H0 (normal conditions).
            std: Standard deviation of the process.
            k: Allowance parameter. If None, defaults to 0.5 * std.
               Smaller k = more sensitive but higher false positive rate.
            h: Decision threshold. If None, defaults to 5 * std.
               Smaller h = faster detection but higher false positive rate.
        """
        self.target_mean = target_mean
        self.std = std
        self.k = k if k is not None else 0.5 * std
        self.h = h if h is not None else 5 * std

        # State
        self.upper_cusum = 0.0
        self.lower_cusum = 0.0
        self.n_observations = 0
        self.history: List[CUSUMResult] = []
        self.change_points: List[ChangePoint] = []

    def reset(self) -> None:
        """Reset detector state to initial conditions."""
        self.upper_cusum = 0.0
        self.lower_cusum = 0.0
        self.n_observations = 0
        self.history = []
        self.change_points = []

    def fit_from_data(
        self,
        data: np.ndarray | pd.Series,
        k_factor: float = 0.5,
        h_factor: float = 5.0,
    ) -> "CUSUMDetector":
        """Estimate parameters from baseline data.

        Args:
            data: Baseline data to estimate mean and std from.
            k_factor: k = k_factor * std
            h_factor: h = h_factor * std

        Returns:
            self (for method chaining)
        """
        if isinstance(data, pd.Series):
            data = data.dropna().values

        self.target_mean = float(np.mean(data))
        self.std = float(np.std(data))

        # Avoid division by zero
        if self.std == 0:
            self.std = 1e-10

        self.k = k_factor * self.std
        self.h = h_factor * self.std

        return self

    def update(self, value: float) -> CUSUMResult:
        """Process a new observation.

        Args:
            value: New observation to process.

        Returns:
            CUSUMResult with updated state and detection status.
        """
        # Standardized deviation from target
        deviation = value - self.target_mean

        # Update cumulative sums
        self.upper_cusum = max(0, self.upper_cusum + deviation - self.k)
        self.lower_cusum = max(0, self.lower_cusum - deviation - self.k)

        # Check for change
        change_detected = False
        direction = None

        if self.upper_cusum > self.h:
            change_detected = True
            direction = "increase"
        elif self.lower_cusum > self.h:
            change_detected = True
            direction = "decrease"

        result = CUSUMResult(
            index=self.n_observations,
            value=value,
            upper_cusum=self.upper_cusum,
            lower_cusum=self.lower_cusum,
            change_detected=change_detected,
            direction=direction,
        )

        self.history.append(result)
        self.n_observations += 1

        # Reset CUSUM after detection (Page's rule)
        if change_detected:
            self._record_change_point(result)
            self.upper_cusum = 0.0
            self.lower_cusum = 0.0

        return result

    def _record_change_point(self, result: CUSUMResult) -> None:
        """Record a detected change point with context."""
        # Estimate pre/post means from history
        n = len(self.history)
        window = min(10, n // 2)

        if n > window * 2:
            pre_values = [h.value for h in self.history[-window*2:-window]]
            post_values = [h.value for h in self.history[-window:]]
            pre_mean = np.mean(pre_values) if pre_values else self.target_mean
            post_mean = np.mean(post_values) if post_values else result.value
        else:
            pre_mean = self.target_mean
            post_mean = result.value

        self.change_points.append(ChangePoint(
            index=result.index,
            timestamp=None,  # Set externally if using timestamps
            direction=result.direction,
            cusum_value=max(result.upper_cusum, result.lower_cusum),
            pre_change_mean=pre_mean,
            post_change_mean=post_mean,
        ))

    def detect_all(
        self,
        data: np.ndarray | pd.Series,
        timestamps: Optional[pd.DatetimeIndex] = None,
    ) -> pd.DataFrame:
        """Run detection on entire dataset.

        Args:
            data: Array or Series of observations.
            timestamps: Optional timestamps for each observation.

        Returns:
            DataFrame with columns: timestamp (optional), value, upper_cusum,
            lower_cusum, change_detected, direction
        """
        self.reset()

        if isinstance(data, pd.Series):
            values = data.values
            if timestamps is None and isinstance(data.index, pd.DatetimeIndex):
                timestamps = data.index
        else:
            values = np.asarray(data)

        results = []
        for i, value in enumerate(values):
            result = self.update(float(value))
            row = {
                "value": result.value,
                "upper_cusum": result.upper_cusum,
                "lower_cusum": result.lower_cusum,
                "change_detected": result.change_detected,
                "direction": result.direction,
            }
            if timestamps is not None and i < len(timestamps):
                row["timestamp"] = timestamps[i]
            results.append(row)

        df = pd.DataFrame(results)

        # Update change point timestamps
        if timestamps is not None:
            for cp in self.change_points:
                if cp.index < len(timestamps):
                    cp.timestamp = timestamps[cp.index]

        return df

    def get_change_points_df(self) -> pd.DataFrame:
        """Return detected change points as DataFrame."""
        if not self.change_points:
            return pd.DataFrame(columns=[
                "index", "timestamp", "direction",
                "cusum_value", "pre_change_mean", "post_change_mean"
            ])

        return pd.DataFrame([
            {
                "index": cp.index,
                "timestamp": cp.timestamp,
                "direction": cp.direction,
                "cusum_value": cp.cusum_value,
                "pre_change_mean": cp.pre_change_mean,
                "post_change_mean": cp.post_change_mean,
            }
            for cp in self.change_points
        ])

    def get_parameters(self) -> dict:
        """Return current parameters."""
        return {
            "target_mean": self.target_mean,
            "std": self.std,
            "k": self.k,
            "h": self.h,
        }


def plot_cusum(
    detection_results: pd.DataFrame,
    metric_name: str = "metric",
    figsize: Tuple[int, int] = (14, 8),
) -> "matplotlib.figure.Figure":
    """Plot CUSUM detection results.

    Creates a two-panel figure:
    - Top: Original time series with change points marked
    - Bottom: CUSUM values with threshold lines

    Args:
        detection_results: DataFrame from CUSUMDetector.detect_all()
        metric_name: Name for y-axis labels
        figsize: Figure dimensions

    Returns:
        matplotlib Figure object
    """
    import matplotlib.pyplot as plt

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=figsize, sharex=True)

    # Determine x-axis
    if "timestamp" in detection_results.columns:
        x = detection_results["timestamp"]
        xlabel = "Time"
    else:
        x = range(len(detection_results))
        xlabel = "Observation Index"

    # Top panel: Original values
    ax1.plot(x, detection_results["value"], "b-", alpha=0.7, label="Observed")

    # Mark change points
    changes = detection_results[detection_results["change_detected"]]
    if len(changes) > 0:
        change_x = changes["timestamp"] if "timestamp" in changes.columns else changes.index
        ax1.scatter(change_x, changes["value"], c="red", s=100, zorder=5,
                   marker="^", label="Change Detected")

    ax1.set_ylabel(metric_name)
    ax1.set_title(f"CUSUM Change Detection: {metric_name}")
    ax1.legend(loc="upper right")
    ax1.grid(True, alpha=0.3)

    # Bottom panel: CUSUM values
    ax2.plot(x, detection_results["upper_cusum"], "g-", label="Upper CUSUM (increase)")
    ax2.plot(x, detection_results["lower_cusum"], "r-", label="Lower CUSUM (decrease)")
    ax2.axhline(y=0, color="k", linestyle="-", alpha=0.3)

    # Note: threshold line would require h parameter, which isn't stored in results
    ax2.set_xlabel(xlabel)
    ax2.set_ylabel("Cumulative Sum")
    ax2.legend(loc="upper right")
    ax2.grid(True, alpha=0.3)

    plt.tight_layout()
    return fig


def detect_connection_failure_changes(
    ts_data: pd.DataFrame,
    metric: str = "failed_rate",
    k_factor: float = 0.5,
    h_factor: float = 4.0,
    baseline_fraction: float = 0.3,
) -> Tuple[pd.DataFrame, CUSUMDetector]:
    """Detect change points in connection failure rate.

    Convenience function that:
    1. Uses first portion of data as baseline to estimate parameters
    2. Runs CUSUM detection on remaining data
    3. Returns results with timestamps

    Args:
        ts_data: Time series DataFrame with failed_rate column.
        metric: Column name for the metric to analyze.
        k_factor: Sensitivity parameter multiplier.
        h_factor: Threshold parameter multiplier.
        baseline_fraction: Fraction of data to use for baseline estimation.

    Returns:
        Tuple of (detection_results_df, fitted_detector)
    """
    if metric not in ts_data.columns:
        raise ValueError(f"Metric '{metric}' not found in data")

    series = ts_data[metric].dropna()
    n = len(series)
    baseline_n = int(n * baseline_fraction)

    if baseline_n < 5:
        raise ValueError("Not enough data for baseline estimation")

    # Split into baseline and detection periods
    baseline = series.iloc[:baseline_n]
    detection = series.iloc[baseline_n:]

    # Fit detector on baseline
    detector = CUSUMDetector()
    detector.fit_from_data(baseline, k_factor=k_factor, h_factor=h_factor)

    # Run detection
    if isinstance(detection.index, pd.DatetimeIndex):
        timestamps = detection.index
    else:
        timestamps = None

    results = detector.detect_all(detection, timestamps=timestamps)

    return results, detector


def generate_cusum_report(
    detector: CUSUMDetector,
    detection_results: pd.DataFrame,
    metric_name: str = "metric",
) -> str:
    """Generate human-readable CUSUM analysis report."""
    lines = [
        "CUSUM CHANGE DETECTION REPORT",
        "=" * 60,
        "",
        "DETECTOR PARAMETERS",
        "-" * 40,
        f"  Target mean (μ):      {detector.target_mean:.4f}",
        f"  Standard deviation:   {detector.std:.4f}",
        f"  Allowance (k):        {detector.k:.4f}",
        f"  Threshold (h):        {detector.h:.4f}",
        "",
        "DETECTION RESULTS",
        "-" * 40,
        f"  Total observations:   {len(detection_results)}",
        f"  Change points found:  {len(detector.change_points)}",
        "",
    ]

    if detector.change_points:
        lines.append("DETECTED CHANGE POINTS")
        lines.append("-" * 40)

        for i, cp in enumerate(detector.change_points, 1):
            ts_str = str(cp.timestamp) if cp.timestamp else f"Index {cp.index}"
            lines.extend([
                f"\n  Change {i}: {ts_str}",
                f"    Direction:     {cp.direction}",
                f"    CUSUM value:   {cp.cusum_value:.4f}",
                f"    Pre-change μ:  {cp.pre_change_mean:.4f}",
                f"    Post-change μ: {cp.post_change_mean:.4f}",
                f"    Shift size:    {abs(cp.post_change_mean - cp.pre_change_mean):.4f}",
            ])

    # Summary statistics
    if len(detection_results) > 0:
        max_upper = detection_results["upper_cusum"].max()
        max_lower = detection_results["lower_cusum"].max()

        lines.extend([
            "",
            "CUSUM STATISTICS",
            "-" * 40,
            f"  Max upper CUSUM:  {max_upper:.4f}",
            f"  Max lower CUSUM:  {max_lower:.4f}",
        ])

    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)


if __name__ == "__main__":
    # Demo with synthetic data showing a change point
    import matplotlib.pyplot as plt

    # Create synthetic data with a change point
    np.random.seed(42)
    n_baseline = 50
    n_after_change = 50

    baseline_data = np.random.normal(0.05, 0.02, n_baseline)  # 5% failure rate
    changed_data = np.random.normal(0.15, 0.03, n_after_change)  # 15% after change
    full_data = np.concatenate([baseline_data, changed_data])

    # Create timestamps
    timestamps = pd.date_range("2024-01-01", periods=len(full_data), freq="1min")
    ts_series = pd.Series(full_data, index=timestamps)

    # Fit and detect
    detector = CUSUMDetector()
    detector.fit_from_data(baseline_data[:30], k_factor=0.5, h_factor=4.0)

    results = detector.detect_all(ts_series, timestamps=timestamps)

    print(generate_cusum_report(detector, results, "failed_rate"))

    # Plot
    fig = plot_cusum(results, metric_name="Failed Connection Rate (%)")
    plt.savefig("cusum_demo.png", dpi=100, bbox_inches="tight")
    print("\nPlot saved to cusum_demo.png")
