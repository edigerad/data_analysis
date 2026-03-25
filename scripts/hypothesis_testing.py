#!/usr/bin/env python3
"""Hypothesis testing for network traffic anomaly detection.

Statistical Hypothesis Testing Framework
──────────────────────────────────────────────────────────────────────────────

CONCEPTUAL FRAMEWORK

In cybersecurity anomaly detection, we frame the problem as:

    H0 (Null Hypothesis):     Traffic behavior is NORMAL
    H1 (Alternative Hypothesis): Traffic behavior is ANOMALOUS

This mirrors the legal principle "innocent until proven guilty"—we assume
traffic is benign unless evidence strongly suggests otherwise.

WHY HYPOTHESIS TESTING FOR SECURITY?

1. QUANTIFIED CONFIDENCE
   A p-value of 0.001 means "there's only a 0.1% chance this traffic pattern
   would occur under normal conditions." This quantifies our confidence in
   the alert, unlike binary threshold rules.

2. FALSE POSITIVE RATE CONTROL
   By setting significance level α (e.g., 0.05), we explicitly control the
   false positive rate. In SOC operations, this maps directly to analyst
   workload: α=0.01 means ~1% of alerts are expected false positives.

3. SAMPLE SIZE AWARENESS
   Tests account for sample size—detecting an anomaly in 10 connections vs
   10,000 requires different levels of deviation. Naive threshold rules
   don't adapt to sample size.

4. INTERPRETABLE OUTPUT
   "Rejected H0 at α=0.01 with p=0.003" is actionable: the analyst knows
   this is a high-confidence alert worth investigating.

MAPPING TO OPERATIONAL ALERTING

    p-value < 0.001  →  CRITICAL: Investigate immediately
    p-value < 0.01   →  HIGH: Investigate within 1 hour
    p-value < 0.05   →  MEDIUM: Add to daily review queue
    p-value >= 0.05  →  LOW: Log for trend analysis only

This provides a principled framework for alert prioritization that scales
with analyst capacity.

Tests Implemented
─────────────────
1. One-sample z-test: Compare observed rate to baseline
2. Proportion test: For rates (failed connections, NXDOMAIN)
3. Two-sample test: Compare two time periods

Usage:
    from scripts.hypothesis_testing import HypothesisTest, test_failed_rate

    result = test_failed_rate(observed_rate=0.25, baseline_rate=0.05, n_samples=100)
    if result.reject_null:
        print(f"Alert! p-value = {result.p_value:.4f}")
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

import numpy as np
from scipy import stats
import pandas as pd


class AlertSeverity(Enum):
    """Alert severity levels based on p-value."""
    CRITICAL = "CRITICAL"  # p < 0.001
    HIGH = "HIGH"          # p < 0.01
    MEDIUM = "MEDIUM"      # p < 0.05
    LOW = "LOW"            # p >= 0.05


@dataclass
class HypothesisTestResult:
    """Result of a statistical hypothesis test."""

    test_name: str
    metric: str
    observed_value: float
    expected_value: float
    test_statistic: float
    p_value: float
    alpha: float
    reject_null: bool
    severity: AlertSeverity
    interpretation: str

    def to_dict(self) -> dict:
        return {
            "test_name": self.test_name,
            "metric": self.metric,
            "observed_value": self.observed_value,
            "expected_value": self.expected_value,
            "test_statistic": self.test_statistic,
            "p_value": self.p_value,
            "alpha": self.alpha,
            "reject_null": self.reject_null,
            "severity": self.severity.value,
            "interpretation": self.interpretation,
        }


def _get_severity(p_value: float) -> AlertSeverity:
    """Map p-value to alert severity."""
    if p_value < 0.001:
        return AlertSeverity.CRITICAL
    elif p_value < 0.01:
        return AlertSeverity.HIGH
    elif p_value < 0.05:
        return AlertSeverity.MEDIUM
    else:
        return AlertSeverity.LOW


def one_sample_z_test(
    observed_mean: float,
    population_mean: float,
    population_std: float,
    n_samples: int,
    alpha: float = 0.05,
    alternative: str = "two-sided",
    metric_name: str = "metric",
) -> HypothesisTestResult:
    """Perform one-sample z-test.

    Tests whether an observed sample mean differs significantly from
    a known population mean.

    Mathematical formulation:
        z = (x̄ - μ) / (σ / √n)

    where:
        x̄ = sample mean (observed_mean)
        μ = population mean (baseline)
        σ = population standard deviation
        n = sample size

    Args:
        observed_mean: Sample mean from current data.
        population_mean: Baseline mean (from historical data).
        population_std: Baseline standard deviation.
        n_samples: Number of observations in sample.
        alpha: Significance level (default 0.05).
        alternative: "two-sided", "greater", or "less".
        metric_name: Name for reporting.

    Returns:
        HypothesisTestResult with test outcome.

    Example:
        >>> result = one_sample_z_test(
        ...     observed_mean=0.25,  # 25% failed rate
        ...     population_mean=0.10,  # baseline 10%
        ...     population_std=0.05,
        ...     n_samples=100
        ... )
        >>> print(result.p_value)
    """
    if n_samples <= 0:
        raise ValueError("n_samples must be positive")
    if population_std <= 0:
        raise ValueError("population_std must be positive")

    # Compute z-statistic
    standard_error = population_std / np.sqrt(n_samples)
    z_stat = (observed_mean - population_mean) / standard_error

    # Compute p-value based on alternative hypothesis
    if alternative == "two-sided":
        p_value = 2 * (1 - stats.norm.cdf(abs(z_stat)))
    elif alternative == "greater":
        p_value = 1 - stats.norm.cdf(z_stat)
    elif alternative == "less":
        p_value = stats.norm.cdf(z_stat)
    else:
        raise ValueError(f"Invalid alternative: {alternative}")

    reject_null = p_value < alpha
    severity = _get_severity(p_value)

    # Generate interpretation
    if reject_null:
        interpretation = (
            f"REJECT H0: Observed {metric_name} ({observed_mean:.4f}) is significantly "
            f"different from baseline ({population_mean:.4f}) at α={alpha}. "
            f"This pattern has only {p_value*100:.2f}% probability under normal conditions."
        )
    else:
        interpretation = (
            f"FAIL TO REJECT H0: Observed {metric_name} ({observed_mean:.4f}) is not "
            f"significantly different from baseline ({population_mean:.4f}) at α={alpha}. "
            f"This pattern is consistent with normal behavior."
        )

    return HypothesisTestResult(
        test_name="One-Sample Z-Test",
        metric=metric_name,
        observed_value=observed_mean,
        expected_value=population_mean,
        test_statistic=z_stat,
        p_value=p_value,
        alpha=alpha,
        reject_null=reject_null,
        severity=severity,
        interpretation=interpretation,
    )


def proportion_test(
    observed_successes: int,
    n_observations: int,
    baseline_proportion: float,
    alpha: float = 0.05,
    alternative: str = "greater",
    metric_name: str = "rate",
) -> HypothesisTestResult:
    """Test if observed proportion differs from baseline.

    Uses normal approximation to binomial distribution (valid when
    np >= 10 and n(1-p) >= 10).

    Mathematical formulation:
        z = (p̂ - p₀) / √(p₀(1-p₀)/n)

    where:
        p̂ = observed proportion (observed_successes / n_observations)
        p₀ = baseline proportion
        n = number of observations

    This is particularly useful for:
    - Failed connection rate (is it higher than baseline?)
    - NXDOMAIN rate (is it higher than baseline?)
    - TI match rate (is it higher than expected?)

    Args:
        observed_successes: Number of "events" (failures, NXDOMAIN, etc.)
        n_observations: Total number of observations.
        baseline_proportion: Expected proportion under H0.
        alpha: Significance level.
        alternative: "two-sided", "greater", or "less".
        metric_name: Name for reporting.

    Returns:
        HypothesisTestResult with test outcome.

    Example:
        >>> # Test if 30 failed connections out of 100 is anomalous
        >>> # when baseline failure rate is 10%
        >>> result = proportion_test(
        ...     observed_successes=30,
        ...     n_observations=100,
        ...     baseline_proportion=0.10,
        ...     alternative="greater"
        ... )
    """
    if n_observations <= 0:
        raise ValueError("n_observations must be positive")
    if not 0 <= baseline_proportion <= 1:
        raise ValueError("baseline_proportion must be between 0 and 1")

    observed_proportion = observed_successes / n_observations

    # Standard error under null hypothesis
    se = np.sqrt(baseline_proportion * (1 - baseline_proportion) / n_observations)

    if se == 0:
        # Edge case: baseline is 0 or 1
        z_stat = np.inf if observed_proportion != baseline_proportion else 0
        p_value = 0 if observed_proportion != baseline_proportion else 1
    else:
        z_stat = (observed_proportion - baseline_proportion) / se

        if alternative == "two-sided":
            p_value = 2 * (1 - stats.norm.cdf(abs(z_stat)))
        elif alternative == "greater":
            p_value = 1 - stats.norm.cdf(z_stat)
        elif alternative == "less":
            p_value = stats.norm.cdf(z_stat)
        else:
            raise ValueError(f"Invalid alternative: {alternative}")

    reject_null = p_value < alpha
    severity = _get_severity(p_value)

    # Generate interpretation
    direction = "higher" if observed_proportion > baseline_proportion else "lower"
    if reject_null:
        interpretation = (
            f"REJECT H0: Observed {metric_name} ({observed_proportion*100:.1f}%) is "
            f"significantly {direction} than baseline ({baseline_proportion*100:.1f}%) "
            f"at α={alpha}. p-value = {p_value:.4f}"
        )
    else:
        interpretation = (
            f"FAIL TO REJECT H0: Observed {metric_name} ({observed_proportion*100:.1f}%) is "
            f"not significantly different from baseline ({baseline_proportion*100:.1f}%) "
            f"at α={alpha}. p-value = {p_value:.4f}"
        )

    return HypothesisTestResult(
        test_name="One-Proportion Z-Test",
        metric=metric_name,
        observed_value=observed_proportion,
        expected_value=baseline_proportion,
        test_statistic=z_stat,
        p_value=p_value,
        alpha=alpha,
        reject_null=reject_null,
        severity=severity,
        interpretation=interpretation,
    )


def test_failed_connection_rate(
    conn: pd.DataFrame,
    baseline_rate: float,
    alpha: float = 0.05,
) -> HypothesisTestResult:
    """Test if failed connection rate is anomalously high.

    Args:
        conn: Connection DataFrame with conn_state column.
        baseline_rate: Expected failure rate (proportion, e.g., 0.05 for 5%).
        alpha: Significance level.

    Returns:
        HypothesisTestResult
    """
    failed_states = ["S0", "REJ", "RSTO", "RSTR", "S1", "S2", "S3"]
    state_col = "conn_state" if "conn_state" in conn.columns else "conn_state"

    n_total = len(conn)
    n_failed = conn[state_col].isin(failed_states).sum()

    return proportion_test(
        observed_successes=n_failed,
        n_observations=n_total,
        baseline_proportion=baseline_rate,
        alpha=alpha,
        alternative="greater",
        metric_name="failed_connection_rate",
    )


def test_nxdomain_rate(
    dns: pd.DataFrame,
    baseline_rate: float,
    alpha: float = 0.05,
) -> HypothesisTestResult:
    """Test if NXDOMAIN rate is anomalously high.

    High NXDOMAIN rates may indicate:
    - Domain Generation Algorithm (DGA) malware
    - DNS tunneling attempts
    - Misconfigured applications

    Args:
        dns: DNS DataFrame with dns_rcode or rcode_name column.
        baseline_rate: Expected NXDOMAIN rate (proportion).
        alpha: Significance level.

    Returns:
        HypothesisTestResult
    """
    rcode_col = "dns_rcode" if "dns_rcode" in dns.columns else "rcode_name"

    n_total = len(dns)
    n_nxdomain = (dns[rcode_col] == "NXDOMAIN").sum()

    return proportion_test(
        observed_successes=n_nxdomain,
        n_observations=n_total,
        baseline_proportion=baseline_rate,
        alpha=alpha,
        alternative="greater",
        metric_name="nxdomain_rate",
    )


def two_sample_proportion_test(
    successes_1: int,
    n_1: int,
    successes_2: int,
    n_2: int,
    alpha: float = 0.05,
    metric_name: str = "rate",
) -> HypothesisTestResult:
    """Compare proportions between two samples.

    Useful for:
    - Comparing today's failure rate to yesterday's
    - Comparing one host's behavior to the network baseline
    - A/B testing security controls

    Mathematical formulation:
        z = (p̂₁ - p̂₂) / √(p̂(1-p̂)(1/n₁ + 1/n₂))

    where p̂ is the pooled proportion.

    Args:
        successes_1: Events in sample 1.
        n_1: Size of sample 1.
        successes_2: Events in sample 2.
        n_2: Size of sample 2.
        alpha: Significance level.
        metric_name: Name for reporting.

    Returns:
        HypothesisTestResult
    """
    p1 = successes_1 / n_1
    p2 = successes_2 / n_2

    # Pooled proportion
    p_pooled = (successes_1 + successes_2) / (n_1 + n_2)

    # Standard error
    se = np.sqrt(p_pooled * (1 - p_pooled) * (1/n_1 + 1/n_2))

    if se == 0:
        z_stat = 0 if p1 == p2 else np.inf
        p_value = 1 if p1 == p2 else 0
    else:
        z_stat = (p1 - p2) / se
        p_value = 2 * (1 - stats.norm.cdf(abs(z_stat)))

    reject_null = p_value < alpha
    severity = _get_severity(p_value)

    if reject_null:
        interpretation = (
            f"REJECT H0: Sample 1 {metric_name} ({p1*100:.1f}%) differs significantly "
            f"from Sample 2 ({p2*100:.1f}%) at α={alpha}. p-value = {p_value:.4f}"
        )
    else:
        interpretation = (
            f"FAIL TO REJECT H0: No significant difference in {metric_name} between "
            f"samples ({p1*100:.1f}% vs {p2*100:.1f}%) at α={alpha}."
        )

    return HypothesisTestResult(
        test_name="Two-Proportion Z-Test",
        metric=metric_name,
        observed_value=p1,
        expected_value=p2,
        test_statistic=z_stat,
        p_value=p_value,
        alpha=alpha,
        reject_null=reject_null,
        severity=severity,
        interpretation=interpretation,
    )


class AlertingFramework:
    """Framework for statistical alerting based on hypothesis testing.

    Maps statistical test results to operational security alerts with
    severity levels and recommended actions.

    Example:
        >>> framework = AlertingFramework(baseline_failed_rate=0.05, baseline_nx_rate=0.10)
        >>> alerts = framework.evaluate(conn, dns)
        >>> for alert in alerts:
        ...     print(f"[{alert.severity.value}] {alert.interpretation}")
    """

    def __init__(
        self,
        baseline_failed_rate: float = 0.05,
        baseline_nxdomain_rate: float = 0.10,
        alpha: float = 0.05,
    ):
        """Initialize alerting framework.

        Args:
            baseline_failed_rate: Expected connection failure rate.
            baseline_nxdomain_rate: Expected NXDOMAIN rate.
            alpha: Significance level for all tests.
        """
        self.baseline_failed_rate = baseline_failed_rate
        self.baseline_nxdomain_rate = baseline_nxdomain_rate
        self.alpha = alpha

    def evaluate(
        self,
        conn: pd.DataFrame,
        dns: pd.DataFrame,
    ) -> list[HypothesisTestResult]:
        """Evaluate all configured tests and return alerts.

        Args:
            conn: Connection DataFrame.
            dns: DNS DataFrame.

        Returns:
            List of test results that triggered alerts (reject_null=True).
        """
        results = []

        # Test failed connection rate
        if len(conn) > 0:
            result = test_failed_connection_rate(conn, self.baseline_failed_rate, self.alpha)
            results.append(result)

        # Test NXDOMAIN rate
        if len(dns) > 0:
            result = test_nxdomain_rate(dns, self.baseline_nxdomain_rate, self.alpha)
            results.append(result)

        return results

    def get_alerts_only(
        self,
        conn: pd.DataFrame,
        dns: pd.DataFrame,
    ) -> list[HypothesisTestResult]:
        """Return only tests that triggered alerts."""
        return [r for r in self.evaluate(conn, dns) if r.reject_null]

    def generate_report(
        self,
        conn: pd.DataFrame,
        dns: pd.DataFrame,
    ) -> str:
        """Generate human-readable alert report."""
        results = self.evaluate(conn, dns)

        lines = [
            "HYPOTHESIS TESTING ALERT REPORT",
            "=" * 60,
            "",
            f"Significance level (α): {self.alpha}",
            f"Connection baseline failure rate: {self.baseline_failed_rate*100:.1f}%",
            f"DNS baseline NXDOMAIN rate: {self.baseline_nxdomain_rate*100:.1f}%",
            "",
            "TEST RESULTS",
            "-" * 60,
        ]

        for result in results:
            status = "ALERT" if result.reject_null else "OK"
            lines.extend([
                "",
                f"[{result.severity.value}] {result.test_name} - {status}",
                f"  Metric: {result.metric}",
                f"  Observed: {result.observed_value:.4f}",
                f"  Expected: {result.expected_value:.4f}",
                f"  z-statistic: {result.test_statistic:.2f}",
                f"  p-value: {result.p_value:.6f}",
                f"  {result.interpretation}",
            ])

        # Summary
        alerts = [r for r in results if r.reject_null]
        lines.extend([
            "",
            "=" * 60,
            f"SUMMARY: {len(alerts)} alert(s) triggered out of {len(results)} tests",
        ])

        if alerts:
            lines.append("\nRECOMMENDED ACTIONS:")
            for alert in alerts:
                if alert.severity == AlertSeverity.CRITICAL:
                    lines.append(f"  - {alert.metric}: INVESTIGATE IMMEDIATELY")
                elif alert.severity == AlertSeverity.HIGH:
                    lines.append(f"  - {alert.metric}: Investigate within 1 hour")
                elif alert.severity == AlertSeverity.MEDIUM:
                    lines.append(f"  - {alert.metric}: Add to daily review queue")

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

    # Run alerting framework
    framework = AlertingFramework(
        baseline_failed_rate=0.05,
        baseline_nxdomain_rate=0.10,
        alpha=0.05,
    )

    print(framework.generate_report(conn, dns))
