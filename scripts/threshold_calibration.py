#!/usr/bin/env python3
"""Calibration and threshold analysis for security alerting systems.

Decision Threshold Calibration
──────────────────────────────────────────────────────────────────────────────

WHY CALIBRATION MATTERS

Machine learning classifiers output scores (probabilities, distances, etc.)
that require calibration before operational use. The default threshold of 0.5
is often suboptimal because:

1. CLASS IMBALANCE
   Security datasets are typically 99%+ normal traffic. A classifier that
   predicts "normal" for everything achieves 99% accuracy but 0% detection.
   Threshold adjustment compensates for this imbalance.

2. ASYMMETRIC COSTS
   False positives (analyst time wasted) and false negatives (missed attacks)
   have different costs. The optimal threshold balances these costs, which
   vary by organization and threat model.

3. PROBABILITY CALIBRATION
   Many classifiers (including SVM with RBF kernel) produce poorly calibrated
   probabilities. A predicted 0.8 doesn't mean 80% chance of being an attack.
   Calibration methods (Platt scaling, isotonic regression) correct this.


THRESHOLD-ALERT TRADE-OFF

                    Low Threshold (0.2)      High Threshold (0.8)
                    ───────────────────      ────────────────────
Alerts generated    Many                     Few
False positives     High                     Low
False negatives     Low                      High
Analyst workload    Heavy                    Light
Detection rate      High                     Low
Use case            Critical assets,         Mature SOC,
                    zero-miss requirement    limited analysts


OPERATIONAL CALIBRATION WORKFLOW

1. DEFINE CONSTRAINTS
   - Max daily alerts (e.g., 50 alerts/analyst/day)
   - Required detection rate (e.g., must catch 95% of attacks)
   - Cost ratio (false positive cost / false negative cost)

2. ANALYZE TRADE-OFF CURVES
   - Precision-Recall curve: Shows achievable precision at each recall level
   - ROC curve: Shows true positive rate vs false positive rate
   - Alert volume curve: Shows expected alerts at each threshold

3. SELECT THRESHOLD
   - If workload-constrained: Set threshold to achieve target alert volume
   - If detection-constrained: Set threshold to achieve target recall
   - If cost-aware: Set threshold to minimize total expected cost

4. VALIDATE ON HOLDOUT DATA
   - Verify that threshold performs as expected on unseen data
   - Monitor for drift and recalibrate periodically


SENSITIVITY VS WORKLOAD

Sensitivity (recall) = TP / (TP + FN) = Fraction of attacks detected

At different sensitivity levels:
- 99% sensitivity: Catches nearly all attacks, but high FP rate
- 95% sensitivity: Catches most attacks, moderate FP rate
- 90% sensitivity: Misses 10% of attacks, but manageable workload

The right balance depends on:
- Attack severity: Critical infrastructure → high sensitivity
- SOC capacity: 5 analysts → lower sensitivity to avoid burnout
- False positive cost: Automated blocking → lower sensitivity to avoid outages

Usage:
    from scripts.threshold_calibration import ThresholdAnalyzer

    analyzer = ThresholdAnalyzer(y_true, y_scores)
    optimal = analyzer.find_optimal_threshold(target_fpr=0.05)
    analyzer.plot_analysis()
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_recall_curve,
    roc_curve,
    auc,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.calibration import calibration_curve


@dataclass
class ThresholdResult:
    """Result of threshold analysis at a specific threshold."""
    threshold: float
    precision: float
    recall: float
    f1: float
    false_positive_rate: float
    true_positive_rate: float
    predicted_positives: int
    actual_positives: int
    total_samples: int

    @property
    def alert_rate(self) -> float:
        """Fraction of samples that would trigger alerts."""
        return self.predicted_positives / self.total_samples if self.total_samples > 0 else 0

    def to_dict(self) -> dict:
        return {
            "threshold": self.threshold,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "false_positive_rate": self.false_positive_rate,
            "true_positive_rate": self.true_positive_rate,
            "predicted_positives": self.predicted_positives,
            "actual_positives": self.actual_positives,
            "alert_rate": self.alert_rate,
        }


class ThresholdAnalyzer:
    """Analyzer for decision threshold calibration.

    Evaluates classifier performance across a range of thresholds to help
    select the optimal operating point.

    Attributes:
        y_true: True binary labels.
        y_scores: Predicted probabilities (for positive class).
        thresholds: Array of thresholds evaluated.
        results: List of ThresholdResult for each threshold.

    Example:
        >>> analyzer = ThresholdAnalyzer(y_true, y_proba[:, 1])
        >>> optimal = analyzer.find_optimal_threshold(target_recall=0.95)
        >>> print(f"Use threshold {optimal.threshold:.3f} for 95% recall")
        >>> analyzer.plot_analysis()
    """

    def __init__(
        self,
        y_true: np.ndarray,
        y_scores: np.ndarray,
        n_thresholds: int = 100,
    ):
        """Initialize threshold analyzer.

        Args:
            y_true: True binary labels (0 or 1).
            y_scores: Predicted scores/probabilities for positive class.
            n_thresholds: Number of thresholds to evaluate.
        """
        self.y_true = np.asarray(y_true)
        self.y_scores = np.asarray(y_scores)

        # Generate thresholds
        self.thresholds = np.linspace(0.01, 0.99, n_thresholds)

        # Compute metrics at each threshold
        self.results = self._evaluate_thresholds()

        # Compute curves
        self.precision_curve, self.recall_curve, self.pr_thresholds = \
            precision_recall_curve(y_true, y_scores)

        self.fpr_curve, self.tpr_curve, self.roc_thresholds = \
            roc_curve(y_true, y_scores)

        self.roc_auc = auc(self.fpr_curve, self.tpr_curve)

    def _evaluate_thresholds(self) -> List[ThresholdResult]:
        """Evaluate metrics at each threshold."""
        results = []

        for threshold in self.thresholds:
            y_pred = (self.y_scores >= threshold).astype(int)

            tp = np.sum((y_pred == 1) & (self.y_true == 1))
            fp = np.sum((y_pred == 1) & (self.y_true == 0))
            fn = np.sum((y_pred == 0) & (self.y_true == 1))
            tn = np.sum((y_pred == 0) & (self.y_true == 0))

            precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            tpr = tp / (tp + fn) if (tp + fn) > 0 else 0

            results.append(ThresholdResult(
                threshold=threshold,
                precision=precision,
                recall=recall,
                f1=f1,
                false_positive_rate=fpr,
                true_positive_rate=tpr,
                predicted_positives=int(tp + fp),
                actual_positives=int(tp + fn),
                total_samples=len(self.y_true),
            ))

        return results

    def find_optimal_threshold(
        self,
        target_recall: Optional[float] = None,
        target_fpr: Optional[float] = None,
        target_alert_rate: Optional[float] = None,
        maximize: str = "f1",
    ) -> ThresholdResult:
        """Find optimal threshold based on constraints.

        Args:
            target_recall: Minimum required recall (e.g., 0.95 for 95%).
            target_fpr: Maximum allowed false positive rate.
            target_alert_rate: Maximum fraction of samples to alert on.
            maximize: Metric to maximize ("f1", "precision", "recall").

        Returns:
            ThresholdResult for the optimal threshold.
        """
        candidates = self.results.copy()

        # Apply constraints
        if target_recall is not None:
            candidates = [r for r in candidates if r.recall >= target_recall]

        if target_fpr is not None:
            candidates = [r for r in candidates if r.false_positive_rate <= target_fpr]

        if target_alert_rate is not None:
            candidates = [r for r in candidates if r.alert_rate <= target_alert_rate]

        if not candidates:
            # No threshold satisfies all constraints; return best F1
            return max(self.results, key=lambda r: r.f1)

        # Maximize chosen metric among candidates
        if maximize == "f1":
            return max(candidates, key=lambda r: r.f1)
        elif maximize == "precision":
            return max(candidates, key=lambda r: r.precision)
        elif maximize == "recall":
            return max(candidates, key=lambda r: r.recall)
        else:
            return max(candidates, key=lambda r: r.f1)

    def get_threshold_df(self) -> pd.DataFrame:
        """Return threshold analysis as DataFrame."""
        return pd.DataFrame([r.to_dict() for r in self.results])

    def estimate_daily_alerts(
        self,
        threshold: float,
        daily_events: int,
    ) -> dict:
        """Estimate daily alert volume at a given threshold.

        Args:
            threshold: Decision threshold.
            daily_events: Expected daily event count.

        Returns:
            Dictionary with alert volume estimates.
        """
        result = self.get_threshold_result(threshold)

        if result is None:
            result = self.find_optimal_threshold()

        expected_alerts = int(daily_events * result.alert_rate)
        expected_true_alerts = int(expected_alerts * result.precision)
        expected_false_alerts = expected_alerts - expected_true_alerts

        return {
            "threshold": result.threshold,
            "daily_events": daily_events,
            "expected_total_alerts": expected_alerts,
            "expected_true_positives": expected_true_alerts,
            "expected_false_positives": expected_false_alerts,
            "precision": result.precision,
            "recall": result.recall,
        }

    def get_threshold_result(self, threshold: float) -> Optional[ThresholdResult]:
        """Get result for a specific threshold."""
        for result in self.results:
            if abs(result.threshold - threshold) < 0.01:
                return result
        return None

    def plot_analysis(
        self,
        figsize: Tuple[int, int] = (14, 10),
    ) -> "matplotlib.figure.Figure":
        """Plot comprehensive threshold analysis.

        Creates a 2x2 figure with:
        - Precision-Recall curve
        - ROC curve
        - F1 vs Threshold
        - Alert volume vs Threshold

        Returns:
            matplotlib Figure object
        """
        import matplotlib.pyplot as plt

        fig, axes = plt.subplots(2, 2, figsize=figsize)

        # Precision-Recall curve
        ax1 = axes[0, 0]
        ax1.plot(self.recall_curve, self.precision_curve, "b-", linewidth=2)
        ax1.fill_between(self.recall_curve, self.precision_curve, alpha=0.3)
        ax1.set_xlabel("Recall (Sensitivity)")
        ax1.set_ylabel("Precision")
        ax1.set_title("Precision-Recall Curve")
        ax1.grid(True, alpha=0.3)
        ax1.set_xlim([0, 1])
        ax1.set_ylim([0, 1])

        # ROC curve
        ax2 = axes[0, 1]
        ax2.plot(self.fpr_curve, self.tpr_curve, "b-", linewidth=2,
                label=f"ROC (AUC = {self.roc_auc:.3f})")
        ax2.plot([0, 1], [0, 1], "k--", alpha=0.5, label="Random")
        ax2.fill_between(self.fpr_curve, self.tpr_curve, alpha=0.3)
        ax2.set_xlabel("False Positive Rate")
        ax2.set_ylabel("True Positive Rate (Recall)")
        ax2.set_title("ROC Curve")
        ax2.legend(loc="lower right")
        ax2.grid(True, alpha=0.3)
        ax2.set_xlim([0, 1])
        ax2.set_ylim([0, 1])

        # F1, Precision, Recall vs Threshold
        ax3 = axes[1, 0]
        df = self.get_threshold_df()
        ax3.plot(df["threshold"], df["f1"], "b-", linewidth=2, label="F1")
        ax3.plot(df["threshold"], df["precision"], "g--", linewidth=1.5, label="Precision")
        ax3.plot(df["threshold"], df["recall"], "r--", linewidth=1.5, label="Recall")

        # Mark optimal F1
        optimal = self.find_optimal_threshold(maximize="f1")
        ax3.axvline(x=optimal.threshold, color="purple", linestyle=":",
                   label=f"Optimal F1 ({optimal.threshold:.2f})")

        ax3.set_xlabel("Decision Threshold")
        ax3.set_ylabel("Score")
        ax3.set_title("Metrics vs Threshold")
        ax3.legend(loc="center right")
        ax3.grid(True, alpha=0.3)
        ax3.set_xlim([0, 1])
        ax3.set_ylim([0, 1])

        # Alert rate vs Threshold
        ax4 = axes[1, 1]
        ax4.plot(df["threshold"], df["alert_rate"] * 100, "b-", linewidth=2)
        ax4.fill_between(df["threshold"], df["alert_rate"] * 100, alpha=0.3)
        ax4.set_xlabel("Decision Threshold")
        ax4.set_ylabel("Alert Rate (%)")
        ax4.set_title("Alert Volume vs Threshold")
        ax4.grid(True, alpha=0.3)
        ax4.set_xlim([0, 1])

        plt.tight_layout()
        return fig


def analyze_workload_scenarios(
    analyzer: ThresholdAnalyzer,
    daily_events: int,
    analyst_capacity: int = 50,
) -> pd.DataFrame:
    """Analyze different threshold scenarios for workload planning.

    Args:
        analyzer: Fitted ThresholdAnalyzer.
        daily_events: Expected daily event count.
        analyst_capacity: Max alerts one analyst can handle per day.

    Returns:
        DataFrame with scenarios showing required analysts and detection rates.
    """
    scenarios = []

    for recall_target in [0.99, 0.95, 0.90, 0.85, 0.80]:
        result = analyzer.find_optimal_threshold(target_recall=recall_target)
        estimates = analyzer.estimate_daily_alerts(result.threshold, daily_events)

        analysts_needed = max(1, estimates["expected_total_alerts"] // analyst_capacity + 1)

        scenarios.append({
            "target_recall": recall_target,
            "threshold": result.threshold,
            "expected_daily_alerts": estimates["expected_total_alerts"],
            "expected_true_positives": estimates["expected_true_positives"],
            "expected_false_positives": estimates["expected_false_positives"],
            "precision": estimates["precision"],
            "analysts_needed": analysts_needed,
        })

    return pd.DataFrame(scenarios)


def generate_calibration_report(
    analyzer: ThresholdAnalyzer,
    daily_events: int = 100000,
    recommended_threshold: Optional[float] = None,
) -> str:
    """Generate comprehensive calibration report."""
    if recommended_threshold is None:
        optimal = analyzer.find_optimal_threshold(maximize="f1")
        recommended_threshold = optimal.threshold
    else:
        optimal = analyzer.get_threshold_result(recommended_threshold)
        if optimal is None:
            optimal = analyzer.find_optimal_threshold()

    estimates = analyzer.estimate_daily_alerts(recommended_threshold, daily_events)

    lines = [
        "THRESHOLD CALIBRATION REPORT",
        "=" * 60,
        "",
        "DATASET SUMMARY",
        "-" * 40,
        f"  Total samples:     {len(analyzer.y_true)}",
        f"  Positive samples:  {sum(analyzer.y_true)} ({sum(analyzer.y_true)/len(analyzer.y_true)*100:.1f}%)",
        f"  Negative samples:  {len(analyzer.y_true) - sum(analyzer.y_true)}",
        "",
        "MODEL PERFORMANCE",
        "-" * 40,
        f"  ROC AUC:           {analyzer.roc_auc:.4f}",
        "",
        "RECOMMENDED THRESHOLD",
        "-" * 40,
        f"  Threshold:         {optimal.threshold:.3f}",
        f"  Precision:         {optimal.precision:.4f}",
        f"  Recall:            {optimal.recall:.4f}",
        f"  F1 Score:          {optimal.f1:.4f}",
        f"  False Positive Rate: {optimal.false_positive_rate:.4f}",
        "",
        f"PROJECTED DAILY WORKLOAD ({daily_events:,} events/day)",
        "-" * 40,
        f"  Expected total alerts:    {estimates['expected_total_alerts']:,}",
        f"  Expected true positives:  {estimates['expected_true_positives']:,}",
        f"  Expected false positives: {estimates['expected_false_positives']:,}",
        "",
        "THRESHOLD SENSITIVITY ANALYSIS",
        "-" * 40,
    ]

    # Show a few key thresholds
    for thresh in [0.3, 0.5, 0.7, 0.9]:
        result = analyzer.get_threshold_result(thresh)
        if result:
            lines.append(
                f"  t={thresh:.1f}: Precision={result.precision:.2f}, "
                f"Recall={result.recall:.2f}, Alert Rate={result.alert_rate*100:.1f}%"
            )

    lines.extend([
        "",
        "GUIDANCE",
        "-" * 40,
        "  - Lower threshold → More alerts, higher recall, more FPs",
        "  - Higher threshold → Fewer alerts, lower recall, fewer FPs",
        "  - Choose based on SOC capacity and risk tolerance",
        "",
        "=" * 60,
    ])

    return "\n".join(lines)


if __name__ == "__main__":
    # Demo with synthetic data
    import matplotlib.pyplot as plt

    np.random.seed(42)

    # Generate synthetic scores
    n_samples = 1000
    n_positive = 50  # 5% positive rate

    # True labels
    y_true = np.zeros(n_samples)
    y_true[:n_positive] = 1
    np.random.shuffle(y_true)

    # Simulated classifier scores (imperfect separation)
    y_scores = np.where(
        y_true == 1,
        np.random.beta(5, 2, n_samples),  # Positives: scores skewed high
        np.random.beta(2, 5, n_samples),  # Negatives: scores skewed low
    )

    # Analyze
    analyzer = ThresholdAnalyzer(y_true, y_scores)

    # Print report
    print(generate_calibration_report(analyzer, daily_events=100000))

    # Workload analysis
    print("\nWORKLOAD SCENARIO ANALYSIS")
    print("-" * 60)
    scenarios = analyze_workload_scenarios(analyzer, daily_events=100000)
    print(scenarios.to_string(index=False))

    # Plot
    fig = analyzer.plot_analysis()
    plt.savefig("threshold_analysis.png", dpi=100, bbox_inches="tight")
    print("\nPlot saved to threshold_analysis.png")
