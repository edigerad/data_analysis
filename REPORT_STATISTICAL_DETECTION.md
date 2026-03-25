# Statistical Foundations for Network Anomaly Detection

## Executive Summary

This report documents the implementation of statistical and machine learning methods for detecting anomalies in network traffic. The work extends an existing Zeek-based analysis pipeline with six key components: statistical baseline modeling, hypothesis testing, time series preparation, CUSUM change detection, SVM classification, and threshold calibration.

---

## Part 1: Statistical Baseline Modeling

### Theoretical Foundation

Before applying machine learning algorithms, it is essential to establish statistical baselines that characterize "normal" behavior. This foundational step serves multiple purposes:

1. **Understanding Normal Behavior**: Baseline statistics (mean, standard deviation, percentiles) provide a quantitative definition of typical network patterns. Without this, ML models may learn to detect noise rather than genuine anomalies.

2. **Interpretability**: Z-scores provide immediately actionable anomaly scores. A statement like "this value is 4 standard deviations from the mean" is more interpretable to security analysts than an opaque probability score.

3. **Computational Efficiency**: Statistical baselines compute in O(n) time with minimal memory, making them suitable for resource-constrained environments like SIEM agents or edge sensors.

4. **Feature Engineering Guidance**: Baseline analysis reveals which metrics exhibit useful variance. If a metric has near-zero standard deviation, it won't contribute to classification.

### Implementation

The `BaselineModel` class computes statistics for three key security metrics:

- **Failed connection rate**: Percentage of connections in failed states (S0, REJ, RSTO, RSTR)
- **NXDOMAIN rate**: Percentage of DNS queries returning NXDOMAIN
- **Bytes sent/received ratio**: Indicator of potential data exfiltration

For each metric, we compute:
- Mean (μ)
- Standard deviation (σ)
- Z-score: z = (x - μ) / σ

Anomalies are flagged when |z| exceeds a configurable threshold (default: 3.0, corresponding to 99.7% confidence under Gaussian assumption).

### Code Reference

See `scripts/baseline_modeling.py` for the implementation.

```python
from scripts.baseline_modeling import BaselineModel

model = BaselineModel(z_threshold=2.0)
model.fit(conn_df, dns_df, time_window="1min")
anomalies = model.detect_anomalies(new_conn_df, new_dns_df)
```

---

## Part 2: Hypothesis Testing

### Theoretical Foundation

Formalizing anomaly detection as statistical hypothesis testing provides a rigorous framework for decision-making:

- **H₀ (Null Hypothesis)**: Traffic behavior is normal
- **H₁ (Alternative Hypothesis)**: Traffic behavior is anomalous

This framing offers several advantages:

1. **Quantified Confidence**: The p-value indicates the probability of observing the data under normal conditions. A p-value of 0.001 means "there's only a 0.1% chance this pattern would occur naturally."

2. **Controlled False Positive Rate**: By setting significance level α (e.g., 0.05), we explicitly control the expected false positive rate.

3. **Sample Size Awareness**: Tests naturally account for sample size—detecting an anomaly in 10 observations requires more extreme deviation than in 10,000 observations.

### Tests Implemented

**One-sample z-test** for comparing observed rates to baseline:

$$z = \frac{\bar{x} - \mu}{\sigma / \sqrt{n}}$$

**Proportion test** for rates like failed connections and NXDOMAIN:

$$z = \frac{\hat{p} - p_0}{\sqrt{p_0(1-p_0)/n}}$$

### Operational Mapping

| p-value | Severity | Recommended Action |
|---------|----------|-------------------|
| < 0.001 | CRITICAL | Investigate immediately |
| < 0.01 | HIGH | Investigate within 1 hour |
| < 0.05 | MEDIUM | Daily review queue |
| ≥ 0.05 | LOW | Log for trend analysis |

### Code Reference

See `scripts/hypothesis_testing.py` for the implementation.

```python
from scripts.hypothesis_testing import AlertingFramework

framework = AlertingFramework(
    baseline_failed_rate=0.05,
    baseline_nxdomain_rate=0.10,
    alpha=0.05
)
alerts = framework.get_alerts_only(conn_df, dns_df)
```

---

## Part 3: Time Series Preparation

### Key Concepts

#### Nonstationarity

A time series is **stationary** if its statistical properties (mean, variance, autocorrelation) remain constant over time. Network traffic is typically **non-stationary**:

- Business hours have higher traffic than nights/weekends
- Month-end processing increases certain traffic types
- Application deployments change baseline behavior
- Attack campaigns create sudden pattern shifts

Non-stationarity implies that a single global baseline may be inappropriate; baselines should adapt to temporal context.

#### Seasonality

Network traffic exhibits predictable recurring patterns:

- **Hourly**: DNS spikes at hour boundaries (cron jobs)
- **Daily**: Web traffic peaks during business hours
- **Weekly**: Monday morning shows highest email volume
- **Monthly**: Financial transactions spike at month-end

Security implications: Attackers may time activities to blend with seasonal peaks. Conversely, the same activity at 3 AM may be highly suspicious.

#### Why Random Train/Test Split is Invalid

Standard ML practice involves random 80/20 train/test splits. For time series, this approach is **fundamentally flawed**:

1. **Temporal Leakage**: Random splitting allows training data to contain samples from AFTER test samples, causing the model to "see the future" and producing artificially inflated accuracy.

2. **Autocorrelation Violated**: Adjacent time points are correlated. Random splitting treats them as independent, underestimating variance.

3. **Distribution Shift Ignored**: The test set should represent future data. Random sampling mixes past and future, failing to evaluate forward prediction.

**Correct Approach**: Temporal split where all training data precedes all validation data, which precedes all test data.

### Implementation

The `TimeSeriesPreprocessor` class:
1. Aggregates raw events into fixed time buckets (e.g., 1-minute windows)
2. Computes per-bucket metrics (counts, rates)
3. Adds rolling statistics (rolling mean, rolling variance, rolling z-score)

```python
from scripts.timeseries_prep import TimeSeriesPreprocessor, temporal_train_test_split

prep = TimeSeriesPreprocessor(bucket_size="1min", window_size=15)
ts_data = prep.transform(conn_df, dns_df)

train, val, test = temporal_train_test_split(ts_data, train_ratio=0.7, val_ratio=0.15)
```

### Code Reference

See `scripts/timeseries_prep.py` for the implementation.

---

## Part 4: CUSUM Change Detection

### Theoretical Foundation

CUSUM (Cumulative Sum) is a sequential analysis technique for detecting shifts in the mean of a process. Originally developed for quality control, it's highly effective for detecting regime changes in network traffic.

#### Mathematical Formulation

Given observations x₁, x₂, ..., xₙ with expected mean μ:

**Upper CUSUM** (detects increase):
$$S_n^+ = \max(0, S_{n-1}^+ + (x_n - \mu) - k)$$

**Lower CUSUM** (detects decrease):
$$S_n^- = \max(0, S_{n-1}^- - (x_n - \mu) - k)$$

Where:
- k = allowance parameter (slack, typically 0.5σ)
- h = decision threshold (typically 4-5σ)

A change is detected when S⁺ₙ > h or S⁻ₙ > h.

### Why CUSUM for Security?

1. **Early Detection**: CUSUM accumulates evidence across observations. A persistent but subtle shift (5% → 8% failure rate) triggers faster than threshold methods.

2. **Low False Positive Rate**: Random noise cancels out in the cumulative sum. Only persistent shifts accumulate enough to exceed threshold.

3. **Interpretable Change Points**: CUSUM identifies WHEN the change occurred, helping responders pinpoint attack start time.

4. **Minimal Parameters**: Only k and h need tuning, unlike complex ML models.

5. **Online Computation**: O(1) update per observation—suitable for real-time streaming.

### Code Reference

See `scripts/cusum_detector.py` for the implementation.

```python
from scripts.cusum_detector import CUSUMDetector

detector = CUSUMDetector()
detector.fit_from_data(baseline_data, k_factor=0.5, h_factor=4.0)
results = detector.detect_all(new_data, timestamps=timestamps)
```

---

## Part 5: SVM Classification

### Theoretical Foundation

Support Vector Machines (SVMs) find the optimal hyperplane that separates classes with **maximum margin**—the distance between the decision boundary and nearest training points (support vectors).

### The Role of C (Regularization)

The C parameter controls the margin/misclassification trade-off:

- **C = 0.1** (soft margin): Tolerates more misclassifications, wider margin, better generalization to unseen data
- **C = 1.0** (balanced): Default balance
- **C = 10** (hard margin): Minimizes training error, narrower margin, may overfit

**Security context**:
- Low C → Fewer alerts, may miss some attacks (higher false negative rate)
- High C → More alerts, catches more attacks but also more false positives

### The Role of Kernel

When classes aren't linearly separable, kernel functions project data into higher dimensions:

- **Linear**: K(x,y) = x·y — fastest, good for high-dimensional sparse data
- **RBF** (Radial Basis Function): K(x,y) = exp(-γ||x-y||²) — flexible, handles non-linear boundaries
- **Polynomial**: K(x,y) = (x·y + c)^d — captures polynomial relationships

### Operational Trade-offs

| | False Positives | False Negatives |
|--|-----------------|-----------------|
| **Impact** | Analyst time wasted, alert fatigue | Attacks missed, longer dwell time |
| **High tolerance** | Limited SOC capacity | Low-criticality systems |
| **Low tolerance** | Automated response enabled | Critical assets, compliance |

### Features Used

- **duration**: Connection duration in seconds
- **bytes_sent**: Bytes from source to destination
- **bytes_recv**: Bytes from destination to source
- **bytes_ratio**: Ratio of sent to received bytes
- **failed**: Binary indicator for failed connection states
- **ti_match**: Binary indicator for threat intelligence match
- **nxdomain**: Binary indicator for NXDOMAIN response

### Code Reference

See `scripts/svm_classifier.py` for the implementation.

```python
from scripts.svm_classifier import SVMClassifier, prepare_features

X, y = prepare_features(conn_df, dns_df)
classifier = SVMClassifier(kernel="rbf", C=1.0, class_weight="balanced")
classifier.fit(X_train, y_train)
metrics = classifier.evaluate(X_test, y_test)
```

---

## Part 6: Calibration and Threshold Analysis

### The Decision Threshold Problem

ML classifiers output scores (probabilities). The **threshold** converts these to binary decisions:

- score ≥ threshold → Alert
- score < threshold → No alert

The default threshold of 0.5 is often suboptimal due to:

1. **Class Imbalance**: Security data is typically 99%+ normal. A classifier that always predicts "normal" achieves 99% accuracy but 0% detection.

2. **Asymmetric Costs**: False positives and false negatives have different costs that vary by organization.

3. **Probability Calibration**: Many classifiers produce poorly calibrated probabilities.

### Threshold-Alert Trade-off

| Low Threshold (0.2) | High Threshold (0.8) |
|---------------------|----------------------|
| Many alerts | Few alerts |
| High recall | Low recall |
| High FP rate | Low FP rate |
| Heavy analyst workload | Light workload |
| Use: Critical assets | Use: Limited SOC capacity |

### Calibration Workflow

1. **Define Constraints**: Max daily alerts, required detection rate, cost ratio
2. **Analyze Curves**: Precision-recall, ROC, alert volume vs threshold
3. **Select Threshold**: Based on workload, detection, or cost constraints
4. **Validate on Holdout**: Verify performance on unseen data
5. **Monitor for Drift**: Recalibrate periodically

### Code Reference

See `scripts/threshold_calibration.py` for the implementation.

```python
from scripts.threshold_calibration import ThresholdAnalyzer, analyze_workload_scenarios

analyzer = ThresholdAnalyzer(y_true, y_scores)
optimal = analyzer.find_optimal_threshold(target_recall=0.95)
scenarios = analyze_workload_scenarios(analyzer, daily_events=100000)
```

---

## Reproducibility

All code maintains the reproducibility principles established in the base repository:

1. **Random Seeds**: All random operations use fixed seeds (default: 42)
2. **Version Tracking**: Dependencies pinned in requirements.txt
3. **Checksums**: Pipeline outputs include SHA-256 checksums
4. **Intermediate Outputs**: All stages saved to outputs/intermediate/

## File Structure

```
scripts/
├── baseline_modeling.py      # Part 1: Statistical baselines
├── hypothesis_testing.py     # Part 2: Hypothesis tests
├── timeseries_prep.py        # Part 3: Time series preparation
├── cusum_detector.py         # Part 4: CUSUM change detection
├── svm_classifier.py         # Part 5: SVM classification
└── threshold_calibration.py  # Part 6: Threshold analysis

notebooks/
└── 02_statistical_detection.ipynb  # Interactive demonstration
```

## Dependencies

Added to requirements.txt:
- scipy>=1.11 (hypothesis testing, CUSUM)
- scikit-learn>=1.3 (SVM, metrics, preprocessing)
- numpy>=1.24 (numerical operations)

## Conclusion

This implementation provides a complete toolkit for network anomaly detection, progressing from interpretable statistical methods to sophisticated ML classification. The key insight is that these approaches are complementary:

- **Baselines** establish what's normal
- **Hypothesis tests** quantify confidence in deviations
- **Time series analysis** respects temporal structure
- **CUSUM** detects regime changes early
- **SVM** handles complex multi-feature classification
- **Calibration** balances detection against operational constraints

Practitioners should start with simpler statistical methods, which often suffice for many detection scenarios, and progress to ML only when the added complexity is justified by improved detection performance.
