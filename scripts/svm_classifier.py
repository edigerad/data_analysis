#!/usr/bin/env python3
"""SVM-based classification for network traffic anomaly detection.

Support Vector Machine (SVM) for Security Classification
──────────────────────────────────────────────────────────────────────────────

WHAT IS SVM?

Support Vector Machines find the optimal hyperplane that separates classes
with maximum margin. In 2D, this is a line; in higher dimensions, a hyperplane.
SVMs are particularly effective when:
- Feature space is high-dimensional (many metrics per connection)
- Classes are linearly separable or nearly so
- Training data is limited (SVMs generalize well from small samples)


KEY CONCEPTS

1. MARGIN
   The margin is the distance between the decision boundary and the nearest
   training points (support vectors). SVMs maximize this margin, leading to
   better generalization on unseen data.

2. SUPPORT VECTORS
   The training points closest to the decision boundary. Only these points
   determine the classifier—other points can be removed without changing it.
   This makes SVMs robust to noise far from the boundary.

3. KERNEL TRICK
   When classes aren't linearly separable, kernel functions project data into
   higher dimensions where linear separation is possible. Common kernels:
   - Linear: K(x,y) = x·y (fastest, good for high-dimensional data)
   - RBF: K(x,y) = exp(-γ||x-y||²) (flexible, most common)
   - Polynomial: K(x,y) = (x·y + c)^d


THE ROLE OF HYPERPARAMETER C

The C parameter controls the trade-off between:
- Large margin (smooth decision boundary, may misclassify some training points)
- Correct classification of all training points (may overfit)

C=0.1:  Soft margin, tolerates misclassifications, better generalization
C=1.0:  Balanced (default)
C=10:   Hard margin, fits training data closely, may overfit

In security contexts:
- Low C: Fewer alerts, may miss some attacks (high false negative rate)
- High C: More alerts, catches more attacks but also more false positives

Choose C based on operational tolerance for false positives vs false negatives.


OPERATIONAL TRADE-OFFS

False Positives (FP): Normal traffic flagged as malicious
- Wastes analyst time investigating benign activity
- "Alert fatigue" causes analysts to ignore real threats
- Blocks legitimate users if automated response is enabled

False Negatives (FN): Malicious traffic flagged as normal
- Attacks go undetected
- Dwell time increases (attacker in network longer)
- Breach impact and cost increases

The choice depends on:
- SOC capacity: More analysts → can tolerate higher FP rate
- Asset criticality: Crown jewels → accept FP to minimize FN
- Attack likelihood: High-threat sector → prioritize low FN


Feature Engineering for Network Security
────────────────────────────────────────

Effective features for classification:
- Duration: Short bursts may indicate scanning; long sessions may be normal
- Bytes sent/received: Exfiltration shows high bytes_sent
- Failed flag: Connection failures indicate scanning or misconfig
- NXDOMAIN indicator: High rate suggests DGA malware
- TI match: Binary indicator of threat intelligence match
- Port number: Unusual ports may indicate C2 or tunneling
- Protocol: TCP vs UDP ratios can indicate attack types

Usage:
    from scripts.svm_classifier import SVMClassifier

    classifier = SVMClassifier(kernel="rbf", C=1.0)
    classifier.fit(X_train, y_train)
    predictions = classifier.predict(X_test)
    metrics = classifier.evaluate(X_test, y_test)
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score, GridSearchCV
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_curve,
    auc,
    precision_recall_curve,
)


@dataclass
class ClassificationMetrics:
    """Container for classification performance metrics."""
    accuracy: float
    precision: float
    recall: float
    f1: float
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int

    def to_dict(self) -> dict:
        return {
            "accuracy": self.accuracy,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
        }


class SVMClassifier:
    """SVM classifier for network traffic anomaly detection.

    Wraps scikit-learn's SVC with security-focused preprocessing,
    evaluation, and interpretation.

    Attributes:
        kernel: Kernel type ('linear', 'rbf', 'poly').
        C: Regularization parameter.
        gamma: Kernel coefficient for 'rbf' and 'poly'.
        scaler: StandardScaler for feature normalization.
        model: Fitted SVC model.
        feature_names: Names of features used for training.

    Example:
        >>> classifier = SVMClassifier(kernel="rbf", C=1.0)
        >>> classifier.fit(X_train, y_train, feature_names=["duration", "bytes", "failed"])
        >>> predictions = classifier.predict(X_test)
        >>> print(classifier.evaluate(X_test, y_test))
    """

    def __init__(
        self,
        kernel: str = "rbf",
        C: float = 1.0,
        gamma: str = "scale",
        class_weight: Optional[dict] = None,
        probability: bool = True,
        random_state: int = 42,
    ):
        """Initialize SVM classifier.

        Args:
            kernel: Kernel type. Options:
                    - "linear": Fast, good for high-dimensional sparse data
                    - "rbf": Flexible, good default choice
                    - "poly": Polynomial kernel
            C: Regularization parameter. Controls trade-off between:
               - Small C: Wider margin, more misclassifications allowed
               - Large C: Narrower margin, fits training data more closely
            gamma: Kernel coefficient for 'rbf'/'poly'. "scale" (default) or "auto".
            class_weight: Dict mapping class labels to weights, or "balanced".
                          Use "balanced" for imbalanced datasets.
            probability: If True, enable probability estimates (slower but
                         enables threshold tuning).
            random_state: Random seed for reproducibility.
        """
        self.kernel = kernel
        self.C = C
        self.gamma = gamma
        self.class_weight = class_weight
        self.probability = probability
        self.random_state = random_state

        self.scaler = StandardScaler()
        self.model = SVC(
            kernel=kernel,
            C=C,
            gamma=gamma,
            class_weight=class_weight,
            probability=probability,
            random_state=random_state,
        )
        self.feature_names: List[str] = []
        self._is_fitted = False

    def fit(
        self,
        X: np.ndarray | pd.DataFrame,
        y: np.ndarray | pd.Series,
        feature_names: Optional[List[str]] = None,
    ) -> "SVMClassifier":
        """Fit the classifier on training data.

        Args:
            X: Feature matrix (n_samples, n_features).
            y: Target labels (0=normal, 1=anomaly).
            feature_names: Optional list of feature names for interpretation.

        Returns:
            self (for method chaining)
        """
        # Convert to numpy arrays
        if isinstance(X, pd.DataFrame):
            self.feature_names = list(X.columns)
            X = X.values
        elif feature_names:
            self.feature_names = feature_names
        else:
            self.feature_names = [f"feature_{i}" for i in range(X.shape[1])]

        if isinstance(y, pd.Series):
            y = y.values

        # Handle missing values
        X = np.nan_to_num(X, nan=0.0)

        # Scale features (critical for SVM performance)
        X_scaled = self.scaler.fit_transform(X)

        # Fit model
        self.model.fit(X_scaled, y)
        self._is_fitted = True

        return self

    def predict(self, X: np.ndarray | pd.DataFrame) -> np.ndarray:
        """Predict class labels for samples.

        Args:
            X: Feature matrix.

        Returns:
            Array of predicted labels (0 or 1).
        """
        if not self._is_fitted:
            raise ValueError("Classifier not fitted. Call fit() first.")

        if isinstance(X, pd.DataFrame):
            X = X.values

        X = np.nan_to_num(X, nan=0.0)
        X_scaled = self.scaler.transform(X)

        return self.model.predict(X_scaled)

    def predict_proba(self, X: np.ndarray | pd.DataFrame) -> np.ndarray:
        """Predict class probabilities.

        Args:
            X: Feature matrix.

        Returns:
            Array of shape (n_samples, 2) with probabilities for each class.
        """
        if not self._is_fitted:
            raise ValueError("Classifier not fitted. Call fit() first.")

        if not self.probability:
            raise ValueError("Probability estimation not enabled. Set probability=True.")

        if isinstance(X, pd.DataFrame):
            X = X.values

        X = np.nan_to_num(X, nan=0.0)
        X_scaled = self.scaler.transform(X)

        return self.model.predict_proba(X_scaled)

    def evaluate(
        self,
        X: np.ndarray | pd.DataFrame,
        y: np.ndarray | pd.Series,
    ) -> ClassificationMetrics:
        """Evaluate classifier performance.

        Args:
            X: Test feature matrix.
            y: True labels.

        Returns:
            ClassificationMetrics with precision, recall, F1, etc.
        """
        y_pred = self.predict(X)

        if isinstance(y, pd.Series):
            y = y.values

        cm = confusion_matrix(y, y_pred)

        # Handle edge cases for confusion matrix
        if cm.shape == (1, 1):
            # All same class
            tn = cm[0, 0] if y[0] == 0 else 0
            tp = cm[0, 0] if y[0] == 1 else 0
            fp, fn = 0, 0
        else:
            tn, fp, fn, tp = cm.ravel()

        return ClassificationMetrics(
            accuracy=accuracy_score(y, y_pred),
            precision=precision_score(y, y_pred, zero_division=0),
            recall=recall_score(y, y_pred, zero_division=0),
            f1=f1_score(y, y_pred, zero_division=0),
            true_positives=int(tp),
            false_positives=int(fp),
            true_negatives=int(tn),
            false_negatives=int(fn),
        )

    def cross_validate(
        self,
        X: np.ndarray | pd.DataFrame,
        y: np.ndarray | pd.Series,
        cv: int = 5,
    ) -> dict:
        """Perform cross-validation.

        Args:
            X: Feature matrix.
            y: Target labels.
            cv: Number of folds.

        Returns:
            Dictionary with mean and std for each metric.
        """
        if isinstance(X, pd.DataFrame):
            X = X.values
        if isinstance(y, pd.Series):
            y = y.values

        X = np.nan_to_num(X, nan=0.0)
        X_scaled = self.scaler.fit_transform(X)

        scores = {
            "accuracy": cross_val_score(self.model, X_scaled, y, cv=cv, scoring="accuracy"),
            "precision": cross_val_score(self.model, X_scaled, y, cv=cv, scoring="precision"),
            "recall": cross_val_score(self.model, X_scaled, y, cv=cv, scoring="recall"),
            "f1": cross_val_score(self.model, X_scaled, y, cv=cv, scoring="f1"),
        }

        return {
            metric: {"mean": scores[metric].mean(), "std": scores[metric].std()}
            for metric in scores
        }

    def get_classification_report(
        self,
        X: np.ndarray | pd.DataFrame,
        y: np.ndarray | pd.Series,
    ) -> str:
        """Generate detailed classification report."""
        y_pred = self.predict(X)
        if isinstance(y, pd.Series):
            y = y.values

        return classification_report(
            y, y_pred,
            target_names=["Normal", "Anomaly"],
            digits=4,
        )


def prepare_features(
    conn: pd.DataFrame,
    dns: pd.DataFrame,
) -> Tuple[pd.DataFrame, pd.Series]:
    """Prepare features for SVM classification.

    Extracts security-relevant features from connection and DNS data.

    Args:
        conn: Connection DataFrame with normalized schema.
        dns: DNS DataFrame with normalized schema.

    Returns:
        Tuple of (feature_matrix, labels)
        Labels are 1 if any indicator is present (TI match, high failure rate, etc.)
    """
    # Work with connection data as base
    df = conn.copy()

    # Feature: Duration
    dur_col = "duration_sec" if "duration_sec" in df.columns else "duration"
    df["feat_duration"] = df[dur_col].fillna(0)

    # Feature: Bytes sent
    bytes_sent_col = "bytes_sent" if "bytes_sent" in df.columns else "orig_bytes"
    df["feat_bytes_sent"] = df[bytes_sent_col].fillna(0)

    # Feature: Bytes received
    bytes_recv_col = "bytes_recv" if "bytes_recv" in df.columns else "resp_bytes"
    df["feat_bytes_recv"] = df[bytes_recv_col].fillna(0)

    # Feature: Bytes ratio
    df["feat_bytes_ratio"] = np.where(
        df["feat_bytes_recv"] > 0,
        df["feat_bytes_sent"] / df["feat_bytes_recv"],
        0
    )

    # Feature: Failed connection (binary)
    failed_states = ["S0", "REJ", "RSTO", "RSTR", "S1", "S2", "S3"]
    state_col = "conn_state" if "conn_state" in df.columns else "conn_state"
    df["feat_failed"] = df[state_col].isin(failed_states).astype(int)

    # Feature: TI match (if available)
    if "ti_match" in df.columns:
        df["feat_ti_match"] = df["ti_match"].fillna(False).astype(int)
    else:
        df["feat_ti_match"] = 0

    # Feature: NXDOMAIN indicator (merge from DNS)
    if len(dns) > 0:
        rcode_col = "dns_rcode" if "dns_rcode" in dns.columns else "rcode_name"
        dns_nxdomain = dns.groupby("uid").apply(
            lambda x: (x[rcode_col] == "NXDOMAIN").any()
        ).reset_index(name="has_nxdomain")

        if "uid" in df.columns:
            df = df.merge(dns_nxdomain, on="uid", how="left")
            df["feat_nxdomain"] = df["has_nxdomain"].fillna(False).astype(int)
            df = df.drop(columns=["has_nxdomain"])
        else:
            df["feat_nxdomain"] = 0
    else:
        df["feat_nxdomain"] = 0

    # Extract feature columns
    feature_cols = [
        "feat_duration", "feat_bytes_sent", "feat_bytes_recv",
        "feat_bytes_ratio", "feat_failed", "feat_ti_match", "feat_nxdomain"
    ]

    X = df[feature_cols].copy()

    # Create labels: mark as anomaly if any indicator is present
    # This is a simplified labeling scheme for demonstration
    y = (
        (df["feat_failed"] == 1) |
        (df["feat_ti_match"] == 1) |
        (df["feat_nxdomain"] == 1)
    ).astype(int)

    # Rename features for clarity
    X.columns = ["duration", "bytes_sent", "bytes_recv", "bytes_ratio",
                 "failed", "ti_match", "nxdomain"]

    return X, y


def grid_search_svm(
    X: np.ndarray | pd.DataFrame,
    y: np.ndarray | pd.Series,
    param_grid: Optional[dict] = None,
    cv: int = 5,
) -> Tuple[SVMClassifier, dict]:
    """Find optimal SVM hyperparameters via grid search.

    Args:
        X: Feature matrix.
        y: Target labels.
        param_grid: Dictionary of parameters to search. If None, uses defaults.
        cv: Number of cross-validation folds.

    Returns:
        Tuple of (best_classifier, best_params)
    """
    if isinstance(X, pd.DataFrame):
        X = X.values
    if isinstance(y, pd.Series):
        y = y.values

    X = np.nan_to_num(X, nan=0.0)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    if param_grid is None:
        param_grid = {
            "C": [0.1, 1.0, 10.0],
            "kernel": ["linear", "rbf"],
            "gamma": ["scale", "auto"],
        }

    grid = GridSearchCV(
        SVC(probability=True, random_state=42),
        param_grid,
        cv=cv,
        scoring="f1",
        n_jobs=-1,
    )
    grid.fit(X_scaled, y)

    # Create classifier with best parameters
    best_classifier = SVMClassifier(**grid.best_params_)
    best_classifier.scaler = scaler
    best_classifier.model = grid.best_estimator_
    best_classifier._is_fitted = True

    return best_classifier, grid.best_params_


def generate_classification_report(
    classifier: SVMClassifier,
    X_test: np.ndarray | pd.DataFrame,
    y_test: np.ndarray | pd.Series,
) -> str:
    """Generate comprehensive classification report."""
    metrics = classifier.evaluate(X_test, y_test)

    lines = [
        "SVM CLASSIFICATION REPORT",
        "=" * 60,
        "",
        "MODEL PARAMETERS",
        "-" * 40,
        f"  Kernel:        {classifier.kernel}",
        f"  C (regularization): {classifier.C}",
        f"  Gamma:         {classifier.gamma}",
        "",
        "PERFORMANCE METRICS",
        "-" * 40,
        f"  Accuracy:      {metrics.accuracy:.4f}",
        f"  Precision:     {metrics.precision:.4f}",
        f"  Recall:        {metrics.recall:.4f}",
        f"  F1 Score:      {metrics.f1:.4f}",
        "",
        "CONFUSION MATRIX",
        "-" * 40,
        "                Predicted",
        "              Normal  Anomaly",
        f"  Actual Normal   {metrics.true_negatives:5d}   {metrics.false_positives:5d}",
        f"  Actual Anomaly  {metrics.false_negatives:5d}   {metrics.true_positives:5d}",
        "",
        "OPERATIONAL INTERPRETATION",
        "-" * 40,
        f"  False Positives: {metrics.false_positives}",
        f"    → {metrics.false_positives} normal events flagged for review",
        f"  False Negatives: {metrics.false_negatives}",
        f"    → {metrics.false_negatives} anomalies potentially missed",
        "",
    ]

    # Add precision/recall trade-off guidance
    if metrics.precision < 0.5:
        lines.append("  ⚠ Low precision: High false positive rate, analyst burden high")
    if metrics.recall < 0.5:
        lines.append("  ⚠ Low recall: Missing many anomalies, consider lowering threshold")

    lines.append("")
    lines.append("=" * 60)

    return "\n".join(lines)


if __name__ == "__main__":
    # Demo with sample data
    import sys
    from pathlib import Path

    sys.path.insert(0, str(Path(__file__).parent.parent))

    from scripts.zeek_to_dataframe import load_zeek_log, CONN_SCHEMA, DNS_SCHEMA
    from scripts.normalize import normalize_conn, normalize_dns
    from sklearn.model_selection import train_test_split

    # Load sample data
    zeek_dir = Path("data/zeek_logs/sample")
    conn = normalize_conn(load_zeek_log(zeek_dir / "conn.log", schema=CONN_SCHEMA))
    dns = normalize_dns(load_zeek_log(zeek_dir / "dns.log", schema=DNS_SCHEMA))

    # Prepare features
    X, y = prepare_features(conn, dns)
    print(f"Feature matrix shape: {X.shape}")
    print(f"Label distribution: {y.value_counts().to_dict()}")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y if y.sum() > 0 else None
    )

    # Train classifier
    classifier = SVMClassifier(kernel="rbf", C=1.0, class_weight="balanced")
    classifier.fit(X_train, y_train)

    # Evaluate
    print("\n" + generate_classification_report(classifier, X_test, y_test))

    # Detailed sklearn report
    print("\nDetailed Classification Report:")
    print(classifier.get_classification_report(X_test, y_test))
