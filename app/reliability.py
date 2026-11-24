
import numpy as np


def evaluate_model(y_true, y_pred):
    """
    Evaluate binary cybersecurity classification predictions.

    1 = Threat
    0 = Benign
    """

    actual = np.asarray(y_true)
    predicted = np.asarray(y_pred)

    if actual.ndim != 1 or predicted.ndim != 1:
        raise ValueError("Labels must be one-dimensional.")

    if len(actual) != len(predicted):
        raise ValueError("Actual and predicted labels must have equal lengths.")

    if len(actual) < 20:
        raise ValueError("At least 20 labelled events are required.")

    if not np.isin(actual, [0, 1]).all():
        raise ValueError("Actual labels must contain only 0 or 1.")

    if not np.isin(predicted, [0, 1]).all():
        raise ValueError("Predicted labels must contain only 0 or 1.")

    actual = actual.astype(int)
    predicted = predicted.astype(int)

    tp = int(np.sum((actual == 1) & (predicted == 1)))
    tn = int(np.sum((actual == 0) & (predicted == 0)))
    fp = int(np.sum((actual == 0) & (predicted == 1)))
    fn = int(np.sum((actual == 1) & (predicted == 0)))

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    f1 = (
        2 * precision * recall / (precision + recall)
        if precision + recall else 0.0
    )

    fpr = fp / (fp + tn) if fp + tn else 0.0
    accuracy = (tp + tn) / len(actual)

    return {
        "sample_count": len(actual),
        "confusion_matrix": {
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn
        },
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1_score": round(f1, 4),
        "false_positive_rate": round(fpr, 4),
        "accuracy": round(accuracy, 4)
    }
