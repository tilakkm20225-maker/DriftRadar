
import pytest

from app.reliability import evaluate_model


def test_perfect_predictions():
    actual = [1] * 10 + [0] * 10
    predicted = [1] * 10 + [0] * 10

    result = evaluate_model(actual, predicted)

    assert result["precision"] == 1.0
    assert result["recall"] == 1.0
    assert result["f1_score"] == 1.0
    assert result["false_positive_rate"] == 0.0


def test_false_positives_are_counted():
    actual = [1] * 10 + [0] * 10
    predicted = [1] * 10 + [1] * 5 + [0] * 5

    result = evaluate_model(actual, predicted)

    assert result["confusion_matrix"]["false_positives"] == 5
    assert result["false_positive_rate"] == 0.5


def test_false_negatives_are_counted():
    actual = [1] * 10 + [0] * 10
    predicted = [0] * 5 + [1] * 5 + [0] * 10

    result = evaluate_model(actual, predicted)

    assert result["confusion_matrix"]["false_negatives"] == 5
    assert result["recall"] == 0.5


def test_mismatched_lengths():
    with pytest.raises(ValueError):
        evaluate_model([1, 0], [1])


def test_invalid_labels():
    with pytest.raises(ValueError):
        evaluate_model([0, 1] * 10, [0, 2] * 10)


def test_insufficient_samples():
    with pytest.raises(ValueError):
        evaluate_model([1, 0] * 5, [1, 0] * 5)

