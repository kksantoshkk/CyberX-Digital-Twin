
# tests/test_metrics.py

from twin.state import TwinState
from twin.metrics import TwinMetrics


def main():
    state = TwinState()
    metrics = TwinMetrics(state)

    # Test 1: Calculate the risk of the critical database.
    result = metrics.calculate_asset_risk("db-01")

    assert result["asset_id"] == "db-01"
    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in {
        "low", "medium", "high", "critical"
    }

    print("Database risk:", result)

    # Test 2: Record a synthetic high-severity event.
    state.add_event(
        event_type="attack_detected",
        asset_id="web-01",
        severity="high",
        message="Synthetic test event",
    )

    risk_after_event = metrics.calculate_asset_risk("web-01")
    assert risk_after_event["risk_score"] > 40

    # Test 3: Update the stored asset risk score.
    updated = metrics.update_asset_risk("web-01")
    assert (
        state.get_asset("web-01").risk_score
        == updated["risk_score"]
    )

    # Test 4: Summarize risk across all assets.
    summary = metrics.get_risk_summary()
    assert summary["asset_count"] == 4
    assert len(summary["assets"]) == 4

    # Test 5: Evaluate synthetic attack-detection predictions.
    actual = [True, True, False, False, True, False]
    predicted = [True, False, False, True, True, False]

    evaluation = metrics.evaluate_detections(actual, predicted)

    assert evaluation["true_positives"] == 2
    assert evaluation["true_negatives"] == 2
    assert evaluation["false_positives"] == 1
    assert evaluation["false_negatives"] == 1
    assert evaluation["accuracy"] == 0.6667
    assert evaluation["precision"] == 0.6667
    assert evaluation["recall"] == 0.6667
    assert evaluation["f1_score"] == 0.6667

    print("Risk summary:", summary)
    print("Detection evaluation:", evaluation)

    print("\nAll metrics tests passed!")


if __name__ == "__main__":
    main()
