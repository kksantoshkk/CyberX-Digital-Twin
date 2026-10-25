
# tests/test_simulator.py

from twin.state import TwinState
from twin.network import TwinNetwork
from twin.controls import TwinControls
from twin.metrics import TwinMetrics
from twin.simulator import TwinSimulator


def main():
    state = TwinState()
    network = TwinNetwork(state)
    controls = TwinControls(state, network)
    metrics = TwinMetrics(state)

    simulator = TwinSimulator(
        state=state,
        network=network,
        controls=controls,
        metrics=metrics,
    )

    # Test 1: Available scenarios.
    scenarios = simulator.get_available_scenarios()
    assert len(scenarios) == 3

    # Test 2: Run SQL injection scenario.
    result = simulator.run_scenario("sqli")

    assert result["scenario_id"] == "sqli"
    assert result["target_asset_id"] == "web-01"
    assert result["outcome"] == "reachable"
    assert result["path"] == ["fw-01", "web-01"]
    assert result["detection_status"] == "not_evaluated"

    # Test 3: Run session anomaly scenario.
    result2 = simulator.run_scenario("session_anomaly")

    assert result2["target_asset_id"] == "auth-01"
    assert result2["outcome"] == "reachable"

    # Test 4: Isolate the web server.
    simulator.isolate_target("web-01")

    # The next scenario cannot reach the web server.
    result3 = simulator.run_scenario("xss")
    assert result3["outcome"] == "blocked"
    assert result3["path"] is None

    # Test 5: Results are stored.
    results = simulator.get_results()
    assert len(results) == 3

    # Test 6: Unknown scenarios must be rejected.
    try:
        simulator.run_scenario("unknown")
        raise AssertionError("Expected ValueError")
    except ValueError as exc:
        assert "Unsupported scenario" in str(exc)

    print("All simulator tests passed!")


if __name__ == "__main__":
    main()
