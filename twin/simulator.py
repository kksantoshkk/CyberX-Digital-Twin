
# twin/simulator.py

from uuid import uuid4

from twin.state import TwinState
from twin.network import TwinNetwork
from twin.controls import TwinControls
from twin.metrics import TwinMetrics


class TwinSimulator:
    """
    Coordinates controlled security scenarios inside the digital twin.

    This module models scenarios; it does not send real attacks,
    execute exploit payloads, or modify real network infrastructure.
    """

    SCENARIOS = {
        "sqli": {
            "name": "SQL Injection",
            "target": "web-01",
            "severity": "high",
            "description": (
                "Synthetic SQL injection attempt against the web server."
            ),
        },
        "xss": {
            "name": "Cross-Site Scripting",
            "target": "web-01",
            "severity": "medium",
            "description": (
                "Synthetic XSS attempt against the web server."
            ),
        },
        "session_anomaly": {
            "name": "Session Anomaly",
            "target": "auth-01",
            "severity": "high",
            "description": (
                "Synthetic suspicious-session scenario."
            ),
        },
    }

    def __init__(
        self,
        state: TwinState,
        network: TwinNetwork,
        controls: TwinControls,
        metrics: TwinMetrics,
    ):
        self.state = state
        self.network = network
        self.controls = controls
        self.metrics = metrics
        self.results = []

    def get_available_scenarios(self) -> list[dict]:
        """Return the scenarios supported by the simulator."""

        return [
            {"scenario_id": key, **value}
            for key, value in self.SCENARIOS.items()
        ]

    def run_scenario(
        self,
        scenario_id: str,
        source_asset_id: str = "fw-01",
        target_asset_id: str | None = None,
    ) -> dict:
        """
        Run a deterministic scenario against the virtual topology.

        Detection is not evaluated here. Actual model predictions
        will be integrated in a later step.
        """

        if scenario_id not in self.SCENARIOS:
            raise ValueError(
                f"Unsupported scenario: {scenario_id}"
            )

        scenario = self.SCENARIOS[scenario_id]
        target = target_asset_id or scenario["target"]

        if source_asset_id not in self.state.assets:
            raise ValueError(
                f"Unknown source asset: {source_asset_id}"
            )

        if target not in self.state.assets:
            raise ValueError(f"Unknown target asset: {target}")

        if source_asset_id == target:
            raise ValueError("Source and target must be different.")

        result_id = str(uuid4())

        # Record the scenario attempt against its target.
        self.state.add_event(
            event_type="simulation_started",
            asset_id=target,
            severity=scenario["severity"],
            message=(
                f"{scenario['name']} simulation started. "
                "Synthetic scenario only."
            ),
        )

        # Check whether the target is reachable in the twin.
        path = self.network.find_path(
            source_asset_id,
            target,
        )

        if path is None:
            outcome = "blocked"
            message = (
                "The target was unreachable in the virtual topology. "
                "No simulated path was found."
            )
        else:
            outcome = "reachable"
            message = (
                "A modeled path to the target exists. "
                "This does not establish that a real vulnerability "
                "was exploited."
            )

        # Estimate risk using the current state and event history.
        risk = self.metrics.calculate_asset_risk(target)

        result = {
            "result_id": result_id,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "source_asset_id": source_asset_id,
            "target_asset_id": target,
            "outcome": outcome,
            "path": path,
            "risk_estimate": risk,
            "detection_status": "not_evaluated",
            "message": message,
        }

        self.state.add_event(
            event_type="simulation_completed",
            asset_id=target,
            severity="info",
            message=(
                f"{scenario['name']} simulation completed: "
                f"{outcome}."
            ),
        )

        self.results.append(result)

        return result

    def get_results(self, limit: int = 20) -> list[dict]:
        """Return the most recent simulation results."""

        if limit < 0:
            raise ValueError("Limit cannot be negative.")

        return list(reversed(self.results[-limit:])) if limit else []

    def isolate_target(self, asset_id: str) -> dict:
        """Apply a virtual defensive action to an asset."""

        return self.controls.isolate_asset(asset_id)
