
from uuid import uuid4

from twin.state import TwinState
from twin.network import TwinNetwork
from twin.controls import TwinControls
from twin.metrics import TwinMetrics


class TwinSimulator:
    """
    Coordinates controlled security scenarios inside the digital twin.

    All scenarios are simulations. No real attacks are sent and no
    real network infrastructure is modified.
    """

    SCENARIOS = {
        "sqli": {
            "name": "SQL Injection",
            "target": "web-01",
            "severity": "high",
            "event_type": "simulation_started",
            "description": "Synthetic SQL injection scenario.",
        },
        "xss": {
            "name": "Cross-Site Scripting",
            "target": "web-01",
            "severity": "medium",
            "event_type": "simulation_started",
            "description": "Synthetic XSS scenario.",
        },
        "session_anomaly": {
            "name": "Session Anomaly",
            "target": "auth-01",
            "severity": "high",
            "event_type": "simulation_started",
            "description": "Synthetic suspicious-session scenario.",
        },
        "baseline": {
            "name": "Normal Activity Baseline",
            "target": "web-01",
            "severity": "info",
            "event_type": "normal_activity",
            "description": "Synthetic benign activity baseline.",
        },
    }

    CONFIGURATIONS = {
        "default": "Default firewall rules",
        "hardened": "Hardened firewall rules",
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
        return [
            {"scenario_id": scenario_id, **scenario}
            for scenario_id, scenario in self.SCENARIOS.items()
        ]

    def get_available_configurations(self) -> list[dict]:
        return [
            {"configuration_id": key, "name": name}
            for key, name in self.CONFIGURATIONS.items()
        ]

    def run_scenario(
        self,
        scenario_id: str,
        source_asset_id: str = "fw-01",
        target_asset_id: str | None = None,
        configuration_id: str = "default",
    ) -> dict:
        """Run one scenario using the selected virtual configuration."""

        if scenario_id not in self.SCENARIOS:
            raise ValueError(f"Unsupported scenario: {scenario_id}")

        if configuration_id not in self.CONFIGURATIONS:
            raise ValueError(
                f"Unsupported configuration: {configuration_id}"
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

        self.state.add_event(
            event_type=scenario["event_type"],
            asset_id=target,
            severity=scenario["severity"],
            message=(
                f"{scenario['name']} scenario started. "
                "Synthetic activity only."
            ),
        )

        path = self.network.find_path(source_asset_id, target)

        # Model a hardened firewall as blocking traffic entering
        # the web server from the firewall node. This is a
        # simulation rule, not a change to a real firewall.
        blocked_by_configuration = (
            configuration_id == "hardened"
            and path is not None
            and len(path) > 1
            and path[0] == "fw-01"
            and path[1] == "web-01"
        )

        if blocked_by_configuration:
            outcome = "blocked"
            displayed_path = None
            message = (
                "The hardened virtual firewall policy blocked "
                "the modeled path to the web server."
            )
        elif path is None:
            outcome = "blocked"
            displayed_path = None
            message = (
                "No reachable path was found in the virtual topology."
            )
        else:
            outcome = "reachable"
            displayed_path = path
            message = (
                "A modeled network path exists. This does not prove "
                "that an attack succeeded or that a vulnerability "
                "was detected."
            )

        risk = self.metrics.calculate_asset_risk(target)

        result = {
            "result_id": result_id,
            "scenario_id": scenario_id,
            "scenario_name": scenario["name"],
            "source_asset_id": source_asset_id,
            "target_asset_id": target,
            "configuration_id": configuration_id,
            "configuration_name": self.CONFIGURATIONS[configuration_id],
            "outcome": outcome,
            "path": displayed_path,
            "risk_estimate": risk,
            "detection_status": "not_evaluated",
            "message": message,
        }

        self.state.add_event(
            event_type="simulation_completed",
            asset_id=target,
            severity="info",
            message=(
                f"{scenario['name']} simulation completed: {outcome}."
            ),
        )

        self.results.append(result)
        return result

    def run_repeated_scenario(
        self,
        scenario_id: str,
        repeat_count: int = 1,
        source_asset_id: str = "fw-01",
        target_asset_id: str | None = None,
        configuration_id: str = "default",
    ) -> dict:
        """Run the selected scenario a specified number of times."""

        if type(repeat_count) is not int or not 1 <= repeat_count <= 10:
            raise ValueError("Repeat count must be an integer from 1 to 10.")

        runs = []

        for _ in range(repeat_count):
            result = self.run_scenario(
                scenario_id=scenario_id,
                source_asset_id=source_asset_id,
                target_asset_id=target_asset_id,
                configuration_id=configuration_id,
            )
            runs.append(result)

        reachable = sum(
            result["outcome"] == "reachable" for result in runs
        )
        blocked = sum(
            result["outcome"] == "blocked" for result in runs
        )

        batch = {
            "batch_id": str(uuid4()),
            "scenario_id": scenario_id,
            "configuration_id": configuration_id,
            "repeat_count": repeat_count,
            "reachable_runs": reachable,
            "blocked_runs": blocked,
            "runs": runs,
        }

        return batch

    def get_results(self, limit: int = 20) -> list[dict]:
        """Return the most recent individual simulation results."""

        if type(limit) is not int or limit < 0:
            raise ValueError("Limit must be a non-negative integer.")

        return list(reversed(self.results[-limit:])) if limit else []

    def isolate_target(self, asset_id: str) -> dict:
        """Apply a virtual isolation action to an asset."""

        return self.controls.isolate_asset(asset_id)
