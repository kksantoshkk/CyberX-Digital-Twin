
from twin.state import TwinState


class TwinMetrics:
    """
    Calculates heuristic asset risk estimates and evaluates
    binary attack-detection performance.
    """

    CRITICALITY_WEIGHT = {
        "low": 10,
        "medium": 25,
        "high": 40,
        "critical": 50,
    }

    SEVERITY_WEIGHT = {
        "info": 0,
        "low": 5,
        "medium": 12,
        "high": 20,
        "critical": 30,
    }

    RELEVANT_RISK_EVENTS = {
        "simulation_started",
        "attack_detected",
        "suspicious_activity",
    }

    def __init__(self, state: TwinState):
        self.state = state

    # --------------------------------------------------
    # ASSET RISK
    # --------------------------------------------------

    def calculate_asset_risk(self, asset_id: str) -> dict:
        """
        Estimate asset risk from criticality, operational status,
        isolation, and the highest relevant recent event severity.

        This is a heuristic score between 0 and 100, not an
        attack probability or a trained ML prediction.
        """

        asset = self.state.get_asset(asset_id)

        if asset is None:
            raise ValueError(f"Unknown asset: {asset_id}")

        # Start with the asset's criticality weight.
        score = self.CRITICALITY_WEIGHT.get(
            asset.criticality.lower(), 25
        )

        # Operational issues increase estimated risk.
        if asset.status == "degraded":
            score += 10
        elif asset.status == "offline":
            score += 15

        # Find the highest relevant event severity.
        # Do not add every event, which can inflate risk
        # when the same scenario is run repeatedly.
        recent_events = self.state.get_recent_events(limit=50)

        relevant_severities = [
            self.SEVERITY_WEIGHT.get(
                event.get("severity", "info").lower(), 0
            )
            for event in recent_events
            if event.get("asset_id") == asset_id
            and event.get("event_type") in self.RELEVANT_RISK_EVENTS
        ]

        if relevant_severities:
            score += max(relevant_severities)

        # Isolation reduces modeled exposure.
        if asset.isolated:
            score *= 0.5

        # Keep the result within the allowed range.
        score = min(100.0, max(0.0, float(score)))

        return {
            "asset_id": asset_id,
            "asset_name": asset.name,
            "risk_score": round(score, 2),
            "risk_level": self._risk_level(score),
            "method": "heuristic",
        }

    def update_asset_risk(self, asset_id: str) -> dict:
        """Calculate and store the current heuristic risk score."""

        result = self.calculate_asset_risk(asset_id)

        # Store the score without creating another risk event.
        # This avoids risk-update events affecting future estimates.
        asset = self.state.get_asset(asset_id)

        if asset is None:
            raise ValueError(f"Unknown asset: {asset_id}")

        asset.risk_score = result["risk_score"]

        return result

    def calculate_all_asset_risks(self) -> list[dict]:
        """Calculate estimated risk for all virtual assets."""

        return [
            self.calculate_asset_risk(asset["asset_id"])
            for asset in self.state.get_all_assets()
        ]

    def get_risk_summary(self) -> dict:
        """Summarize heuristic risk estimates across all assets."""

        risks = self.calculate_all_asset_risks()

        counts = {
            "low": 0,
            "medium": 0,
            "high": 0,
            "critical": 0,
        }

        for result in risks:
            counts[result["risk_level"]] += 1

        average = (
            sum(item["risk_score"] for item in risks) / len(risks)
            if risks
            else 0.0
        )

        return {
            "asset_count": len(risks),
            "average_risk_score": round(average, 2),
            "risk_level_counts": counts,
            "assets": risks,
        }

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 30:
            return "medium"
        return "low"

    # --------------------------------------------------
    # DETECTION PERFORMANCE
    # --------------------------------------------------

    @staticmethod
    def evaluate_detections(
        actual: list[bool],
        predicted: list[bool],
    ) -> dict:
        """
        Evaluate binary attack-detection predictions.

        True means attack; False means normal activity.
        Both lists must contain labeled test results.
        """

        if len(actual) != len(predicted):
            raise ValueError(
                "Actual and predicted lists must have equal lengths."
            )

        if not actual:
            raise ValueError("At least one test case is required.")

        if any(
            type(value) is not bool
            for value in actual + predicted
        ):
            raise ValueError(
                "Actual and predicted values must be booleans."
            )

        tp = sum(
            a and p for a, p in zip(actual, predicted)
        )
        tn = sum(
            not a and not p for a, p in zip(actual, predicted)
        )
        fp = sum(
            not a and p for a, p in zip(actual, predicted)
        )
        fn = sum(
            a and not p for a, p in zip(actual, predicted)
        )

        total = len(actual)

        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        specificity = tn / (tn + fp) if tn + fp else 0.0
        accuracy = (tp + tn) / total

        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall
            else 0.0
        )

        return {
            "total_cases": total,
            "true_positives": tp,
            "true_negatives": tn,
            "false_positives": fp,
            "false_negatives": fn,
            "accuracy": round(accuracy, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "specificity": round(specificity, 4),
            "f1_score": round(f1, 4),
        }
