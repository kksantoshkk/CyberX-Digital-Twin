
# twin/metrics.py

from twin.state import TwinState


class TwinMetrics:
    """
    Calculates asset risk estimates and evaluates detection performance.

    Asset risk is a heuristic estimate, not a calibrated prediction.
    Detection metrics require labeled test cases and model predictions.
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

    def __init__(self, state: TwinState):
        self.state = state

    # --------------------------------------------------
    # ASSET RISK
    # --------------------------------------------------

    def calculate_asset_risk(self, asset_id: str) -> dict:
        """
        Estimate an asset's risk using criticality, operational
        status, isolation, and recent security events.

        The result is a heuristic score between 0 and 100.
        """

        asset = self.state.get_asset(asset_id)

        if asset is None:
            raise ValueError(f"Unknown asset: {asset_id}")

        score = self.CRITICALITY_WEIGHT.get(
            asset.criticality.lower(), 25
        )

        # Operational issues increase estimated risk.
        if asset.status == "degraded":
            score += 10
        elif asset.status == "offline":
            score += 15

        # Recent events contribute to risk.
        recent_events = self.state.get_recent_events(limit=50)

        for event in recent_events:
            if event["asset_id"] != asset_id:
                continue

            score += self.SEVERITY_WEIGHT.get(
                event["severity"].lower(), 0
            )

        # Isolation reduces the modeled exposure estimate.
        if asset.isolated:
            score *= 0.5

        score = min(100.0, max(0.0, float(score)))

        return {
            "asset_id": asset_id,
            "asset_name": asset.name,
            "risk_score": round(score, 2),
            "risk_level": self._risk_level(score),
            "method": "heuristic",
        }

    def update_asset_risk(self, asset_id: str) -> dict:
        """Calculate risk and store it on the virtual asset."""

        result = self.calculate_asset_risk(asset_id)

        self.state.set_risk_score(
            asset_id,
            result["risk_score"],
        )

        return result

    def calculate_all_asset_risks(self) -> list[dict]:
        """Calculate estimated risk for every virtual asset."""

        return [
            self.calculate_asset_risk(asset["asset_id"])
            for asset in self.state.get_all_assets()
        ]

    def get_risk_summary(self) -> dict:
        """Summarize current heuristic risk estimates."""

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
            if risks else 0.0
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
        Evaluate binary attack detection predictions.

        True means attack; False means normal traffic.
        Both lists must contain labeled test results.
        """

        if len(actual) != len(predicted):
            raise ValueError(
                "Actual and predicted lists must have equal lengths."
            )

        if not actual:
            raise ValueError("At least one test case is required.")

        if any(type(value) is not bool for value in actual + predicted):
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
            if precision + recall else 0.0
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
