
# twin/state.py

from dataclasses import dataclass, field
from datetime import datetime, timezone
from uuid import uuid4
from typing import Optional


# --------------------------------------------------
# 1. VIRTUAL ASSET
# --------------------------------------------------

@dataclass
class Asset:
    asset_id: str
    name: str
    asset_type: str
    ip_address: str
    criticality: str

    status: str = "online"
    risk_score: float = 0.0
    isolated: bool = False

    def to_dict(self) -> dict:
        """Convert an asset into a JSON-friendly dictionary."""
        return {
            "asset_id": self.asset_id,
            "name": self.name,
            "asset_type": self.asset_type,
            "ip_address": self.ip_address,
            "criticality": self.criticality,
            "status": self.status,
            "risk_score": self.risk_score,
            "isolated": self.isolated,
        }


# --------------------------------------------------
# 2. SECURITY EVENT
# --------------------------------------------------

@dataclass
class TwinEvent:
    event_type: str
    asset_id: str
    severity: str
    message: str

    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        """Convert an event into a JSON-friendly dictionary."""
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
            "asset_id": self.asset_id,
            "severity": self.severity,
            "message": self.message,
            "timestamp": self.timestamp,
        }


# --------------------------------------------------
# 3. DIGITAL TWIN STATE
# --------------------------------------------------

class TwinState:
    def __init__(self):
        # These are virtual assets, not actual machines.
        self.assets: dict[str, Asset] = {
            "web-01": Asset(
                asset_id="web-01",
                name="Web Server",
                asset_type="web_server",
                ip_address="10.0.0.10",
                criticality="high",
            ),
            "fw-01": Asset(
                asset_id="fw-01",
                name="Firewall",
                asset_type="firewall",
                ip_address="10.0.0.1",
                criticality="critical",
            ),
            "db-01": Asset(
                asset_id="db-01",
                name="Database",
                asset_type="database",
                ip_address="10.0.0.20",
                criticality="critical",
            ),
            "auth-01": Asset(
                asset_id="auth-01",
                name="Authentication Service",
                asset_type="auth_service",
                ip_address="10.0.0.30",
                criticality="high",
            ),
        }

        # Security events recorded during operation.
        self.events: list[TwinEvent] = []

    # --------------------------------------------------
    # ASSET OPERATIONS
    # --------------------------------------------------

    def get_all_assets(self) -> list[dict]:
        """Return all virtual assets."""
        return [
            asset.to_dict()
            for asset in self.assets.values()
        ]

    def get_asset(self, asset_id: str) -> Optional[Asset]:
        """Return one asset, or None if it does not exist."""
        return self.assets.get(asset_id)

    # --------------------------------------------------
    # EVENT OPERATIONS
    # --------------------------------------------------

    def add_event(
        self,
        event_type: str,
        asset_id: str,
        severity: str,
        message: str,
    ) -> dict:
        """Record an event associated with a known asset."""

        if asset_id not in self.assets:
            raise ValueError(f"Unknown asset ID: {asset_id}")

        if not event_type.strip():
            raise ValueError("Event type cannot be empty.")

        if not message.strip():
            raise ValueError("Event message cannot be empty.")

        allowed_severities = {
            "info",
            "low",
            "medium",
            "high",
            "critical",
        }

        if severity not in allowed_severities:
            raise ValueError(
                f"Invalid severity: {severity}"
            )

        event = TwinEvent(
            event_type=event_type,
            asset_id=asset_id,
            severity=severity,
            message=message,
        )

        self.events.append(event)

        return event.to_dict()

    def get_recent_events(self, limit: int = 20) -> list[dict]:
        """Return the newest events first."""

        if limit < 0:
            raise ValueError("Limit cannot be negative.")

        recent = self.events[-limit:] if limit else []

        return [
            event.to_dict()
            for event in reversed(recent)
        ]

    # --------------------------------------------------
    # ASSET STATE OPERATIONS
    # --------------------------------------------------

    def set_asset_status(
        self,
        asset_id: str,
        status: str,
    ) -> dict:
        """Update the status of a virtual asset."""

        asset = self.get_asset(asset_id)

        if asset is None:
            raise ValueError(f"Unknown asset ID: {asset_id}")

        allowed_statuses = {
            "online",
            "degraded",
            "offline",
        }

        if status not in allowed_statuses:
            raise ValueError(
                f"Status must be one of {allowed_statuses}"
            )

        asset.status = status

        self.add_event(
            event_type="asset_status_changed",
            asset_id=asset_id,
            severity="info" if status == "online" else "warning"
            if False else "medium",
            message=f"{asset.name} status changed to {status}.",
        )

        return asset.to_dict()

    def set_asset_isolation(
        self,
        asset_id: str,
        isolated: bool,
    ) -> dict:
        """Change isolation state inside the virtual twin only."""

        asset = self.get_asset(asset_id)

        if asset is None:
            raise ValueError(f"Unknown asset ID: {asset_id}")

        if not isinstance(isolated, bool):
            raise ValueError("Isolation must be True or False.")

        asset.isolated = isolated

        self.add_event(
            event_type="asset_isolation_changed",
            asset_id=asset_id,
            severity="medium" if isolated else "info",
            message=(
                f"{asset.name} isolated in the virtual twin."
                if isolated
                else f"{asset.name} isolation cleared in the virtual twin."
            ),
        )

        return asset.to_dict()

    def set_risk_score(
        self,
        asset_id: str,
        risk_score: float,
    ) -> dict:
        """Set a risk score between 0 and 100."""

        asset = self.get_asset(asset_id)

        if asset is None:
            raise ValueError(f"Unknown asset ID: {asset_id}")

        if isinstance(risk_score, bool) or not isinstance(
            risk_score, (int, float)
        ):
            raise ValueError("Risk score must be numeric.")

        if not 0 <= risk_score <= 100:
            raise ValueError("Risk score must be between 0 and 100.")

        asset.risk_score = float(risk_score)

        severity = (
            "critical" if risk_score >= 80
            else "high" if risk_score >= 60
            else "medium" if risk_score >= 30
            else "low"
        )

        self.add_event(
            event_type="risk_score_updated",
            asset_id=asset_id,
            severity=severity,
            message=f"Risk score updated to {risk_score:.1f}/100.",
        )

        return asset.to_dict()
