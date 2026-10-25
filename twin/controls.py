
# twin/controls.py

from twin.state import TwinState
from twin.network import TwinNetwork


class TwinControls:
    """
    Executes defensive actions against the virtual digital twin.

    These controls do not modify real machines, firewall rules,
    operating systems, or physical network connections.
    """

    def __init__(self, state: TwinState, network: TwinNetwork):
        self.state = state
        self.network = network

    # --------------------------------------------------
    # ASSET ISOLATION
    # --------------------------------------------------

    def isolate_asset(self, asset_id: str) -> dict:
        """Isolate a virtual asset in the digital twin."""

        asset = self.state.get_asset(asset_id)

        if asset is None:
            raise ValueError(f"Unknown asset: {asset_id}")

        if asset.isolated:
            return {
                "success": True,
                "action": "isolate_asset",
                "asset_id": asset_id,
                "message": f"{asset.name} is already isolated.",
            }

        updated_asset = self.state.set_asset_isolation(
            asset_id, True
        )

        return {
            "success": True,
            "action": "isolate_asset",
            "asset_id": asset_id,
            "asset": updated_asset,
            "message": f"{asset.name} isolated in the virtual twin.",
        }

    def restore_asset(self, asset_id: str) -> dict:
        """Remove virtual isolation from an asset."""

        asset = self.state.get_asset(asset_id)

        if asset is None:
            raise ValueError(f"Unknown asset: {asset_id}")

        if not asset.isolated:
            return {
                "success": True,
                "action": "restore_asset",
                "asset_id": asset_id,
                "message": f"{asset.name} is not isolated.",
            }

        updated_asset = self.state.set_asset_isolation(
            asset_id, False
        )

        return {
            "success": True,
            "action": "restore_asset",
            "asset_id": asset_id,
            "asset": updated_asset,
            "message": f"{asset.name} restored in the virtual twin.",
        }

    # --------------------------------------------------
    # CONNECTION CONTROLS
    # --------------------------------------------------

    def block_connection(
        self, source: str, target: str
    ) -> dict:
        """Disable a modeled connection between two assets."""

        self.network.set_connection_enabled(
            source, target, False
        )

        return {
            "success": True,
            "action": "block_connection",
            "source": source,
            "target": target,
            "message": (
                f"Virtual connection {source} -> {target} blocked."
            ),
        }

    def allow_connection(
        self, source: str, target: str
    ) -> dict:
        """Re-enable a modeled connection."""

        self.network.set_connection_enabled(
            source, target, True
        )

        return {
            "success": True,
            "action": "allow_connection",
            "source": source,
            "target": target,
            "message": (
                f"Virtual connection {source} -> {target} enabled."
            ),
        }

    # --------------------------------------------------
    # ASSET STATUS
    # --------------------------------------------------

    def change_asset_status(
        self, asset_id: str, status: str
    ) -> dict:
        """Change an asset's simulated operational status."""

        updated_asset = self.state.set_asset_status(
            asset_id, status
        )

        return {
            "success": True,
            "action": "change_asset_status",
            "asset_id": asset_id,
            "asset": updated_asset,
            "message": (
                f"{updated_asset['name']} status changed to {status}."
            ),
        }
