
# twin/network.py

from dataclasses import dataclass
from collections import deque

from twin.state import TwinState


@dataclass
class Connection:
    source: str
    target: str
    protocol: str
    port: int
    enabled: bool = True

    def to_dict(self) -> dict:
        return {
            "source": self.source,
            "target": self.target,
            "protocol": self.protocol,
            "port": self.port,
            "enabled": self.enabled,
        }


class TwinNetwork:
    """
    Manages connections between virtual assets.
    All connections exist only inside the digital twin.
    """

    def __init__(self, state: TwinState):
        self.state = state
        self.connections: list[Connection] = []

        # Initial virtual network topology.
        self.add_connection("fw-01", "web-01", "HTTPS", 443)
        self.add_connection("web-01", "db-01", "TCP", 3306)
        self.add_connection("web-01", "auth-01", "HTTPS", 443)

    def add_connection(
        self,
        source: str,
        target: str,
        protocol: str,
        port: int,
    ) -> dict:
        """Add a connection between two known virtual assets."""

        if source not in self.state.assets:
            raise ValueError(f"Unknown source asset: {source}")

        if target not in self.state.assets:
            raise ValueError(f"Unknown target asset: {target}")

        if source == target:
            raise ValueError("An asset cannot connect to itself.")

        if not protocol or not protocol.strip():
            raise ValueError("Protocol cannot be empty.")

        if isinstance(port, bool) or not isinstance(port, int):
            raise ValueError("Port must be an integer.")

        if not 1 <= port <= 65535:
            raise ValueError("Port must be between 1 and 65535.")

        # Avoid duplicate connections.
        for connection in self.connections:
            if (
                connection.source == source
                and connection.target == target
                and connection.protocol.upper() == protocol.upper()
                and connection.port == port
            ):
                return connection.to_dict()

        connection = Connection(
            source=source,
            target=target,
            protocol=protocol.upper(),
            port=port,
        )

        self.connections.append(connection)
        return connection.to_dict()

    def get_connections(self) -> list[dict]:
        """Return every connection in the virtual network."""

        return [
            connection.to_dict()
            for connection in self.connections
        ]

    def set_connection_enabled(
        self,
        source: str,
        target: str,
        enabled: bool,
    ) -> bool:
        """Enable or disable matching virtual connections."""

        if not isinstance(enabled, bool):
            raise ValueError("enabled must be True or False.")

        found = False

        for connection in self.connections:
            if (
                connection.source == source
                and connection.target == target
            ):
                connection.enabled = enabled
                found = True

        if not found:
            raise ValueError(
                f"No connection found from {source} to {target}."
            )

        self.state.add_event(
            event_type="virtual_connection_changed",
            asset_id=source,
            severity="medium" if not enabled else "info",
            message=(
                f"Virtual connection {source} -> {target} "
                f"{'enabled' if enabled else 'disabled'}."
            ),
        )

        return True

    def get_neighbors(self, asset_id: str) -> list[str]:
        """Return assets directly reachable through enabled connections."""

        if asset_id not in self.state.assets:
            raise ValueError(f"Unknown asset: {asset_id}")

        neighbors = []

        for connection in self.connections:
            if not connection.enabled:
                continue

            if connection.source != asset_id:
                continue

            destination = self.state.get_asset(connection.target)

            if (
                destination is not None
                and not destination.isolated
                and destination.status == "online"
                and not destination.isolated
            ):
                neighbors.append(connection.target)

        return neighbors

    def find_path(
        self,
        source: str,
        target: str,
    ) -> list[str] | None:
        """
        Find a path through enabled virtual connections.

        Returns a list of asset IDs, or None if no path exists.
        Connections are directional.
        """

        if source not in self.state.assets:
            raise ValueError(f"Unknown source asset: {source}")

        if target not in self.state.assets:
            raise ValueError(f"Unknown target asset: {target}")

        if source == target:
            return [source]

        source_asset = self.state.get_asset(source)
        target_asset = self.state.get_asset(target)

        if (
            source_asset.isolated
            or source_asset.status != "online"
            or target_asset.isolated
            or target_asset.status != "online"
        ):
            return None

        queue = deque([[source]])
        visited = {source}

        while queue:
            path = queue.popleft()
            current = path[-1]

            for neighbor in self.get_neighbors(current):
                if neighbor in visited:
                    continue

                new_path = path + [neighbor]

                if neighbor == target:
                    return new_path

                visited.add(neighbor)
                queue.append(new_path)

        return None
