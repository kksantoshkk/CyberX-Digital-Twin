
from twin.state import TwinState
from twin.network import TwinNetwork


def main():
    state = TwinState()
    network = TwinNetwork(state)

    # Verify initial topology.
    connections = network.get_connections()
    assert len(connections) == 3

    # Verify direct reachability.
    assert "web-01" in network.get_neighbors("fw-01")
    assert "db-01" in network.get_neighbors("web-01")

    # Verify path discovery.
    path = network.find_path("fw-01", "db-01")
    assert path == ["fw-01", "web-01", "db-01"]

    # Disable the web server -> database connection.
    network.set_connection_enabled(
        "web-01", "db-01", False
    )

    # The database should no longer be reachable by this path.
    assert network.find_path("fw-01", "db-01") is None

    # Restore the connection.
    network.set_connection_enabled(
        "web-01", "db-01", True
    )
    assert network.find_path("fw-01", "db-01") is not None

    # Verify isolation affects reachability.
    state.set_asset_isolation("web-01", True)
    assert network.find_path("fw-01", "db-01") is None

    print("All network tests passed!")


if __name__ == "__main__":
    main()
