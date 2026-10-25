
# tests/test_controls.py

from twin.state import TwinState
from twin.network import TwinNetwork
from twin.controls import TwinControls


def main():
    state = TwinState()
    network = TwinNetwork(state)
    controls = TwinControls(state, network)

    # Test 1: Isolate the Web Server.
    result = controls.isolate_asset("web-01")
    assert result["success"] is True
    assert state.get_asset("web-01").isolated is True

    # The Web Server should no longer be reachable from the Firewall.
    assert network.find_path("fw-01", "web-01") is None

    # Test 2: Restore the Web Server.
    result = controls.restore_asset("web-01")
    assert result["success"] is True
    assert state.get_asset("web-01").isolated is False
    assert network.find_path("fw-01", "web-01") is not None

    # Test 3: Block the Web Server -> Database connection.
    result = controls.block_connection("web-01", "db-01")
    assert result["success"] is True
    assert network.find_path("web-01", "db-01") is None

    # Test 4: Allow the connection again.
    result = controls.allow_connection("web-01", "db-01")
    assert result["success"] is True
    assert network.find_path("web-01", "db-01") is not None

    # Test 5: Change the simulated asset status.
    result = controls.change_asset_status("db-01", "degraded")
    assert result["success"] is True
    assert state.get_asset("db-01").status == "degraded"

    # Test 6: Reject an unknown asset.
    try:
        controls.isolate_asset("unknown-asset")
        raise AssertionError("Expected ValueError was not raised")
    except ValueError:
        pass

    print("All controls tests passed!")


if __name__ == "__main__":
    main()
