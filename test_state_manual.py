
from twin.state import TwinState

twin = TwinState()

print("=== ASSETS ===")
for asset in twin.get_all_assets():
    print(asset)

print("\n=== UPDATE RISK ===")
twin.set_risk_score("web-01", 75)
print(twin.get_asset("web-01").to_dict())

print("\n=== RECORD EVENT ===")
twin.add_event(
    event_type="test_detection",
    asset_id="web-01",
    severity="high",
    message="Synthetic security test event",
)

print("\n=== ISOLATE VIRTUAL ASSET ===")
twin.set_asset_isolation("web-01", True)
print(twin.get_asset("web-01").to_dict())

print("\n=== RECENT EVENTS ===")
for event in twin.get_recent_events():
    print(event)

assert len(twin.get_all_assets()) == 4
assert twin.get_asset("web-01").risk_score == 75.0
assert twin.get_asset("web-01").isolated is True
assert len(twin.get_recent_events()) == 3

print("\nAll state tests passed!")
