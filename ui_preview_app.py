from flask import Flask, render_template
from flask import jsonify, request

from twin.state import TwinState
from twin.network import TwinNetwork
from twin.controls import TwinControls
from twin.metrics import TwinMetrics
from twin.simulator import TwinSimulator
app = Flask(__name__, template_folder="web/templates", static_folder="web/static", static_url_path="/static")
# Initialize the digital twin once when Flask starts
twin_state = TwinState()
twin_network = TwinNetwork(twin_state)
twin_controls = TwinControls(twin_state, twin_network)
twin_metrics = TwinMetrics(twin_state)

twin_simulator = TwinSimulator(
    twin_state,
    twin_network,
    twin_controls,
    twin_metrics
)
@app.get("/")
def dashboard(): return render_template("dashboard.html", active_page="dashboard")
@app.get("/twin")
def twin(): return render_template("twin.html", active_page="twin")
@app.get("/scenarios")
def scenarios(): return render_template("scenarios.html", active_page="scenarios")
@app.get("/results")
def results(): return render_template("results.html", active_page="results")


# ---------------- DIGITAL TWIN API ----------------

# ================= DIGITAL TWIN API =================

@app.route("/api/health", methods=["GET"])
def api_health():
    return jsonify({
        "status": "online",
        "service": "CyberX Digital Twin",
        "mode": "simulation"
    })



@app.route("/api/assets", methods=["GET"])
def api_assets():
    assets = twin_state.get_all_assets()

    return jsonify({
        "success": True,
        "count": len(assets),
        "assets": assets
    })


@app.route("/api/connections", methods=["GET"])
def api_connections():
    connections = twin_network.get_connections()

    return jsonify({
        "success": True,
        "count": len(connections),
        "connections": connections
    })


@app.route("/api/events", methods=["GET"])
def api_events():
    limit = request.args.get("limit", default=20, type=int)
    limit = max(1, min(limit, 100))

    events = twin_state.get_recent_events(limit)

    return jsonify({
        "success": True,
        "events": [event.to_dict() for event in events]
    })


@app.route("/api/scenarios", methods=["GET"])
def api_scenarios():
    return jsonify({
        "success": True,
        "scenarios": twin_simulator.get_available_scenarios()
    })


@app.route("/api/risks", methods=["GET"])
def api_risks():
    risks = twin_metrics.calculate_all_asset_risks()

    return jsonify({
        "success": True,
        "risks": risks,
        "summary": twin_metrics.get_risk_summary()
    })


@app.route("/api/simulate", methods=["POST"])
def api_simulate():
    data = request.get_json(silent=True) or {}

    if not data.get("scenario_id"):
        return jsonify({
            "success": False,
            "error": "scenario_id is required"
        }), 400

    try:
        result = twin_simulator.run_scenario(
            scenario_id=data["scenario_id"],
            source_asset_id=data.get(
                "source_asset_id", "fw-01"
            ),
            target_asset_id=data.get("target_asset_id")
        )

        return jsonify({
            "success": True,
            "result": result
        })

    except ValueError as error:
        return jsonify({
            "success": False,
            "error": str(error)
        }), 400

    except Exception:
        app.logger.exception("Simulation failed")
        return jsonify({
            "success": False,
            "error": "Internal simulation error"
        }), 500

if __name__ == "__main__": app.run(debug=True, port=8080)