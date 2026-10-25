
document.addEventListener("DOMContentLoaded", () => {
    const $ = (id) => document.getElementById(id);

    const twinNodes = [...document.querySelectorAll(".twin-node")];

    // Match the labels in the existing UI to simulator scenario IDs.
    const scenarioIds = {
        "SQL injection detection test": "sqli",
        "XSS input classification": "xss",
        "Session anomaly review": "session_anomaly",
        "Normal activity baseline": null
    };

    const api = async (url, options = {}) => {
        const response = await fetch(url, options);
        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || `Request failed: ${response.status}`);
        }

        return data;
    };

    // Mobile sidebar
    $("menu")?.addEventListener("click", () => {
        $("sidebar")?.classList.toggle("open");
    });

    // Load real virtual assets and connections.
    async function loadTwinData() {
        try {
            const [assetData, connectionData] = await Promise.all([
                api("/api/assets"),
                api("/api/connections")
            ]);

            const assets = assetData.assets;
            const connections = connectionData.connections;

            twinNodes.forEach((node) => {
                const id = node.dataset.id.toLowerCase();
                const asset = assets.find(
                    (item) => item.asset_id.toLowerCase() === id
                );

                if (!asset) return;

                node.dataset.name = asset.name;
                node.dataset.type = asset.asset_type;
                node.dataset.criticality =
                    asset.criticality.charAt(0).toUpperCase() +
                    asset.criticality.slice(1);

                const related = connections
                    .filter((connection) =>
                        connection.source.toLowerCase() === id ||
                        connection.target.toLowerCase() === id
                    )
                    .map((connection) =>
                        connection.source.toLowerCase() === id
                            ? connection.target.toUpperCase()
                            : connection.source.toUpperCase()
                    );

                node.dataset.connections = [...new Set(related)].join(", ") || "None";

                const small = node.querySelector("small");
                if (small) {
                    small.textContent = asset.asset_id.toUpperCase();
                }

                let status = node.querySelector(".backend-status");
                if (!status) {
                    status = document.createElement("small");
                    status.className = "backend-status";
                    node.appendChild(status);
                }

                status.textContent =
                    `${asset.status.toUpperCase()}${asset.isolated ? " · ISOLATED" : ""}`;
            });

            // Refresh details for the selected asset.
            const selected = twinNodes.find(
                (node) => node.classList.contains("selected")
            );

            if (selected) showAssetDetails(selected);

            console.info("Digital twin data loaded.", {
                assets: assets.length,
                connections: connections.length
            });
        } catch (error) {
            console.error("Could not load digital twin data:", error);
            if ($("saveHint")) {
                $("saveHint").textContent =
                    "Could not load backend data. Check that Flask is running.";
            }
        }
    }

    function showAssetDetails(node) {
        if ($("assetGlyph")) {
            $("assetGlyph").textContent =
                node.textContent.trim().charAt(0);
        }

        if ($("assetName")) $("assetName").textContent = node.dataset.name;
        if ($("assetId")) $("assetId").textContent = node.dataset.id;
        if ($("assetType")) $("assetType").textContent = node.dataset.type;
        if ($("assetCrit")) {
            $("assetCrit").textContent = node.dataset.criticality;
        }
        if ($("assetConnections")) {
            $("assetConnections").textContent =
                node.dataset.connections || "None";
        }
        if ($("criticality")) {
            $("criticality").value = node.dataset.criticality;
        }
        if ($("isolate")) {
            $("isolate").checked = false;
        }
        if ($("saveHint")) {
            $("saveHint").textContent =
                "Asset details loaded from the backend. Settings changes are not saved yet.";
        }
    }

    twinNodes.forEach((node) => {
        node.addEventListener("click", () => {
            twinNodes.forEach((item) => {
                item.classList.toggle("selected", item === node);
            });
            showAssetDetails(node);
        });
    });

    $("reset")?.addEventListener("click", () => {
        const firstNode = twinNodes[0];
        if (firstNode) firstNode.click();
    });

    // Criticality editing is still local until a backend endpoint is added.
    $("saveAsset")?.addEventListener("click", () => {
        const selected = twinNodes.find(
            (node) => node.classList.contains("selected")
        );

        if (!selected) return;

        if ($("assetCrit")) {
            $("assetCrit").textContent = $("criticality").value;
        }

        if ($("saveHint")) {
            $("saveHint").textContent =
                "Displayed value changed locally only; backend settings remain unchanged.";
        }
    });

    // Scenario cards select a scenario in the configuration panel.
    document.querySelectorAll(".choose").forEach((button) => {
        button.addEventListener("click", () => {
            const select = $("scenarioSelect");
            if (select) select.value = button.dataset.scenario;

            $("runConfig")?.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
        });
    });

    // Execute a real backend simulation.
    $("runScenario")?.addEventListener("click", async () => {
        const output = $("runOutput");
        const select = $("scenarioSelect");

        if (!output || !select) return;

        const scenarioName = select.value;
        const scenarioId = scenarioIds[scenarioName];

        output.classList.remove("hidden");

        if (!scenarioId) {
            output.textContent =
                "This scenario is not implemented in the backend yet. " +
                "Choose SQL injection, XSS, or Session anomaly.";
            return;
        }

        const runButton = $("runScenario");
        runButton.disabled = true;
        runButton.textContent = "Running simulation...";

        output.textContent = "Sending scenario to the digital-twin backend...";

        try {
            const data = await api("/api/simulate", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    scenario_id: scenarioId,
                    source_asset_id: "fw-01"
                })
            });

            const result = data.result;

            output.textContent = [
                "SIMULATION COMPLETED",
                "",
                `Scenario: ${result.scenario_name}`,
                `Outcome: ${result.outcome}`,
                `Source: ${result.source_asset_id}`,
                `Target: ${result.target_asset_id}`,
                `Path: ${
                    result.path?.length
                        ? result.path.join(" → ")
                        : "No reachable path"
                }`,
                `Risk estimate: ${
                    result.risk_estimate?.risk_score ?? "Unavailable"
                }`,
                "",
                result.message,
                "",
                "Note: Reachability is a network-path simulation, not proof of a successful attack or an ML detection."
            ].join("\n");

            // Refresh backend state after the scenario generates events.
            await loadTwinData();
        } catch (error) {
            console.error("Simulation failed:", error);
            output.textContent = `Simulation failed: ${error.message}`;
        } finally {
            runButton.disabled = false;
            runButton.textContent = "▷ Run simulation";
        }
    });

    // Initialize only the page elements that exist.
    loadTwinData();
});
