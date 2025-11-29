// content.js

console.log("WebRace Detector Suite Content Script Active (v2.5).");

// MV2 Promise Wrapper for Storage API (required for async/await usage)
const getStorageLocal = (keys) => new Promise((resolve, reject) => {
    chrome.storage.local.get(keys, (result) => {
        if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
        } else {
            resolve(result);
        }
    });
});

const initiateActiveScan = async (overrideConfig = {}) => {
    // 1. Check Master Switch
    const settings = await getStorageLocal(["masterSwitch", "authScanMode", "scanConcurrency", "scanDelay"]);
    if (settings.masterSwitch === false) { // Explicitly check for false
        console.log("Master switch is disabled. Skipping active scans.");
        return;
    }

    // 2. Determine the Protocol
    let protocol = "unknown";
    try {
        const navigationEntry = performance.getEntriesByType("navigation")[0];
        if (navigationEntry && navigationEntry.nextHopProtocol) {
            protocol = navigationEntry.nextHopProtocol;
        }
    } catch (e) {
        console.error("Could not determine protocol via Performance API:", e);
    }

    const targetUrl = window.location.href;

    // 3. Get Configuration (Authenticated Scan Mode)
    const authScanModeEnabled = settings.authScanMode === true;
    
    // Config Merge
    const scanConcurrency = overrideConfig.concurrency || settings.scanConcurrency || 15;
    const scanDelay = overrideConfig.delay || settings.scanDelay || 0;

    const authModeString = authScanModeEnabled ? 'include' : 'omit';
    console.log(`[Active Scan] Initiating scan for: ${targetUrl} (Protocol: ${protocol}, AuthMode: ${authModeString}, Concurrency: ${scanConcurrency}, Delay: ${scanDelay}ms)`);


    // 3. Initialize Web Worker
    if (typeof Worker === "undefined") {
        console.error("Web Workers are not supported.");
        return;
    }

    try {
        const workerUrl = chrome.runtime.getURL("workers/simulator.js");
        const worker = new Worker(workerUrl);

        worker.onmessage = (event) => {
            const data = event.data;
            if (data.type === "SCAN_COMPLETE") {
                chrome.runtime.sendMessage({
                    type: "ACTIVE_SCAN_RESULT",
                    data: data.payload
                });
            } else if (data.type === "LOG") {
                console.log("[Worker Log]:", data.message);
            }
        };

        worker.onerror = (error) => {
            console.error("[Active Scan] Worker Error:", error.message, error);
            worker.terminate();
        };

        // 4. Start Scans
        const baseConfig = {
            url: targetUrl,
            method: "GET",
            useAuth: authScanModeEnabled,
            delay: scanDelay,
            customBody: overrideConfig.customBody || null
        };

        // A. ToCTOU Scan
        worker.postMessage({
            type: "START_SCAN",
            testType: "TOCTOU",
            config: {
                ...baseConfig,
                concurrency: scanConcurrency,
            }
        });

        // B. HSPA Scan (Only if H2 or H3)
        // HSPA usually requires higher concurrency, so we might want to scale it or respect the user override if explicit.
        // For now, let's use the user setting if it's high, otherwise default to high for HSPA, OR just use user setting.
        // If user set concurrency to 1, HSPA won't work well. But "Fine Grain Control" implies obedience.
        if (protocol.startsWith("h2") || protocol.startsWith("h3")) {
            // If user explicitly set concurrency, use it. Otherwise, if it's the default 15, bump it to 100 for HSPA?
            // To be safe and "fine grain", we obey the user setting.
            // But if the user didn't override (just auto-scan), we might want different defaults.
            // Let's assume the user setting (or default 15) applies to TOCTOU.
            // HSPA needs more.
            // Let's make a decision: If it's a manual scan (overrideConfig present), use it.
            // If it's auto scan, use default logic (15 for TOCTOU, 100 for HSPA).

            let hspaConcurrency = 100;
            if (overrideConfig.concurrency) {
                 hspaConcurrency = overrideConfig.concurrency;
            } else if (settings.scanConcurrency) {
                 hspaConcurrency = settings.scanConcurrency;
            }

            worker.postMessage({
                type: "START_SCAN",
                testType: "HSPA",
                config: {
                    ...baseConfig,
                    concurrency: hspaConcurrency,
                    protocol: protocol
                }
            });
        }

    } catch (error) {
        console.error("Error initializing Web Worker:", error);
    }
};

// Listen for manual scan commands
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "CMD_START_SCAN") {
        console.log("Manual scan command received.", message.config);
        initiateActiveScan(message.config);
        sendResponse({status: "started"});
    }
});

// Auto-start logic
getStorageLocal(["autoStart"]).then(settings => {
    if (settings.autoStart !== false && !window.webRaceScanInitiated) {
        window.webRaceScanInitiated = true;
        initiateActiveScan();
    } else {
        console.log("Auto-scan disabled or already initiated.");
    }
});
