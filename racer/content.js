// content.js

console.log("WebRace Detector Suite Content Script Active.");

// MV2 Promise Wrapper for Storage API (required for async/await usage)
const getStorageLocal = (key) => new Promise((resolve, reject) => {
    chrome.storage.local.get(key, (result) => {
        if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
        } else {
            resolve(result);
        }
    });
});

const initiateActiveScan = async () => {
    // 1. Determine the Protocol
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

    // 2. Get Configuration (Authenticated Scan Mode)
    let authScanModeEnabled = false;
    try {
        // Use the wrapper function
        const settings = await getStorageLocal("authScanMode");
        authScanModeEnabled = settings.authScanMode === true;
    } catch (error) {
        console.error("Error retrieving settings:", error);
    }
    
    const authModeString = authScanModeEnabled ? 'include' : 'omit';
    console.log(`[Active Scan] Initiating scan for: ${targetUrl} (Protocol: ${protocol}, AuthMode: ${authModeString})`);


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
            useAuth: authScanModeEnabled
        };

        // A. ToCTOU Scan
        worker.postMessage({
            type: "START_SCAN",
            testType: "TOCTOU",
            config: {
                ...baseConfig,
                concurrency: 15,
            }
        });

        // B. HSPA Scan (Only if H2 or H3)
        if (protocol.startsWith("h2") || protocol.startsWith("h3")) {
            worker.postMessage({
                type: "START_SCAN",
                testType: "HSPA",
                config: {
                    ...baseConfig,
                    concurrency: 100,
                    protocol: protocol
                }
            });
        }

    } catch (error) {
        console.error("Error initializing Web Worker:", error);
    }
};

// Ensure the scan runs only once per page load
if (!window.webRaceScanInitiated) {
    window.webRaceScanInitiated = true;
    initiateActiveScan();
}
