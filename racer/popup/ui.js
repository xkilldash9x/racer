// popup/ui.js

document.addEventListener('DOMContentLoaded', () => {
    const findingsContainer = document.getElementById('findings-container');
    const statusDiv = document.getElementById('status');
    const exportBtn = document.getElementById('export-btn');
    const authScanToggle = document.getElementById('auth-scan-toggle');
    const tlsStatusIndicator = document.getElementById('tls-status-indicator');
    const masterToggle = document.getElementById('master-toggle');

    // --- Settings Management (MV2 Compatible - Callbacks) ---

    // Load settings (using chrome.storage.local)
    chrome.storage.local.get(["authScanMode", "masterSwitch"], (settings) => {
        if (chrome.runtime.lastError) {
            console.error("Error loading settings:", chrome.runtime.lastError);
            return;
        }
        // Default master switch to ON if not set
        masterToggle.checked = settings.masterSwitch !== false;
        authScanToggle.checked = settings.authScanMode === true;

        // Disable auth toggle if master is off
        authScanToggle.disabled = !masterToggle.checked;
    });

    // Save master switch state
    masterToggle.addEventListener('change', () => {
        const isEnabled = masterToggle.checked;
        authScanToggle.disabled = !isEnabled;

        if (!isEnabled) {
            const confirmed = confirm(
                "Disabling the master switch will turn off ALL extension features, including passive TLS/Header checks and active scans.\n\n" +
                "The extension will be completely inactive until re-enabled.\n\n" +
                "Are you sure you want to proceed?"
            );
            if (!confirmed) {
                masterToggle.checked = true;
                authScanToggle.disabled = false;
                return;
            }
        }

        chrome.storage.local.set({ masterSwitch: isEnabled }, () => {
            // Notify the background script to re-initialize listeners
            chrome.runtime.sendMessage({ type: "MASTER_SWITCH_CHANGED" });
        });
    });


    // Save auth scan settings when changed
    authScanToggle.addEventListener('change', () => {
        const isEnabled = authScanToggle.checked;
        if (isEnabled) {
            const confirmed = confirm(
                "WARNING: Enabling Authenticated Scans will use your active session/cookies.\n\n" +
                "If the website uses GET requests for state-changing actions (e.g., /delete_account, /logout), this tool WILL trigger them concurrently.\n\n" +
                "Use only on test accounts. Do you wish to proceed?"
            );
            if (!confirmed) {
                authScanToggle.checked = false;
                return;
            }
        }
        chrome.storage.local.set({ authScanMode: authScanToggle.checked });
    });

    // --- Feature Status (TLS Inspection) ---
    
    function updateTlsStatus(isActive) {
        if (isActive) {
            tlsStatusIndicator.textContent = "Active (Firefox/Advanced Permissions)";
            tlsStatusIndicator.className = "active";
        } else {
            tlsStatusIndicator.textContent = "Unavailable (Chromium Limitation)";
            tlsStatusIndicator.className = "inactive";
        }
    }

    // Check feature status on load
    chrome.runtime.sendMessage({ type: "CHECK_FEATURES" }, (response) => {
        // Check lastError in MV2 communication
        if (chrome.runtime.lastError) {
            // Background script might not be ready yet
            return;
        }
        if (response && response.ADVANCED_TLS !== undefined) {
            updateTlsStatus(response.ADVANCED_TLS);
        }
    });

    // Listen for real-time feature updates
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.type === "FEATURE_STATUS" && message.feature === "ADVANCED_TLS") {
            updateTlsStatus(message.status);
        }
    });


    // --- Findings Rendering ---

    exportBtn.addEventListener('click', () => {
        chrome.runtime.sendMessage({ type: "EXPORT_LOGS" });
    });

    const severityOrder = { "High": 1, "Medium": 2, "Low": 3, "Info": 4 };

    function renderFindings(findings) {
        findingsContainer.innerHTML = '';
        if (!findings || findings.length === 0) {
            statusDiv.textContent = 'No vulnerabilities or anomalies detected on this page yet.';
            return;
        }

        statusDiv.textContent = `Found ${findings.length} items for this tab.`;

        // Sort by severity
        findings.sort((a, b) => (severityOrder[a.severity] || 99) - (severityOrder[b.severity] || 99));

        findings.forEach(finding => {
            const div = document.createElement('div');
            div.className = `finding severity-${finding.severity}`;

            const type = document.createElement('div');
            type.className = 'type';
            type.textContent = `[${finding.severity}] ${finding.type}`;

            const message = document.createElement('p');
            message.textContent = finding.message;

            div.appendChild(type);
            div.appendChild(message);

            if (finding.details) {
                const details = document.createElement('p');
                details.className = 'details';
                details.textContent = finding.details;
                div.appendChild(details);
            }
            
            const url = document.createElement('a');
            url.href = finding.url;
            const displayUrl = finding.url.substring(0, 120) + (finding.url.length > 120 ? '...' : '');
            url.textContent = displayUrl;
            url.target = "_blank";
            div.appendChild(url);

            findingsContainer.appendChild(div);
        });
    }

    // Load findings when the popup opens
    function loadFindings() {
        // The background script handles fetching from storage
        chrome.runtime.sendMessage({ type: "GET_FINDINGS" }, (response) => {
            if (chrome.runtime.lastError) {
                statusDiv.textContent = "Error loading findings. Background script might be inactive.";
                console.error(chrome.runtime.lastError.message);
                // Optionally retry
                setTimeout(loadFindings, 1000);
            } else {
                renderFindings(response);
            }
        });
    }
    
    loadFindings();

    // Listen for real-time updates
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.type === "NEW_FINDING") {
            loadFindings();
        }
    });
});
