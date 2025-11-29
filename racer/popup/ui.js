// popup/ui.js

document.addEventListener('DOMContentLoaded', () => {
    const findingsContainer = document.getElementById('findings-container');
    const statusDiv = document.getElementById('status');
    const exportBtn = document.getElementById('export-btn');
    const authScanToggle = document.getElementById('auth-scan-toggle');
    const tlsStatusIndicator = document.getElementById('tls-status-indicator');
    const masterToggle = document.getElementById('master-toggle');

    // Manual controls
    const autoStartToggle = document.getElementById('auto-start-toggle');
    const concurrencyInput = document.getElementById('concurrency-input');
    const delayInput = document.getElementById('delay-input');
    const customPayloadInput = document.getElementById('custom-payload-input');
    const startScanBtn = document.getElementById('start-scan-btn');

    // Server Mode controls
    const serverModeToggle = document.getElementById('server-mode-toggle');
    const mockControls = document.getElementById('mock-controls');
    const mockUrlInput = document.getElementById('mock-url');
    const mockTypeInput = document.getElementById('mock-type');
    const mockBodyInput = document.getElementById('mock-body');
    const addRuleBtn = document.getElementById('add-rule-btn');
    const rulesList = document.getElementById('rules-list');

    // Traffic Monitor
    const refreshTrafficBtn = document.getElementById('refresh-traffic-btn');
    const trafficList = document.getElementById('traffic-list');

    // --- Settings Management (MV2 Compatible - Callbacks) ---

    // Load settings (using chrome.storage.local)
    chrome.storage.local.get(["authScanMode", "masterSwitch", "autoStart", "scanConcurrency", "scanDelay", "serverMode", "mockRules"], (settings) => {
        if (chrome.runtime.lastError) {
            console.error("Error loading settings:", chrome.runtime.lastError);
            return;
        }
        // Default master switch to ON if not set
        masterToggle.checked = settings.masterSwitch !== false;
        authScanToggle.checked = settings.authScanMode === true;

        // Manual Config Defaults
        autoStartToggle.checked = settings.autoStart !== false; // Default true
        concurrencyInput.value = settings.scanConcurrency || 15;
        delayInput.value = settings.scanDelay || 0;

        // Server Mode
        serverModeToggle.checked = settings.serverMode === true;
        mockControls.style.display = serverModeToggle.checked ? 'block' : 'none';
        renderRules(settings.mockRules || []);

        // Disable auth toggle if master is off
        authScanToggle.disabled = !masterToggle.checked;
    });

    // Save configuration immediately when changed
    function saveConfig() {
        chrome.storage.local.set({
            autoStart: autoStartToggle.checked,
            scanConcurrency: parseInt(concurrencyInput.value, 10) || 15,
            scanDelay: parseInt(delayInput.value, 10) || 0,
            serverMode: serverModeToggle.checked
        });
    }

    autoStartToggle.addEventListener('change', saveConfig);
    concurrencyInput.addEventListener('change', saveConfig);
    delayInput.addEventListener('change', saveConfig);

    serverModeToggle.addEventListener('change', () => {
        saveConfig();
        mockControls.style.display = serverModeToggle.checked ? 'block' : 'none';
        // Notify background
        chrome.runtime.sendMessage({ type: "SERVER_MODE_CHANGED", enabled: serverModeToggle.checked });
    });

    // Mock Rules Management
    function renderRules(rules) {
        rulesList.innerHTML = '';
        if (rules.length === 0) {
            rulesList.innerHTML = '<p style="color: #666; font-style: italic;">No active rules.</p>';
            return;
        }
        rules.forEach((rule, index) => {
            const div = document.createElement('div');
            div.className = 'mock-rule';
            div.style.border = '1px solid #ccc';
            div.style.padding = '5px';
            div.style.marginTop = '5px';
            div.style.borderRadius = '4px';
            div.style.backgroundColor = '#fff';

            // Securely create elements
            const patternDiv = document.createElement('div');
            patternDiv.style.fontWeight = 'bold';
            patternDiv.textContent = rule.urlPattern;

            const typeDiv = document.createElement('div');
            typeDiv.style.fontSize = '11px';
            typeDiv.style.color = '#555';
            typeDiv.textContent = rule.contentType;

            const bodyDiv = document.createElement('div');
            bodyDiv.style.fontSize = '11px';
            bodyDiv.style.color = '#555';
            bodyDiv.style.whiteSpace = 'nowrap';
            bodyDiv.style.overflow = 'hidden';
            bodyDiv.style.textOverflow = 'ellipsis';
            bodyDiv.style.maxWidth = '250px';
            bodyDiv.textContent = rule.body;

            const deleteBtn = document.createElement('button');
            deleteBtn.className = 'delete-rule-btn';
            deleteBtn.setAttribute('data-index', index);
            deleteBtn.style.backgroundColor = '#dc3545';
            deleteBtn.style.marginTop = '5px';
            deleteBtn.style.padding = '5px';
            deleteBtn.textContent = 'Delete';

            div.appendChild(patternDiv);
            div.appendChild(typeDiv);
            div.appendChild(bodyDiv);
            div.appendChild(deleteBtn);

            rulesList.appendChild(div);
        });

        // Add delete listeners
        document.querySelectorAll('.delete-rule-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const index = parseInt(e.target.getAttribute('data-index'));
                deleteRule(index);
            });
        });
    }

    function deleteRule(index) {
        chrome.storage.local.get(["mockRules"], (data) => {
            const rules = data.mockRules || [];
            rules.splice(index, 1);
            chrome.storage.local.set({ mockRules: rules }, () => {
                renderRules(rules);
                chrome.runtime.sendMessage({ type: "MOCK_RULES_UPDATED" });
            });
        });
    }

    addRuleBtn.addEventListener('click', () => {
        const pattern = mockUrlInput.value.trim();
        const type = mockTypeInput.value;
        const body = mockBodyInput.value;

        if (!pattern) {
            alert("URL Pattern is required.");
            return;
        }

        chrome.storage.local.get(["mockRules"], (data) => {
            const rules = data.mockRules || [];
            rules.push({
                urlPattern: pattern,
                contentType: type,
                body: body
            });
            chrome.storage.local.set({ mockRules: rules }, () => {
                renderRules(rules);
                mockUrlInput.value = '';
                mockBodyInput.value = '';
                chrome.runtime.sendMessage({ type: "MOCK_RULES_UPDATED" });
            });
        });
    });

    // Start Scan Handler
    startScanBtn.addEventListener('click', () => {
        saveConfig();
        const customPayload = customPayloadInput.value;
        const config = {
            concurrency: parseInt(concurrencyInput.value, 10) || 15,
            delay: parseInt(delayInput.value, 10) || 0,
            force: true, // Force start even if auto-start is off or scan already ran
            customBody: customPayload.length > 0 ? customPayload : null
        };

        // Send message to active tab to start scan
        chrome.tabs.query({active: true, currentWindow: true}, (tabs) => {
            if (tabs.length > 0) {
                chrome.tabs.sendMessage(tabs[0].id, {
                    type: "CMD_START_SCAN",
                    config: config
                }, (response) => {
                    // check for errors
                    if (chrome.runtime.lastError) {
                        statusDiv.textContent = "Error: Could not contact content script. Refresh the page?";
                    } else {
                        statusDiv.textContent = "Scan command sent...";
                    }
                });
            }
        });
    });

    // Traffic Monitor Logic
    refreshTrafficBtn.addEventListener('click', loadTraffic);

    function loadTraffic() {
        chrome.runtime.sendMessage({ type: "GET_TRAFFIC_LOG" }, (response) => {
            if (chrome.runtime.lastError) {
                trafficList.innerHTML = '<div style="padding:10px; color:red">Error loading traffic.</div>';
                return;
            }
            renderTraffic(response || []);
        });
    }

    function renderTraffic(requests) {
        trafficList.innerHTML = '';
        if (requests.length === 0) {
            trafficList.innerHTML = '<div style="padding:10px; color:#666">No traffic captured yet.</div>';
            return;
        }

        // Reverse to show newest first
        requests.slice().reverse().forEach((req, index) => {
            const div = document.createElement('div');
            div.className = 'traffic-item';

            const methodSpan = document.createElement('span');
            methodSpan.className = 'traffic-method';
            methodSpan.textContent = req.method;

            const urlSpan = document.createElement('span');
            urlSpan.className = 'traffic-url';
            urlSpan.textContent = req.url;
            urlSpan.title = req.url; // Tooltip

            const actionsDiv = document.createElement('div');
            actionsDiv.className = 'traffic-actions';

            const copyBtn = document.createElement('button');
            copyBtn.textContent = 'Copy to Manual';
            copyBtn.onclick = () => {
                // Populate Manual Scan fields
                // Extract relevant parts for "Mock" or "Payload"

                // If it's a GET, maybe we just mock it?
                // If it's a POST, we might want to replay the payload?

                if (req.requestBody) {
                    customPayloadInput.value = req.requestBody;
                } else {
                     customPayloadInput.value = "";
                }

                // Also helpful to set the Mock URL Pattern
                // Convert full URL to a simple pattern (remove query params maybe?)
                try {
                    const urlObj = new URL(req.url);
                    mockUrlInput.value = urlObj.origin + urlObj.pathname + "*";
                } catch (e) {
                    mockUrlInput.value = req.url;
                }

                // Visual feedback
                statusDiv.textContent = "Copied traffic data to Manual/Mock inputs.";
            };

            actionsDiv.appendChild(copyBtn);

            div.appendChild(methodSpan);
            div.appendChild(urlSpan);
            div.appendChild(actionsDiv);

            trafficList.appendChild(div);
        });
    }

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
