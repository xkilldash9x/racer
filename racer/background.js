// background.js

console.log("WebRace Detector Suite Background Script Initialized (v2.4.0 - MV2).");

// --- Configuration & Constants ---
const WAF_BODY_SIGNATURES = ['rate limited', 'access denied', 'cloudflare', 'sucuri', 'akamai', 'imperva', 'incapsula', 'security check', 'are you a human', 'bot protection', 'ddos protection', 'forbidden', 'too many requests', 'ray id', 'aws waf', 'wordfence', 'mod_security'];

// Initialize Storage (MV2 Persistence)
// In MV2, chrome.storage.local is used as chrome.storage.session is generally unavailable.
const storage = chrome.storage.local;
const FINDINGS_KEY = "WebRaceFindings";

// --- MV2 Promise Wrappers for Storage API ---
// Allows us to keep using async/await even with MV2 callback APIs.
const getStorageData = (key) => new Promise((resolve, reject) => {
    storage.get(key, (data) => {
        if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
        } else {
            resolve(data);
        }
    });
});

const setStorageData = (data) => new Promise((resolve, reject) => {
    storage.set(data, () => {
        if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
        } else {
            resolve();
        }
    });
});

// Initialize storage structure on startup
getStorageData(FINDINGS_KEY).then(data => {
    if (!data || !data[FINDINGS_KEY]) {
        setStorageData({ [FINDINGS_KEY]: {} });
    }
}).catch(err => console.error("Storage initialization error:", err));


// Centralized Logging Function
const logFinding = async (tabId, finding) => {
  if (tabId < 0) return;

  if (!finding.timestamp) {
      finding.timestamp = new Date().toISOString();
  }

  try {
      const data = await getStorageData(FINDINGS_KEY);
      const findings = (data && data[FINDINGS_KEY]) || {};

      if (!findings[tabId]) {
        findings[tabId] = [];
      }
      
      // Simple deduplication for passive findings
      if (finding.type.startsWith("SECURITY_HEADER_") || finding.type.startsWith("TLS_CONFIGURATION_")) {
        const findingHash = `${finding.type}-${finding.url}`;
        if (findings[tabId].some(f => `${f.type}-${f.url}` === findingHash)) {
            return;
        }
      }

      findings[tabId].push(finding);
      await setStorageData({ [FINDINGS_KEY]: findings });

      console.log(`[Finding Tab ${tabId}]:`, finding);
      // Handle potential error if popup is closed in MV2
      chrome.runtime.sendMessage({ type: "NEW_FINDING" }, () => {
          if (chrome.runtime.lastError) {} 
      });

  } catch (error) {
      console.error("Error logging finding:", error);
  }
};

// 1. Passive Observation: TLS and Security Headers
const responseListener = async (details) => {
  if (details.tabId < 0 || !details.url.startsWith('http') || details.type !== 'main_frame') return { responseHeaders: details.responseHeaders };

  // A. Advanced TLS Inspection (Conditional - Primarily Firefox)
  if (chrome.webRequest.getSecurityInfo) {
      chrome.runtime.sendMessage({ type: "FEATURE_STATUS", feature: "ADVANCED_TLS", status: true }, () => { if (chrome.runtime.lastError) {} });
      try {
          // getSecurityInfo returns a Promise in Firefox
          const securityInfo = await chrome.webRequest.getSecurityInfo(details.requestId, { certificateChain: false });
          
          if (securityInfo.state === "insecure" || securityInfo.state === "broken") {
              logFinding(details.tabId, {
                  type: "TLS_CONFIGURATION_WEAK",
                  severity: "Medium",
                  message: `Insecure connection detected (State: ${securityInfo.state}). May indicate mixed content or certificate errors.`,
                  url: details.url
              });
          } else if (securityInfo.protocol && securityInfo.protocol !== "TLSv1.3" && securityInfo.protocol !== "TLSv1.2") {
               logFinding(details.tabId, {
                  type: "TLS_CONFIGURATION_LEGACY",
                  severity: "Low",
                  message: `Legacy TLS protocol detected (${securityInfo.protocol}). Modern standards require TLS 1.2 or higher.`,
                  url: details.url
              });
          }

      } catch (error) {
          // API might fail or be restricted
      }
  } else {
       chrome.runtime.sendMessage({ type: "FEATURE_STATUS", feature: "ADVANCED_TLS", status: false }, () => { if (chrome.runtime.lastError) {} });
  }

  // B. Security Header Analysis
  if (details.responseHeaders) {
      analyzeSecurityHeaders(details.responseHeaders, details.tabId, details.url);
  }
  
  // In MV2 blocking listeners, returning the headers allows the request to proceed.
  return { responseHeaders: details.responseHeaders };
};

// analyzeSecurityHeaders remains the same
const analyzeSecurityHeaders = (headers, tabId, url) => {
    const headerMap = new Map();
    headers.forEach(header => {
        if (header.name && header.value) {
            headerMap.set(header.name.toLowerCase(), header.value.toLowerCase());
        }
    });

    if (url.startsWith("https://") && !headerMap.has("strict-transport-security")) {
        logFinding(tabId, {
            type: "SECURITY_HEADER_MISSING_HSTS",
            severity: "Medium",
            message: "Missing 'Strict-Transport-Security' header over HTTPS. Site may be vulnerable to SSL stripping.",
            url: url
        });
    }

    const csp = headerMap.get("content-security-policy");
    if (!csp) {
        logFinding(tabId, {
            type: "SECURITY_HEADER_MISSING_CSP",
            severity: "Low",
            message: "Missing 'Content-Security-Policy' header. Increases risk of XSS attacks.",
            url: url
        });
    }

    if (!headerMap.has("x-frame-options") && (!csp || !csp.includes("frame-ancestors"))) {
         logFinding(tabId, {
            type: "SECURITY_HEADER_MISSING_CLICKJACKING",
            severity: "Low",
            message: "Missing 'X-Frame-Options' or CSP 'frame-ancestors'. Site may be vulnerable to Clickjacking.",
            url: url
        });
    }
};


// 2. Communication Handler
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "ACTIVE_SCAN_RESULT") {
        handleActiveScanResult(message.data, sender.tab.id);
        sendResponse({ status: "received" });
    } else if (message.type === "GET_FINDINGS") {
        // Fetch findings from storage
        chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
            if (tabs.length > 0 && tabs[0].id) {
                try {
                    const data = await getStorageData(FINDINGS_KEY);
                    const findings = (data && data[FINDINGS_KEY]) || {};
                    sendResponse(findings[tabs[0].id] || []);
                } catch (error) {
                    console.error("Error fetching findings:", error);
                    sendResponse([]);
                }
            } else {
                sendResponse([]);
            }
        });
        return true; // Required for asynchronous response in MV2
    } else if (message.type === "EXPORT_LOGS") {
        exportLogs();
        return true;
    } else if (message.type === "CHECK_FEATURES") {
        const advancedTlsAvailable = !!chrome.webRequest.getSecurityInfo;
        sendResponse({ ADVANCED_TLS: advancedTlsAvailable });
        return true;
    }
});

// 3. Analysis Logic (Heuristics) - (Logic remains the same as v2.3.0)

const handleActiveScanResult = (data, tabId) => {
    const { testType, result } = data;

    if (testType === "HSPA") {
        analyzeHspaResults(result, tabId);
    } else if (testType === "TOCTOU") {
        analyzeToctouResults(result, tabId);
    }
};

// --- Smart Analysis Engine: WAF vs DoS Differentiation (Logic remains the same) ---

function analyzeWafVsDos(failedRequests) {
    let wafScore = 0;
    let dosIndicators = { timeouts: 0, serverErrors: 0, connectionResets: 0 };
    const totalFailures = failedRequests.length;
    const evidence = new Set();

    if (totalFailures === 0) return { isWaf: false, isDos: false, avgWafScore: 0, evidence: "" };

    // 1. Consistency Check (Hashing)
    const validHashes = failedRequests.map(r => r.hash).filter(h => h !== null);
    const uniqueFailureHashes = new Set(validHashes);
    
    if (validHashes.length > 3 && uniqueFailureHashes.size === 1) {
        wafScore += 4 * totalFailures; 
        evidence.add("Consistent response body (Hash).");
    } else if (uniqueFailureHashes.size > 1 && uniqueFailureHashes.size < totalFailures * 0.3) {
        wafScore += 1 * totalFailures;
        evidence.add("High response body consistency.");
    }

    failedRequests.forEach(req => {
        let localWafScore = 0;

        // 2. Status Code Analysis
        if (req.status === 429) {
            localWafScore += 4;
            evidence.add("Status 429 (Too Many Requests).");
        } else if (req.status === 403 || req.status === 406) {
            localWafScore += 1.5;
            evidence.add(`Status ${req.status}.`);
        } else if (req.status === 503) {
            localWafScore += 0.5; 
        } else if (req.status >= 500) {
            dosIndicators.serverErrors++;
        } else if (req.status === 0) {
            if (req.error === 'Request timed out') {
                dosIndicators.timeouts++;
            } else {
                dosIndicators.connectionResets++;
            }
        }

        // 3. Header Analysis (Fingerprinting)
        if (req.headers) {
            if (req.headers['retry-after']) {
                localWafScore += 4;
                evidence.add("Retry-After header.");
            }
            if (req.headers['cf-ray'] || (req.headers['server'] && req.headers['server'].includes('cloudflare'))) {
                localWafScore += 1;
                evidence.add("Cloudflare indicators.");
            }
            if (req.headers['x-sucuri-id'] || (req.headers['server'] && req.headers['server'].includes('sucuri'))) {
                 localWafScore += 1;
                evidence.add("Sucuri indicators.");
            }
        }

        // 4. Body Analysis (Fingerprinting)
        if (req.bodySnippet) {
            if (WAF_BODY_SIGNATURES.some(sig => req.bodySnippet.includes(sig))) {
                localWafScore += 2.5;
                evidence.add("Body signatures match WAF.");
            }
        }
        
        // 5. Timing Analysis (Behavioral)
        if (req.duration < 250 && localWafScore > 0) {
             localWafScore += 1;
             evidence.add("Rapid rejection time.");
        }

        wafScore += localWafScore;
    });

    const avgWafScore = wafScore / totalFailures;
    const isWaf = avgWafScore > 2.0; 

    const dosIndicatorCount = dosIndicators.timeouts + dosIndicators.serverErrors + dosIndicators.connectionResets;
    const isDos = !isWaf && (dosIndicatorCount / totalFailures > 0.7);

    return { isWaf, isDos, avgWafScore, dosIndicators, evidence: Array.from(evidence).join(' ') };
}


// --- HSPA/ToCTOU Analysis (Logic remains the same) ---

const analyzeHspaResults = (result, tabId) => {
    const { url, protocol, failureCount, totalRequests, authMode, results } = result;
    if (totalRequests === 0) return;

    const detailsPrefix = `[AuthMode: ${authMode}] Protocol: ${protocol}.`;

    // Heuristic 1: High Failure Rate Analysis (WAF vs DoS)
    if (failureCount > totalRequests * 0.2) {
        const failedRequests = results.filter(r => !r.ok);
        const wafAnalysis = analyzeWafVsDos(failedRequests);

        if (wafAnalysis.isWaf) {
            logFinding(tabId, {
                type: "HSPA_WAF_INTERVENTION",
                severity: "Info",
                message: `WAF or Rate Limiting detected during HSPA stress test. The server/firewall actively blocked concurrent requests. This is likely NOT a vulnerability.`,
                url: url,
                details: `${detailsPrefix} Failures: ${failureCount}/${totalRequests}. WAF Score: ${wafAnalysis.avgWafScore.toFixed(2)}. Evidence: ${wafAnalysis.evidence}`
            });
            return; 
        } else if (wafAnalysis.isDos) {
            logFinding(tabId, {
                type: "H2/H3SPA_POTENTIAL_DOS",
                severity: "High",
                message: `High failure rate (${(failureCount/totalRequests*100).toFixed(1)}%) under high concurrency. Server instability indicates vulnerability to resource exhaustion (Genuine DoS). WAF not detected.`,
                url: url,
                details: `${detailsPrefix} Timeouts: ${wafAnalysis.dosIndicators.timeouts}, Server Errors: ${wafAnalysis.dosIndicators.serverErrors}, Resets: ${wafAnalysis.dosIndicators.connectionResets}.`
            });
            return;
        }
    }
    
    // Heuristic 2: Timing Variance Analysis
    const successfulTimings = results.filter(r => r.ok).map(r => r.duration);
    if (successfulTimings.length > 5) {
        const avgDuration = successfulTimings.reduce((a, b) => a + b, 0) / successfulTimings.length;
        const variance = successfulTimings.reduce((a, b) => a + Math.pow(b - avgDuration, 2), 0) / successfulTimings.length;
        const stdDev = Math.sqrt(variance);

        if (stdDev > avgDuration * 0.7 && avgDuration > 50) {
             logFinding(tabId, {
                type: "H2/H3SPA_TIMING_VARIANCE",
                severity: "Medium",
                message: `Significant timing variance detected during concurrent ${protocol} streams. Potential prioritization issue or bottleneck (HSPA indicator).`,
                url: url,
                details: `${detailsPrefix} StdDev: ${stdDev.toFixed(2)}ms, Avg: ${avgDuration.toFixed(2)}ms.`
            });
            return;
        }
    }
};

const analyzeToctouResults = (result, tabId) => {
    const { url, duration, results, authMode } = result;
    if (!results || results.length === 0) return;

    const detailsPrefix = `[AuthMode: ${authMode}] Duration: ${duration.toFixed(2)}ms.`;

    const unauthorizedCount = results.filter(r => r.status === 401 || r.status === 403).length;
    const failedRequests = results.filter(r => !r.ok);
    const failureCount = failedRequests.length;

    // Heuristic 0: WAF/DoS Analysis
    let wafDetected = false;
    if (failureCount > results.length * 0.3) {
        const wafAnalysis = analyzeWafVsDos(failedRequests);
        if (wafAnalysis.isWaf) {
            logFinding(tabId, {
                type: "TOCTOU_WAF_INTERVENTION",
                severity: "Info",
                message: `WAF or Rate Limiting detected during ToCTOU stress test. This may interfere with race condition detection.`,
                url: url,
                details: `${detailsPrefix} Failures: ${failureCount}/${results.length}. WAF Score: ${wafAnalysis.avgWafScore.toFixed(2)}. Evidence: ${wafAnalysis.evidence}`
            });
            wafDetected = true;
        } else if (wafAnalysis.isDos) {
             logFinding(tabId, {
                type: "TOCTOU_POTENTIAL_INSTABILITY_DOS",
                severity: "High",
                message: `Server resource exhaustion (Genuine DoS) likely occurred during concurrent requests. Potential critical locking issues or race conditions causing crashes. WAF not detected.`,
                url: url,
                details: `${detailsPrefix} Timeouts: ${wafAnalysis.dosIndicators.timeouts}, Server Errors: ${wafAnalysis.dosIndicators.serverErrors}, Resets: ${wafAnalysis.dosIndicators.connectionResets}.`
            });
        }
    }

    // Heuristic 1: Authentication Check
    if (authMode === 'omit' && unauthorizedCount > results.length * 0.8) {
        const authFailures = failedRequests.filter(r => r.status === 401 || r.status === 403).length;
        if (!wafDetected || authFailures < failureCount * 0.8) {
             logFinding(tabId, {
                type: "TOCTOU_AUTH_REQUIRED",
                severity: "Info",
                message: `Resource appears to require authentication (401/403 responses). Enable 'Authenticated Scan Mode' in the settings to test the logged-in state.`,
                url: url,
                details: `Unauthorized requests: ${unauthorizedCount}/${results.length}.`
             });
        }
    }

    // Heuristic 2: Inconsistent State (ToCTOU)
    const successfulHashes = new Set(results.filter(r => r.ok).map(r => r.hash).filter(h => h !== null));

    if (successfulHashes.size > 1) {
        logFinding(tabId, {
            type: "TOCTOU_RACE_CONDITION_DETECTED",
            severity: "High",
            message: `Inconsistent resource states detected across concurrent requests. The server returned different content (${successfulHashes.size} variations), indicating a race condition (ToCTOU).`,
            url: url,
            details: `${detailsPrefix} Successful Requests: ${results.length - failureCount}. Sample Hashes: ${Array.from(successfulHashes).slice(0, 3).join(', ')}`
        });
    }

    // Heuristic 3: Server Instability (Medium severity)
    const instabilityErrorCount = failedRequests.filter(r => r.status >= 500).length;
    const dosAlreadyFlagged = failureCount > results.length * 0.3 && analyzeWafVsDos(failedRequests).isDos;

    if (!wafDetected && !dosAlreadyFlagged && instabilityErrorCount > results.length * 0.2) {
         logFinding(tabId, {
            type: "TOCTOU_POTENTIAL_INSTABILITY_MEDIUM",
            severity: "Medium",
            message: `High rate of server errors (5xx) detected during concurrent requests. Potential locking issues. WAF not strongly indicated.`,
            url: url,
            details: `${detailsPrefix} Errors: ${instabilityErrorCount}/${results.length}.`
        });
    }
};


// 4. Utilities and Listeners

const exportLogs = async () => {
    try {
        const data = await getStorageData(FINDINGS_KEY);
        const findings = (data && data[FINDINGS_KEY]) || {};

        const blob = new Blob([JSON.stringify(findings, null, 2)], { type: "application/json" });
        const url = URL.createObjectURL(blob);
        chrome.downloads.download({
            url: url,
            filename: `webrace_suite_report_${Date.now()}.json`
        }, () => {
            if (chrome.runtime.lastError) {
                console.error("Download failed:", chrome.runtime.lastError.message);
            }
            setTimeout(() => URL.revokeObjectURL(url), 10000);
        });
    } catch (error) {
        console.error("Error exporting logs:", error);
    }
};

try {
    if (chrome.webRequest) {
        // MV2 requires 'blocking' to inspect headers reliably.
        chrome.webRequest.onHeadersReceived.addListener(
            responseListener,
            { urls: ["<all_urls>"], types: ["main_frame"] },
            ["responseHeaders", "blocking"]
        );
        console.log("webRequest listeners attached.");
    }
} catch (error) {
    console.error("Failed to attach webRequest listeners:", error);
}

// Clear findings on navigation
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'loading' && tab.url && tab.url.startsWith('http')) {
        try {
            const data = await getStorageData(FINDINGS_KEY);
            const findings = (data && data[FINDINGS_KEY]) || {};
            if (findings[tabId]) {
                delete findings[tabId];
                await setStorageData({ [FINDINGS_KEY]: findings });
            }
        } catch (error) {
            console.error("Error clearing findings on navigation:", error);
        }
    }
});
