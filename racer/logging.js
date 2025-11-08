// racer/logging.js

const storage = chrome.storage.local;
const FINDINGS_KEY = "WebRaceFindings";

// MV2 Promise Wrappers for Storage API
const getStorageData = (key) => new Promise((resolve, reject) => {
    storage.get(key, (data) => {
        if (chrome.runtime.lastError) {
            reject(chrome.runtime.lastError);
        } else {
            resolve(data);
        }
    });
});

let storageLock = Promise.resolve();

const setStorageData = (data) => {
    const newLock = new Promise((resolve, reject) => {
        storageLock.finally(() => {
            storage.set(data, () => {
                if (chrome.runtime.lastError) {
                    reject(chrome.runtime.lastError);
                } else {
                    resolve();
                }
            });
        });
    });
    storageLock = newLock;
    return newLock;
};

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

module.exports = { logFinding, getStorageData, FINDINGS_KEY, setStorageData };
