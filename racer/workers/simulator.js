// workers/simulator.js

self.onmessage = (event) => {
    const data = event.data;
    if (data.type === "START_SCAN") {
        if (data.config.method !== "GET") {
            log(`WARN: Non-GET method (${data.config.method}) requested. Proceeding, but ensure safety.`);
        }
        runScan(data.testType, data.config);
    }
};

const log = (message) => {
    self.postMessage({ type: "LOG", message });
};

// Robust Fetch wrapper
async function robustFetch(url, options, timeout = 10000) {
    const controller = new AbortController();
    const id = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        clearTimeout(id);
        return response;
    } catch (error) {
        clearTimeout(id);
        if (error.name === 'AbortError') {
            throw new Error('Request timed out');
        }
        throw error;
    }
}

// Hashing function (djb2)
function simpleHash(str) {
    if (!str) return null;
    let hash = 5381;
    const limitedStr = str.substring(0, 50000);
    for (let i = 0; i < limitedStr.length; i++) {
        hash = (hash * 33) ^ limitedStr.charCodeAt(i);
    }
    return (hash >>> 0).toString(16);
}

// Helper to extract relevant headers for fingerprinting
function extractFingerprintHeaders(headers) {
    const fingerprintHeaders = {};
    // Keys commonly associated with WAFs, CDNs, and Rate Limiters
    const relevantKeys = ['server', 'x-powered-by', 'x-ratelimit-limit', 'retry-after', 'cf-ray', 'x-amz-cf-id', 'x-sucuri-id', 'x-waf-event', 'akamai-request-id'];
    
    headers.forEach((value, key) => {
        const lowerKey = key.toLowerCase();
        if (relevantKeys.includes(lowerKey)) {
            // Store in lowercase for easier comparison
            fingerprintHeaders[lowerKey] = value.toLowerCase();
        }
    });
    return fingerprintHeaders;
}


const runScan = async (testType, config) => {
    const credentialsMode = config.useAuth ? 'include' : 'omit';
    log(`Starting ${testType} scan. URL: ${config.url}, Concurrency: ${config.concurrency}, Auth: ${credentialsMode}`);

    const startTime = performance.now();
    const requests = [];

    const delay = config.delay || 0;

    for (let i = 0; i < config.concurrency; i++) {
        if (delay > 0 && i > 0) {
            await new Promise(resolve => setTimeout(resolve, delay));
        }

        // Cache busting
        const scanUrl = new URL(config.url);
        scanUrl.searchParams.append(`_webrace_probe_${testType}`, `${i}_${Date.now()}`);

        const requestStartTime = performance.now();

        // Handle Custom Body (Payload Replay)
        let fetchOptions = {
            method: config.method,
            cache: 'no-store',
            credentials: credentialsMode
        };

        if (config.customBody) {
            fetchOptions.method = 'POST'; // Default to POST if body is present
            fetchOptions.body = config.customBody;
            // Add JSON content type if it looks like JSON?
            // For now, let's keep it simple or allow headers injection later.
            // If the user wants to replay a GET with body (non-standard but possible), we might need more config.
            // But usually payload = POST.
        }

        requests.push(
            robustFetch(scanUrl.toString(), fetchOptions).then(async response => {
                const requestEndTime = performance.now();
                let hash = null;
                let bodySnippet = null;

                // 1. Capture Headers (Crucial for WAF detection)
                const responseHeaders = extractFingerprintHeaders(response.headers);

                // 2. Capture Body (For ToCTOU consistency AND WAF analysis)
                // Attempt to read the body regardless of the status code, if it seems like text.
                const contentType = response.headers.get("content-type");
                const isTextLike = !contentType || contentType.includes("text") || contentType.includes("json") || contentType.includes("xml");

                if (isTextLike) {
                    try {
                        const body = await response.text();
                        // Hash the body (used for consistency analysis)
                        hash = simpleHash(body);
                        // Capture snippet for keyword analysis (first 500 chars, lowercase)
                        bodySnippet = body.substring(0, 500).toLowerCase();
                    } catch (e) {
                        // Error reading body (e.g., connection closed during stream)
                    }
                }

                return {
                    status: response.status,
                    ok: response.ok,
                    duration: requestEndTime - requestStartTime, 
                    hash: hash,
                    bodySnippet: bodySnippet,
                    headers: responseHeaders,
                    error: null,
                    index: i
                };
            }).catch(error => {
                // Handles network errors, timeouts (status 0), connection resets
                const requestEndTime = performance.now();
                return {
                    status: 0,
                    ok: false,
                    error: error.message,
                    duration: requestEndTime - requestStartTime,
                    hash: null,
                    bodySnippet: null,
                    headers: {},
                    index: i
                };
            })
        );
    }

    // Wait for all concurrent requests
    const results = await Promise.all(requests);
    const totalDuration = performance.now() - startTime;

    const payload = processResults(testType, config, results, totalDuration, credentialsMode);

    self.postMessage({
        type: "SCAN_COMPLETE",
        payload: {
            testType: testType,
            result: payload
        }
    });
};

const processResults = (testType, config, results, duration, authMode) => {
    const successCount = results.filter(r => r.ok).length;
    const failureCount = results.length - successCount;
    // Use all timings initially; background script filters successful ones if needed.
    const timings = results.map(r => r.duration);

    const baseResult = {
        url: config.url,
        duration: duration,
        authMode: authMode,
        results: results // CRUCIAL: Include detailed results for background analysis
    };

    if (testType === "HSPA") {
        return {
            ...baseResult,
            protocol: config.protocol,
            successCount: successCount,
            failureCount: failureCount,
            totalRequests: results.length,
            timings: timings
        };
    } else if (testType === "TOCTOU") {
        return {
            ...baseResult
        };
    }
};
