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
    const strategy = config.strategy || 'standard';
    log(`Starting ${testType} scan. URL: ${config.url}, Concurrency: ${config.concurrency}, Auth: ${credentialsMode}, Strategy: ${strategy}`);

    const startTime = performance.now();
    const requests = [];

    if (strategy === 'last-byte') {
        // --- Low Level / SPA / Last-Byte Sync Strategy ---
        // This requires creating streams, pushing headers/partial body,
        // waiting, and then pushing the last byte.

        if (typeof ReadableStream === 'undefined') {
            log("ERROR: ReadableStream not supported in this environment. Falling back to standard scan.");
            return runScanStandard(testType, config, credentialsMode, startTime);
        }

        const streams = [];
        const controllers = [];

        // Prepare shared barrier promise
        let syncResolve;
        const syncPromise = new Promise(r => syncResolve = r);

        for (let i = 0; i < config.concurrency; i++) {
            const scanUrl = new URL(config.url);
            scanUrl.searchParams.append(`_webrace_probe_${testType}`, `${i}_${Date.now()}`);

            // Create a stream for the request body
            const stream = new ReadableStream({
                start(controller) {
                    controllers.push(controller);
                }
            });

            // Must use POST/PUT for streams
            const fetchOptions = {
                method: 'POST',
                body: stream,
                cache: 'no-store',
                credentials: credentialsMode,
                duplex: 'half' // Required for streaming uploads in Chrome
            };

            const requestStartTime = performance.now();

            // Initiate request but don't close stream yet
            requests.push(
                robustFetch(scanUrl.toString(), fetchOptions).then(async response => {
                    return handleResponse(response, requestStartTime, i);
                }).catch(error => handleError(error, requestStartTime, i))
            );
        }

        // 1. Send initial payload (Padding or Custom Body part 1)
        const encoder = new TextEncoder();
        const payloadStr = config.customBody || "X".repeat(1024); // Default padding if no custom body
        // We will send all but the last byte
        const initialChunk = encoder.encode(payloadStr.slice(0, -1));
        const lastByte = encoder.encode(payloadStr.slice(-1));

        log(`[SPA] Pushing initial chunk to ${controllers.length} streams...`);
        for (const controller of controllers) {
            controller.enqueue(initialChunk);
        }

        // 2. Wait a bit to ensure headers/initial body are sent and connections established
        // This is the "sync" phase. In a real low-level tool we'd wait for ACKs,
        // here we wait for a fixed short delay (e.g., 50ms) to allow network propagation.
        await new Promise(r => setTimeout(r, 100));

        // 3. Send Last Byte simultaneously
        log(`[SPA] releasing LAST BYTE to all streams!`);
        for (const controller of controllers) {
            controller.enqueue(lastByte);
            controller.close();
        }

    } else {
        // --- Standard Concurrent Strategy ---
        return runScanStandard(testType, config, credentialsMode, startTime);
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

const runScanStandard = async (testType, config, credentialsMode, startTime) => {
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
        }

        requests.push(
            robustFetch(scanUrl.toString(), fetchOptions).then(async response => {
                return handleResponse(response, requestStartTime, i);
            }).catch(error => handleError(error, requestStartTime, i))
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

// Refactored Response Handlers
async function handleResponse(response, requestStartTime, i) {
    const requestEndTime = performance.now();
    let hash = null;
    let bodySnippet = null;

    // 1. Capture Headers (Crucial for WAF detection)
    const responseHeaders = extractFingerprintHeaders(response.headers);

    // 2. Capture Body
    const contentType = response.headers.get("content-type");
    const isTextLike = !contentType || contentType.includes("text") || contentType.includes("json") || contentType.includes("xml");

    if (isTextLike) {
        try {
            const body = await response.text();
            hash = simpleHash(body);
            bodySnippet = body.substring(0, 500).toLowerCase();
        } catch (e) {
            // Error reading body
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
}

function handleError(error, requestStartTime, i) {
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
}

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
