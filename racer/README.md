# WebRace Detector Suite (v2.3.0)

## Overview

The WebRace Detector Suite is an advanced browser extension designed to identify potential security vulnerabilities related to race conditions (ToCTOU) and HTTP/2 & HTTP/3 implementation issues (HSPA).

Version 2.3.0 introduces a **Smart Analysis Engine** that significantly improves the accuracy of findings by differentiating between security mechanism intervention (WAF/Rate Limiting) and genuine server vulnerabilities (DoS/Instability).

## Key Features and Enhancements (v2.3.0)

- **Manifest V3 Architecture, Multi-threading, Session Persistence, and Authenticated Scan Mode.**
- **NEW: Smart Analysis Engine (WAF vs. DoS Detection):**
    *   The suite analyzes failure patterns during high-concurrency tests using a sophisticated heuristic scoring system.
    *   **Data Capture:** Captures response headers, body snippets, and hashes for all requests.
    *   **WAF/Rate Limiting Detection:** Identifies WAF intervention through:
        *   **Fingerprinting:** Analyzing headers (e.g., `CF-Ray`, `Retry-After`) and body keywords.
        *   **Status Codes:** Detecting high rates of 429 (Too Many Requests) or 403 (Forbidden).
        *   **Consistency Analysis:** Determining if failed requests return identical block pages (strong WAF indicator).
        *   **Timing:** Recognizing rapid rejection times typical of edge protection.
    *   **Legitimate DoS/Instability Detection:** Identifies patterns indicative of server crashes, such as high rates of timeouts, connection resets, or varied internal server errors (500, 502, 504).

---

### ⚠️ WARNING: Authenticated Scan Mode

When "Authenticated Scan Mode" is enabled, the extension sends concurrent requests that include your session cookies. If a website incorrectly uses a `GET` request for a state-changing action, this extension **will trigger that action repeatedly**.

**Use this extension responsibly.**

---

## Detection Capabilities

### Advanced ToCTOU Detection
1.  **Inconsistent State Detection (High Severity):** Confirms race conditions by detecting different response bodies for concurrent requests.
2.  **Race Condition Instability (High Severity):** (Improved) Uses the Smart Analysis Engine to confirm if concurrent access causes genuine server instability (DoS).
3.  **WAF Intervention (Info):** (New) Detects if a WAF is preventing the test.

### Heuristic H2/H3SPA Detection
1.  **Resource Exhaustion (High Severity):** (Improved) Uses the Smart Analysis Engine to confirm if multiplexing leads to genuine server resource exhaustion (DoS).
2.  **Timing Variance Analysis (Medium Severity):** Analyzes standard deviation of timings (only run if WAF is not detected).
3.  **WAF Intervention (Info):** (New) Detects if a WAF or Rate Limiter is preventing the test.

## Installation (Temporary Loading)

1.  Create the `webrace-suite` folder and place all files according to the structure above.
2.  **IMPORTANT:** Ensure `icons/icon48.png` exists.
3.  **Chromium (Chrome, Edge, Brave):**
    *   Go to `chrome://extensions/`.
    *   Enable "Developer mode".
    *   Click "Load unpacked" and select the `webrace-suite` folder.
4.  **Firefox:**
    *   Go to `about:debugging`.
    *   Click "This Firefox".
    *   Click "Load Temporary Add-on" and select the `manifest.json` file.
