// Mock the chrome API
global.chrome = {
    storage: {
        local: {
            get: jest.fn(),
            set: jest.fn(),
        },
    },
    runtime: {
        onMessage: {
            addListener: jest.fn(),
        },
        sendMessage: jest.fn(),
    },
    tabs: {
        onUpdated: {
            addListener: jest.fn(),
        },
    },
};

const background = require('./background');
const logging = require('./logging');

jest.mock('./logging', () => ({
    logFinding: jest.fn(),
}));

describe('analyzeWafVsDos', () => {

    // Test case 1: No failed requests
    test('should return no WAF or DoS if there are no failed requests', () => {
        const result = background.analyzeWafVsDos([]);
        expect(result.isWaf).toBe(false);
        expect(result.isDos).toBe(false);
    });

    // Test case 2: Clear WAF signature (status code 429)
    test('should detect a WAF based on a high number of 429 status codes', () => {
        const failedRequests = [
            { status: 429, hash: 'a', duration: 100 },
            { status: 429, hash: 'a', duration: 110 },
            { status: 429, hash: 'a', duration: 90 },
            { status: 429, hash: 'a', duration: 120 },
        ];
        const result = background.analyzeWafVsDos(failedRequests);
        expect(result.isWaf).toBe(true);
        expect(result.isDos).toBe(false);
    });

    // Test case 3: Clear DoS signature (high timeouts)
    test('should detect DoS based on a high number of timeouts', () => {
        const failedRequests = [
            { status: 0, error: 'Request timed out', hash: null, duration: 5000 },
            { status: 0, error: 'Request timed out', hash: null, duration: 5000 },
            { status: 0, error: 'Request timed out', hash: null, duration: 5000 },
            { status: 200, hash: 'b', duration: 200 },
        ];
        const result = background.analyzeWafVsDos(failedRequests);
        expect(result.isWaf).toBe(false);
        expect(result.isDos).toBe(true);
    });

    // Test case 4: Mixed signals, but leans towards WAF (body signatures)
    test('should detect a WAF with mixed signals leaning towards WAF due to body signatures', () => {
        const failedRequests = [
            { status: 403, bodySnippet: 'cloudflare security check', hash: 'b', duration: 150 },
            { status: 403, bodySnippet: 'cloudflare security check', hash: 'b', duration: 160 },
            { status: 500, hash: 'c', duration: 1000 },
            { status: 200, hash: 'd', duration: 200 },
        ];
        const result = background.analyzeWafVsDos(failedRequests);
        expect(result.isWaf).toBe(true);
        expect(result.isDos).toBe(false);
    });

    // Test case 5: High consistency in response bodies (hashes)
    test('should detect a WAF due to high consistency in response body hashes', () => {
        const failedRequests = [
            { status: 403, hash: 'blocked', duration: 80 },
            { status: 403, hash: 'blocked', duration: 85 },
            { status: 403, hash: 'blocked', duration: 90 },
            { status: 403, hash: 'blocked', duration: 75 },
        ];
        const result = background.analyzeWafVsDos(failedRequests);
        expect(result.isWaf).toBe(true);
        expect(result.isDos).toBe(false);
    });

    // Test case 6: Server errors pointing to DoS
    test('should detect DoS from a high rate of 5xx server errors', () => {
        const failedRequests = [
            { status: 502, hash: 'e1', duration: 1200 },
            { status: 503, hash: 'e2', duration: 1500 },
            { status: 500, hash: 'e3', duration: 1100 },
            { status: 504, hash: 'e4', duration: 1300 },
        ];
        const result = background.analyzeWafVsDos(failedRequests);
        expect(result.isWaf).toBe(false);
        expect(result.isDos).toBe(true);
    });

     // Test case 7: WAF with Cloudflare headers
     test('should detect a WAF from Cloudflare headers', () => {
        const failedRequests = [
            { status: 403, headers: { 'cf-ray': '123' }, hash: 'cf', duration: 50 },
            { status: 403, headers: { 'server': 'cloudflare' }, hash: 'cf', duration: 55 },
            { status: 403, headers: { 'cf-ray': '124' }, hash: 'cf' },
        ];
        const result = background.analyzeWafVsDos(failedRequests);
        expect(result.isWaf).toBe(true);
    });
});

describe('analyzeHspaResults', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('should log HSPA_WAF_INTERVENTION when a WAF is detected', () => {
        const result = {
            url: 'http://example.com',
            protocol: 'HTTP/2',
            failureCount: 5,
            totalRequests: 10,
            authMode: 'include',
            results: [
                { ok: false, status: 429, hash: 'a' },
                { ok: false, status: 429, hash: 'a' },
                { ok: false, status: 429, hash: 'a' },
                { ok: false, status: 429, hash: 'a' },
                { ok: false, status: 429, hash: 'a' },
                { ok: true, status: 200, hash: 'b' },
                { ok: true, status: 200, hash: 'b' },
                { ok: true, status: 200, hash: 'b' },
                { ok: true, status: 200, hash: 'b' },
                { ok: true, status: 200, hash: 'b' },
            ],
        };

        background.analyzeHspaResults(result, 1);
        expect(logging.logFinding).toHaveBeenCalledWith(1, expect.objectContaining({
            type: 'HSPA_WAF_INTERVENTION',
        }));
    });

    test('should log H2/H3SPA_POTENTIAL_DOS when DoS is detected', () => {
        const result = {
            url: 'http://example.com',
            protocol: 'HTTP/2',
            failureCount: 8,
            totalRequests: 10,
            authMode: 'include',
            results: [
                { ok: false, status: 0, error: 'Request timed out' },
                { ok: false, status: 0, error: 'Request timed out' },
                { ok: false, status: 0, error: 'Request timed out' },
                { ok: false, status: 0, error: 'Request timed out' },
                { ok: false, status: 0, error: 'Request timed out' },
                { ok: false, status: 0, error: 'Request timed out' },
                { ok: false, status: 0, error: 'Request timed out' },
                { ok: false, status: 0, error: 'Request timed out' },
                { ok: true, status: 200, hash: 'b' },
                { ok: true, status: 200, hash: 'b' },
            ],
        };

        background.analyzeHspaResults(result, 1);
        expect(logging.logFinding).toHaveBeenCalledWith(1, expect.objectContaining({
            type: 'H2/H3SPA_POTENTIAL_DOS',
        }));
    });
});

describe('analyzeToctouResults', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('should log TOCTOU_RACE_CONDITION_DETECTED when multiple hashes are found', () => {
        const result = {
            url: 'http://example.com',
            duration: 1000,
            authMode: 'include',
            results: [
                { ok: true, hash: 'a' },
                { ok: true, hash: 'b' },
                { ok: true, hash: 'a' },
                { ok: true, hash: 'b' },
            ],
        };

        background.analyzeToctouResults(result, 1);
        expect(logging.logFinding).toHaveBeenCalledWith(1, expect.objectContaining({
            type: 'TOCTOU_RACE_CONDITION_DETECTED',
        }));
    });

    test('should log TOCTOU_WAF_INTERVENTION when a WAF is detected', () => {
        const result = {
            url: 'http://example.com',
            duration: 1000,
            authMode: 'include',
            results: [
                { ok: false, status: 429, hash: 'a' },
                { ok: false, status: 429, hash: 'a' },
                { ok: false, status: 429, hash: 'a' },
                { ok: true, status: 200, hash: 'b' },
            ],
        };

        background.analyzeToctouResults(result, 1);
        expect(logging.logFinding).toHaveBeenCalledWith(1, expect.objectContaining({
            type: 'TOCTOU_WAF_INTERVENTION',
        }));
    });
});

describe('analyzeSecurityHeaders', () => {
    beforeEach(() => {
        jest.clearAllMocks();
    });

    test('should log SECURITY_HEADER_MISSING_HSTS when HSTS is missing', () => {
        const headers = [];
        const url = 'https://example.com';
        background.analyzeSecurityHeaders(headers, 1, url);
        expect(logging.logFinding).toHaveBeenCalledWith(1, expect.objectContaining({
            type: 'SECURITY_HEADER_MISSING_HSTS',
        }));
    });

    test('should log SECURITY_HEADER_MISSING_CSP when CSP is missing', () => {
        const headers = [];
        const url = 'http://example.com';
        background.analyzeSecurityHeaders(headers, 1, url);
        expect(logging.logFinding).toHaveBeenCalledWith(1, expect.objectContaining({
            type: 'SECURITY_HEADER_MISSING_CSP',
        }));
    });

    test('should log SECURITY_HEADER_MISSING_CLICKJACKING when clickjacking protection is missing', () => {
        const headers = [];
        const url = 'http://example.com';
        background.analyzeSecurityHeaders(headers, 1, url);
        expect(logging.logFinding).toHaveBeenCalledWith(1, expect.objectContaining({
            type: 'SECURITY_HEADER_MISSING_CLICKJACKING',
        }));
    });
});
