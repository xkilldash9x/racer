
const background = require('./background');
const { analyzeWafVsDos, analyzeHspaResults, analyzeToctouResults, WAF_BODY_SIGNATURES } = background;

describe('Background Script - Configuration and Control', () => {

    test('WAF signatures are defined', () => {
        expect(WAF_BODY_SIGNATURES).toBeDefined();
        expect(WAF_BODY_SIGNATURES.length).toBeGreaterThan(0);
    });

    test('analyzeWafVsDos handles zero failures correctly', () => {
        const result = analyzeWafVsDos([]);
        expect(result.isWaf).toBe(false);
        expect(result.isDos).toBe(false);
        expect(result.avgWafScore).toBe(0);
    });

    // We can add more specific unit tests for the logic that resides in background.js
    // Note: Integration tests involving chrome.runtime.onMessage would require more extensive mocking of the chrome API,
    // which is partially done in jest.setup.js but might need specific handlers for the new messages.
});
