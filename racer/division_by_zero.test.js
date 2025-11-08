
const background = require('./background');

describe('analyzeWafVsDos Division by Zero', () => {
  test('should not crash when a WAF is detected', () => {
    const failedRequests = [];

    const result = background.analyzeWafVsDos(failedRequests);
    expect(result.isWaf).toBe(false);
  });
});
