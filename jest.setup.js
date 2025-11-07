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
