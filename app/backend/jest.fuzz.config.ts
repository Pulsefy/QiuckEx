import type { Config } from 'jest';

const config: Config = {
    moduleFileExtensions: ['js', 'json', 'ts'],
    rootDir: '.',
    testRegex: ['.fuzz.spec.ts$'],
    transform: {
        '^.+\\.(t|j)s$': 'ts-jest',
    },
    testEnvironment: 'node',
    // Fuzz tests need long timeouts because they run thousands of iterations
    testTimeout: 120_000,
};

export default config;