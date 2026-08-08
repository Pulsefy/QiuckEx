export default {
  moduleFileExtensions: ["js", "json", "ts"],
  rootDir: ".",
  testRegex: ".*\\.unit\\.spec\\.ts$",
  transform: {
    "^.+\\.(t|j)s$": "ts-jest",
  },
  collectCoverageFrom: ["src/**/*.(t|j)s", "!src/**/*spec.ts"],
  coverageDirectory: "./coverage",
  testEnvironment: "node",
  setupFiles: ["<rootDir>/jest.setup.ts"],
  testTimeout: 10000,
  maxWorkers: "50%",
  coverageThreshold: {
    global: {
      branches: 37,
      functions: 40,
      lines: 44,
      statements: 44,
    },
  },
};
