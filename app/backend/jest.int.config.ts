import base from "./jest.config";

export default {
  ...base,
  testRegex: ".*\\.int\\.spec\\.ts$",
  coverageThreshold: {
    global: {
      branches: 40,
      functions: 50,
      lines: 50,
      statements: 50,
    },
  },
};
