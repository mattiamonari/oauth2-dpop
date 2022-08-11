module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testRegex: "/tests/.*\\.(test|spec)\\.(ts|tsx)$",
  moduleNameMapper: {
    "^@/(.*)$": "<rootDir>/src/$1",
  },
};
