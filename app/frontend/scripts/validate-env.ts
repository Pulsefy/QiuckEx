#!/usr/bin/env node
/**
 * Pre-build environment validation script.
 * Fails the build if required environment variables are missing or invalid.
 */

import { validateEnv } from "../src/lib/env";

console.log("🔍 Validating environment variables...");

const validation = validateEnv();

if (!validation.isValid) {
  console.error("\n❌ Environment validation failed!\n");

  if (validation.missing.length > 0) {
    console.error("Missing required variables:");
    validation.missing.forEach((key) => {
      console.error(`  - ${key}`);
    });
    console.error("");
  }

  if (validation.invalid.length > 0) {
    console.error("Invalid variables:");
    validation.invalid.forEach(({ key, reason }) => {
      console.error(`  - ${key}: ${reason}`);
    });
    console.error("");
  }

  console.error(
    "Please set the required environment variables and try again.\n"
  );
  process.exit(1);
}

console.log("✅ Environment validation passed!\n");
process.exit(0);
