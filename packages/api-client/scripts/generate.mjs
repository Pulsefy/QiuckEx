import { execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const specPath = resolve(root, "../../app/backend/docs/openapi.yaml");
const outPath = resolve(root, "src/schemas.d.ts");
const binPath = resolve(root, "node_modules/.bin/openapi-typescript");

mkdirSync(dirname(outPath), { recursive: true });

execFileSync(
  process.execPath,
  [binPath, specPath, "--output", outPath],
  { stdio: "inherit" },
);

console.log(`Generated typed client schemas -> ${outPath}`);
