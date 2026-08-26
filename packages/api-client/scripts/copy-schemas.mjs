import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const src = resolve(root, "src/schemas.d.ts");
const dest = resolve(root, "dist/schemas.d.ts");

mkdirSync(dirname(dest), { recursive: true });
copyFileSync(src, dest);

console.log(`Copied schema types -> ${dest}`);
