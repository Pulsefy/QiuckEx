import fs from 'fs';
import path from 'path';
import { exportRegistry } from '../dist/index.js';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const snapshotPath = path.join(__dirname, '../schemas.snapshot.json');

const currentRegistry = exportRegistry();

if (!fs.existsSync(snapshotPath)) {
  console.log('No snapshot found. Creating initial snapshot...');
  fs.writeFileSync(snapshotPath, JSON.stringify(currentRegistry, null, 2));
  process.exit(0);
}

const previousRegistry = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));

let hasError = false;

for (const [eventName, currentSchema] of Object.entries(currentRegistry)) {
  const prevSchema = previousRegistry[eventName];
  if (!prevSchema) {
    continue; // new event, no breaking changes to check
  }

  const prevVersion = prevSchema.version;
  const currentVersion = currentSchema.version;

  if (currentVersion > prevVersion) {
    continue; // version incremented, breaking changes allowed
  }

  // Check for removed fields
  for (const prevField of Object.keys(prevSchema.properties || {})) {
    if (!currentSchema.properties[prevField]) {
      console.error(`ERROR: Field '${prevField}' removed from event '${eventName}' without incrementing version.`);
      hasError = true;
    }
  }

  // Check for new required fields
  for (const reqField of (currentSchema.required || [])) {
    if (!(prevSchema.required || []).includes(reqField) && !prevSchema.properties[reqField]) {
      console.error(`ERROR: Required field '${reqField}' added to event '${eventName}' without incrementing version.`);
      hasError = true;
    }
  }
}

if (hasError) {
  console.error('\nSchema validation failed! Breaking changes detected without version increment.');
  process.exit(1);
}

// Update snapshot if everything is valid (so it's ready for the next commit)
fs.writeFileSync(snapshotPath, JSON.stringify(currentRegistry, null, 2));
console.log('Schema validation passed. Snapshot updated.');
process.exit(0);
