/**
 * Script to run the crash reporting database migration
 * 
 * Usage:
 *   node run-migration.js
 * 
 * Prerequisites:
 *   - PostgreSQL client (psql) installed
 *   - OR Supabase project with connection details
 *   - .env file with SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY
 */

const fs = require('fs');
const path = require('path');
require('dotenv').config();

const migrationPath = path.join(__dirname, 'src', 'crash-reporting', 'migrations', '001_create_crash_reporting_tables.sql');

console.log('🚀 Crash Reporting Database Migration\n');

// Read the migration file
if (!fs.existsSync(migrationPath)) {
  console.error('❌ Migration file not found:', migrationPath);
  process.exit(1);
}

const migrationSQL = fs.readFileSync(migrationPath, 'utf8');

console.log('📄 Migration file loaded:', migrationPath);
console.log('\n' + '='.repeat(80));
console.log('MIGRATION SQL:');
console.log('='.repeat(80));
console.log(migrationSQL);
console.log('='.repeat(80) + '\n');

console.log('📋 To run this migration, you have several options:\n');

console.log('Option 1: Using psql (PostgreSQL command-line tool)');
console.log('--------------------------------------------------');
console.log('psql -U postgres -d quickex -f src/crash-reporting/migrations/001_create_crash_reporting_tables.sql\n');

console.log('Option 2: Using Supabase Dashboard');
console.log('----------------------------------');
console.log('1. Go to your Supabase project dashboard');
console.log('2. Navigate to SQL Editor');
console.log('3. Copy and paste the SQL above');
console.log('4. Click "Run"\n');

console.log('Option 3: Using Supabase CLI');
console.log('---------------------------');
console.log('supabase db push\n');

console.log('Option 4: Using Node.js with @supabase/supabase-js');
console.log('--------------------------------------------------');
console.log('Run: node run-migration-supabase.js\n');

// Check if we have Supabase credentials
if (process.env.SUPABASE_URL && process.env.SUPABASE_SERVICE_ROLE_KEY) {
  console.log('✅ Supabase credentials found in .env');
  console.log('   You can use Option 4 (run-migration-supabase.js)\n');
} else {
  console.log('⚠️  Supabase credentials not found in .env');
  console.log('   Add SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY to use Option 4\n');
}

console.log('💡 Tip: After running the migration, verify with:');
console.log('   SELECT table_name FROM information_schema.tables');
console.log('   WHERE table_schema = \'public\'');
console.log('   AND table_name IN (\'crash_reports\', \'crash_reporting_settings\');\n');
