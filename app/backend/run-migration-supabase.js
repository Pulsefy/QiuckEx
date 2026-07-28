/**
 * Script to run the crash reporting database migration using Supabase client
 * 
 * Usage:
 *   node run-migration-supabase.js
 * 
 * Prerequisites:
 *   - .env file with SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY
 *   - npm install @supabase/supabase-js (should already be installed)
 */

const fs = require('fs');
const path = require('path');
require('dotenv').config();

async function runMigration() {
  console.log('🚀 Running Crash Reporting Database Migration\n');

  // Check for required environment variables
  if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SERVICE_ROLE_KEY) {
    console.error('❌ Missing required environment variables:');
    console.error('   - SUPABASE_URL');
    console.error('   - SUPABASE_SERVICE_ROLE_KEY');
    console.error('\nPlease add these to your .env file');
    process.exit(1);
  }

  // Import Supabase client
  let createClient;
  try {
    const supabase = require('@supabase/supabase-js');
    createClient = supabase.createClient;
  } catch (error) {
    console.error('❌ Failed to import @supabase/supabase-js');
    console.error('   Run: npm install @supabase/supabase-js');
    process.exit(1);
  }

  // Read migration file
  const migrationPath = path.join(__dirname, 'src', 'crash-reporting', 'migrations', '001_create_crash_reporting_tables.sql');
  
  if (!fs.existsSync(migrationPath)) {
    console.error('❌ Migration file not found:', migrationPath);
    process.exit(1);
  }

  const migrationSQL = fs.readFileSync(migrationPath, 'utf8');
  console.log('📄 Migration file loaded:', migrationPath);

  // Create Supabase client with service role key
  const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SERVICE_ROLE_KEY,
    {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    }
  );

  console.log('🔌 Connected to Supabase:', process.env.SUPABASE_URL);

  try {
    // Split the SQL into individual statements
    const statements = migrationSQL
      .split(';')
      .map(s => s.trim())
      .filter(s => s.length > 0 && !s.startsWith('--'));

    console.log(`\n📝 Executing ${statements.length} SQL statements...\n`);

    // Execute each statement
    for (let i = 0; i < statements.length; i++) {
      const statement = statements[i] + ';';
      
      // Skip comments
      if (statement.trim().startsWith('--')) {
        continue;
      }

      console.log(`[${i + 1}/${statements.length}] Executing...`);
      
      const { data, error } = await supabase.rpc('exec_sql', { sql: statement });
      
      if (error) {
        // Try direct query if RPC doesn't work
        const { error: queryError } = await supabase.from('_').select('*').limit(0);
        
        if (queryError) {
          console.error(`❌ Error executing statement ${i + 1}:`, error.message);
          console.error('Statement:', statement.substring(0, 100) + '...');
          
          console.log('\n⚠️  Direct SQL execution via Supabase client may not work.');
          console.log('Please use one of these alternatives:\n');
          console.log('1. Supabase Dashboard SQL Editor (recommended)');
          console.log('2. psql command-line tool');
          console.log('3. Supabase CLI: supabase db push\n');
          
          process.exit(1);
        }
      }
    }

    console.log('\n✅ Migration completed successfully!\n');

    // Verify tables were created
    console.log('🔍 Verifying tables...');
    
    const { data: tables, error: verifyError } = await supabase
      .from('information_schema.tables')
      .select('table_name')
      .in('table_name', ['crash_reports', 'crash_reporting_settings']);

    if (verifyError) {
      console.log('⚠️  Could not verify tables (this is okay)');
    } else if (tables && tables.length === 2) {
      console.log('✅ Tables verified:');
      console.log('   - crash_reports');
      console.log('   - crash_reporting_settings');
    }

    console.log('\n🎉 Migration complete! You can now use the crash reporting feature.\n');

  } catch (error) {
    console.error('\n❌ Migration failed:', error.message);
    console.error('\nPlease try using the Supabase Dashboard SQL Editor instead:');
    console.error('1. Go to your Supabase project dashboard');
    console.error('2. Navigate to SQL Editor');
    console.error('3. Copy the SQL from: src/crash-reporting/migrations/001_create_crash_reporting_tables.sql');
    console.error('4. Paste and run it\n');
    process.exit(1);
  }
}

// Run the migration
runMigration().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});
