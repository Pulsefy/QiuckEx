# Crash Reporting Setup Guide

This guide will walk you through setting up and testing the crash reporting feature.

## Prerequisites

- Node.js and npm installed
- Access to your Supabase project
- Backend dependencies installed (`npm install`)

## Step 1: Run the Database Migration

You have **4 options** to run the migration. Choose the one that works best for you:

### Option 1: Supabase Dashboard (Easiest - Recommended)

1. Open your Supabase project dashboard
2. Go to **SQL Editor** (left sidebar)
3. Click **New Query**
4. Open the file: `src/crash-reporting/migrations/001_create_crash_reporting_tables.sql`
5. Copy all the SQL content
6. Paste it into the Supabase SQL Editor
7. Click **Run** (or press Ctrl+Enter)
8. You should see "Success. No rows returned"

**Verify it worked:**
```sql
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name IN ('crash_reports', 'crash_reporting_settings');
```
You should see both tables listed.

---

### Option 2: Using the Migration Helper Script

```bash
cd app/backend
node run-migration.js
```

This will show you the migration SQL and instructions for running it.

---

### Option 3: Using psql (if you have PostgreSQL installed)

```bash
cd app/backend
psql -U postgres -d quickex -f src/crash-reporting/migrations/001_create_crash_reporting_tables.sql
```

Replace `postgres` with your database username and `quickex` with your database name.

---

### Option 4: Using Supabase Client (Advanced)

```bash
cd app/backend
node run-migration-supabase.js
```

**Note:** This requires `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` in your `.env` file.

---

## Step 2: Run the Tests

### Option A: Run All Tests at Once (Windows)

```bash
cd app/backend
run-crash-reporting-tests.bat
```

This will run all three test suites and show you the results.

---

### Option B: Run Tests Individually

**1. Test Redaction Service:**
```bash
npm run test:unit -- --testPathPattern=redaction.service.spec.ts
```

**2. Test Crash Reporting Service:**
```bash
npm run test:unit -- --testPathPattern=crash-reporting.service.spec.ts
```

**3. Test Integration:**
```bash
npm run test:int -- --testPathPattern=crash-reporting.integration.spec.ts
```

---

### Option C: Run All Crash Reporting Tests

```bash
npm run test:unit -- --testPathPattern=crash-reporting
```

---

## Step 3: Verify Everything Works

### Test the API Endpoints

**1. Start the backend:**
```bash
npm run dev
```

**2. Test getting settings (should return default):**
```bash
curl http://localhost:4000/crash-reporting/settings/test-user
```

Expected response:
```json
{
  "userId": "test-user",
  "crashReportingEnabled": false,
  "updatedAt": "2026-05-26T..."
}
```

**3. Enable crash reporting:**
```bash
curl -X PUT http://localhost:4000/crash-reporting/settings/test-user ^
  -H "Content-Type: application/json" ^
  -d "{\"enabled\": true}"
```

Expected response:
```json
{
  "message": "Crash reporting enabled successfully"
}
```

**4. Verify it's enabled:**
```bash
curl http://localhost:4000/crash-reporting/settings/test-user
```

Expected response:
```json
{
  "userId": "test-user",
  "crashReportingEnabled": true,
  "updatedAt": "2026-05-26T..."
}
```

---

## Troubleshooting

### Issue: "jest is not recognized"

**Solution:** Install dependencies first:
```bash
cd app/backend
npm install
```

---

### Issue: Migration fails with "permission denied"

**Solution:** Make sure you're using the service role key (not the anon key) in your `.env` file:
```
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key-here
```

---

### Issue: Tests fail with "Cannot find module"

**Solution:** Make sure you're in the backend directory:
```bash
cd app/backend
npm install
npm run test:unit -- --testPathPattern=crash-reporting
```

---

### Issue: "Table already exists"

**Solution:** The migration has already been run. You can verify the tables exist:
```sql
SELECT table_name FROM information_schema.tables 
WHERE table_schema = 'public' 
AND table_name LIKE 'crash_%';
```

---

## What's Next?

After setup is complete:

1. **Read the documentation:**
   - `src/crash-reporting/README.md` - Complete feature documentation
   - `src/crash-reporting/QUICK_START.md` - Quick reference guide

2. **Optional: Enable automatic crash capture:**
   - Add the global exception filter to `app.module.ts`
   - Add the log capture interceptor to `app.module.ts`
   - See `README.md` for instructions

3. **Set up cleanup job:**
   - Schedule periodic cleanup of old crash reports
   - See `README.md` for details

---

## Quick Command Reference

```bash
# Run migration helper
node run-migration.js

# Run all tests (Windows)
run-crash-reporting-tests.bat

# Run specific test
npm run test:unit -- --testPathPattern=redaction.service.spec.ts

# Start backend
npm run dev

# Test API
curl http://localhost:4000/crash-reporting/settings/test-user
```

---

## Need Help?

- Check `src/crash-reporting/README.md` for detailed documentation
- Check `src/crash-reporting/QUICK_START.md` for common tasks
- Check `src/crash-reporting/DEPLOYMENT_CHECKLIST.md` for deployment steps
- Review the test files for usage examples

---

## Success Checklist

- [ ] Database migration completed successfully
- [ ] Both tables created (crash_reports, crash_reporting_settings)
- [ ] All tests pass (redaction, service, integration)
- [ ] API endpoints respond correctly
- [ ] Can enable/disable crash reporting for a user
- [ ] Backend starts without errors

Once all items are checked, the crash reporting feature is ready to use! 🎉
