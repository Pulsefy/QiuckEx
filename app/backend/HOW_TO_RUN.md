# How to Run Database Migration and Tests

## Quick Start (3 Steps)

### 1️⃣ Run Database Migration

**Easiest Method - Supabase Dashboard:**

1. Go to your Supabase project → **SQL Editor**
2. Open file: `src/crash-reporting/migrations/001_create_crash_reporting_tables.sql`
3. Copy all the SQL
4. Paste into Supabase SQL Editor
5. Click **Run**

**Alternative - Use Helper Script:**
```bash
cd app/backend
node run-migration.js
```
This shows you the SQL and instructions.

---

### 2️⃣ Run Tests

**Windows (All tests at once):**
```bash
cd app/backend
run-crash-reporting-tests.bat
```

**Or run individually:**
```bash
# Test 1: Redaction
npm run test:unit -- --testPathPattern=redaction.service.spec.ts

# Test 2: Service
npm run test:unit -- --testPathPattern=crash-reporting.service.spec.ts

# Test 3: Integration
npm run test:int -- --testPathPattern=crash-reporting.integration.spec.ts
```

---

### 3️⃣ Test the API

**Start backend:**
```bash
npm run dev
```

**Test in another terminal:**
```bash
# Get settings
curl http://localhost:4000/crash-reporting/settings/test-user

# Enable crash reporting
curl -X PUT http://localhost:4000/crash-reporting/settings/test-user -H "Content-Type: application/json" -d "{\"enabled\": true}"
```

---

## That's It! 🎉

For more details, see `SETUP_GUIDE.md`
