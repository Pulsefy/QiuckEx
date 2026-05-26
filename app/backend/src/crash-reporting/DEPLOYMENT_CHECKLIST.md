# Crash Reporting Deployment Checklist

## Pre-Deployment

### 1. Code Review
- [ ] Review all redaction patterns in `redaction.service.ts`
- [ ] Verify no hardcoded sensitive data in test files
- [ ] Check that all imports are correct
- [ ] Verify TypeScript compilation succeeds

### 2. Testing
- [ ] Run unit tests: `npm run test:unit -- --testPathPattern=crash-reporting`
- [ ] Run integration tests: `npm run test:int -- --testPathPattern=crash-reporting`
- [ ] Manually test redaction with real sensitive data patterns
- [ ] Verify opt-in enforcement works correctly
- [ ] Test export functionality with opted-in user
- [ ] Test export returns null for non-opted-in user

### 3. Database Setup
- [ ] Review migration file: `migrations/001_create_crash_reporting_tables.sql`
- [ ] Test migration in development environment
- [ ] Verify RLS policies are enabled
- [ ] Test that users can only access their own data
- [ ] Verify indexes are created correctly

## Deployment Steps

### 1. Database Migration
```bash
# Backup database first
pg_dump -U postgres quickex > backup_before_crash_reporting.sql

# Run migration
psql -U postgres -d quickex -f src/crash-reporting/migrations/001_create_crash_reporting_tables.sql

# Verify tables
psql -U postgres -d quickex -c "\dt crash_*"
```

### 2. Deploy Code
- [ ] Merge feature branch to main
- [ ] Deploy to staging environment
- [ ] Verify application starts successfully
- [ ] Check logs for any errors

### 3. Smoke Tests (Staging)
- [ ] Test GET /crash-reporting/settings/:userId (should return default settings)
- [ ] Test PUT /crash-reporting/settings/:userId (enable crash reporting)
- [ ] Trigger a test error and verify crash is captured
- [ ] Test GET /crash-reporting/export/:userId (should return redacted logs)
- [ ] Verify no sensitive data in exported logs
- [ ] Test disabling crash reporting
- [ ] Verify no crashes captured after disabling

### 4. Production Deployment
- [ ] Deploy to production
- [ ] Monitor application logs for errors
- [ ] Verify database connection works
- [ ] Test API endpoints with a test user

## Post-Deployment

### 1. Monitoring
- [ ] Set up alerts for crash reporting errors
- [ ] Monitor database table sizes
- [ ] Check for any performance impact
- [ ] Monitor API endpoint response times

### 2. Documentation
- [ ] Update API documentation with new endpoints
- [ ] Notify support team about log export feature
- [ ] Create user-facing documentation for opt-in process
- [ ] Document internal procedures for accessing crash reports

### 3. Maintenance Setup
- [ ] Schedule periodic cleanup of old crash reports
- [ ] Set up monitoring for redaction failures
- [ ] Create runbook for common issues
- [ ] Document escalation procedures

## Validation Tests

### Test 1: Redaction Validation
```bash
# Create a test user and enable crash reporting
curl -X PUT http://localhost:4000/crash-reporting/settings/test-user \
  -H "Content-Type: application/json" \
  -d '{"enabled": true}'

# Trigger an error with sensitive data (in a test endpoint)
# Then export logs
curl http://localhost:4000/crash-reporting/export/test-user > test-export.json

# Verify no sensitive data in export
grep -i "SBZVMB74Z76QZ3ZOY3XRXEPNQN754WKRGMAG4OQIPOOB6QMHIDCNVYKY" test-export.json
# Should return nothing

grep -i "test_key_" test-export.json
# Should return nothing

grep -i "@example.com" test-export.json
# Should return nothing
```

### Test 2: Opt-In Enforcement
```bash
# Create a test user WITHOUT enabling crash reporting
# Trigger an error
# Verify no crash report was created
curl http://localhost:4000/crash-reporting/reports/test-user-2
# Should return empty array
```

### Test 3: Export Without Opt-In
```bash
# Try to export logs for user who hasn't opted in
curl http://localhost:4000/crash-reporting/export/test-user-3
# Should return 404 or null
```

## Rollback Plan

If issues are detected:

### 1. Immediate Actions
- [ ] Disable crash reporting module in app.module.ts
- [ ] Redeploy without crash reporting
- [ ] Verify application stability

### 2. Database Rollback (if needed)
```bash
# Drop tables
psql -U postgres -d quickex -c "DROP TABLE IF EXISTS crash_reports CASCADE;"
psql -U postgres -d quickex -c "DROP TABLE IF EXISTS crash_reporting_settings CASCADE;"

# Restore from backup if needed
psql -U postgres -d quickex < backup_before_crash_reporting.sql
```

### 3. Code Rollback
- [ ] Revert commit
- [ ] Remove CrashReportingModule from app.module.ts
- [ ] Redeploy

## Success Criteria

- [ ] All tests pass
- [ ] No sensitive data in crash reports (validated)
- [ ] Users can opt-in and opt-out successfully
- [ ] Export functionality works for opted-in users
- [ ] Export returns null for non-opted-in users
- [ ] No performance degradation
- [ ] No errors in application logs
- [ ] Database queries are performant
- [ ] RLS policies work correctly

## Optional Enhancements (Post-Launch)

### Phase 2 Features
- [ ] Add global exception filter (CrashCaptureFilter)
- [ ] Add log capture interceptor (LogCaptureInterceptor)
- [ ] Implement automatic cleanup job for old reports
- [ ] Add metrics for crash reporting usage
- [ ] Create admin dashboard for crash report analysis

### Phase 3 Features
- [ ] Add support for custom redaction patterns
- [ ] Implement log streaming to external services
- [ ] Add crash report aggregation and analysis
- [ ] Implement log sampling for high-traffic scenarios
- [ ] Add support for structured logging with field redaction

## Support Contacts

- **Database Issues**: DBA Team
- **API Issues**: Backend Team
- **Security Concerns**: Security Team
- **User Support**: Support Team

## Notes

- Feature is opt-in by default - no user data is captured without consent
- All data is redacted before storage - no secrets or PII should ever be stored
- RLS policies ensure users can only access their own data
- Regular cleanup of old reports is recommended (90 days)
- Monitor for any redaction failures and update patterns as needed

## Sign-Off

- [ ] Development Lead: _______________
- [ ] QA Lead: _______________
- [ ] Security Review: _______________
- [ ] Product Owner: _______________
- [ ] DevOps: _______________

Date: _______________
