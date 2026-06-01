@echo off
echo ========================================
echo Running Crash Reporting Tests
echo ========================================
echo.

echo [1/3] Running Redaction Service Tests...
echo ----------------------------------------
call npm run test:unit -- --testPathPattern=redaction.service.unit.spec.ts
if %errorlevel% neq 0 (
    echo.
    echo ❌ Redaction tests failed!
    pause
    exit /b %errorlevel%
)

echo.
echo ✅ Redaction tests passed!
echo.

echo [2/3] Running Crash Reporting Service Tests...
echo -----------------------------------------------
call npm run test:unit -- --testPathPattern=crash-reporting.service.unit.spec.ts
if %errorlevel% neq 0 (
    echo.
    echo ❌ Crash reporting service tests failed!
    pause
    exit /b %errorlevel%
)

echo.
echo ✅ Crash reporting service tests passed!
echo.

echo [3/3] Running Integration Tests...
echo -----------------------------------
call npm run test:int -- --testPathPattern=crash-reporting.int.spec.ts
if %errorlevel% neq 0 (
    echo.
    echo ❌ Integration tests failed!
    pause
    exit /b %errorlevel%
)

echo.
echo ✅ Integration tests passed!
echo.
echo ========================================
echo 🎉 All Crash Reporting Tests Passed!
echo ========================================
echo.
pause
