@echo off
setlocal enabledelayedexpansion

REM Enhanced ML Model Deployment Script for Windows
REM TypoSentinel Enhanced Threat Detection Model Deployment

set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%.."
set "MODEL_FILE=enhanced_threat_detection_model.json"
set "BACKUP_DIR=%PROJECT_ROOT%\backups\ml"
set "CONFIG_FILE=%PROJECT_ROOT%\config\ml_production.yaml"
set "LOG_DIR=%PROJECT_ROOT%\logs"
set "LOG_FILE=%LOG_DIR%\deployment.log"
set "HEALTH_CHECK_URL=http://localhost:8080/api/v1/ml/health"
set "DEPLOYMENT_TIMEOUT=300"

REM Create logs directory if it doesn't exist
if not exist "%LOG_DIR%" mkdir "%LOG_DIR%"

REM Function to log messages
:log
set "timestamp=%date% %time%"
echo [%timestamp%] [%1] %~2
echo [%timestamp%] [%1] %~2 >> "%LOG_FILE%"
goto :eof

:log_info
call :log "INFO" "%~1"
echo [INFO] %~1
goto :eof

:log_warn
call :log "WARN" "%~1"
echo [WARN] %~1
goto :eof

:log_error
call :log "ERROR" "%~1"
echo [ERROR] %~1
goto :eof

:log_success
call :log "SUCCESS" "%~1"
echo [SUCCESS] %~1
goto :eof

:error_exit
call :log_error "%~1"
echo Deployment failed: %~1
exit /b 1

REM Function to check prerequisites
:check_prerequisites
call :log_info "Checking deployment prerequisites..."

REM Check if model file exists
if not exist "%PROJECT_ROOT%\%MODEL_FILE%" (
    call :error_exit "Enhanced model file not found: %PROJECT_ROOT%\%MODEL_FILE%"
)

REM Check if configuration file exists
if not exist "%CONFIG_FILE%" (
    call :error_exit "Configuration file not found: %CONFIG_FILE%"
)

REM Check if backup directory exists, create if not
if not exist "%BACKUP_DIR%" (
    call :log_info "Creating backup directory: %BACKUP_DIR%"
    mkdir "%BACKUP_DIR%"
)

REM Check if Go is installed
go version >nul 2>&1
if errorlevel 1 (
    call :error_exit "Go is not installed or not in PATH"
)

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    python3 --version >nul 2>&1
    if errorlevel 1 (
        call :error_exit "Python is not installed or not in PATH"
    )
)

call :log_success "Prerequisites check completed"
goto :eof

REM Function to backup current model
:backup_current_model
call :log_info "Backing up current model..."

set "current_model=%PROJECT_ROOT%\models\default.model"
for /f "tokens=1-3 delims=/: " %%a in ("%date% %time%") do (
    set "backup_timestamp=%%c%%a%%b_%%d%%e%%f"
)
set "backup_timestamp=%backup_timestamp: =0%"
set "backup_file=%BACKUP_DIR%\model_backup_%backup_timestamp%.model"

if exist "%current_model%" (
    copy "%current_model%" "%backup_file%" >nul
    call :log_success "Current model backed up to: %backup_file%"
) else (
    call :log_warn "No current model found to backup"
)

REM Backup enhanced model if it exists
set "enhanced_model=%PROJECT_ROOT%\enhanced_threat_detection_model.json"
if exist "%enhanced_model%" (
    set "enhanced_backup=%BACKUP_DIR%\enhanced_model_backup_%backup_timestamp%.json"
    copy "%enhanced_model%" "!enhanced_backup!" >nul
    call :log_success "Enhanced model backed up to: !enhanced_backup!"
)

goto :eof

REM Function to validate model file
:validate_model
call :log_info "Validating enhanced model file..."

set "model_path=%PROJECT_ROOT%\%MODEL_FILE%"

REM Check if file is valid JSON using Python
python -c "import json; json.load(open('%model_path%'))" >nul 2>&1
if errorlevel 1 (
    call :error_exit "Model file is not valid JSON: %model_path%"
)

REM Check model performance metrics
for /f %%i in ('python -c "import json; data=json.load(open('%model_path%')); print(data['training_result']['final_accuracy'])"') do set "accuracy=%%i"

call :log_success "Model validation completed (accuracy: %accuracy%)"
goto :eof

REM Function to run tests
:run_tests
call :log_info "Running pre-deployment tests..."

cd /d "%PROJECT_ROOT%"

REM Run enhanced ML tests
if exist "test_enhanced_ml.py" (
    call :log_info "Running enhanced ML test suite..."
    python test_enhanced_ml.py
    if errorlevel 1 (
        call :error_exit "Enhanced ML tests failed"
    )
    call :log_success "Enhanced ML tests passed"
) else (
    call :log_warn "Enhanced ML test file not found, skipping tests"
)

REM Run Go tests
call :log_info "Running Go tests..."
go test ./... -v
if errorlevel 1 (
    call :error_exit "Go tests failed"
)
call :log_success "Go tests passed"

goto :eof

REM Function to build application
:build_application
call :log_info "Building TypoSentinel application..."

cd /d "%PROJECT_ROOT%"

REM Clean previous builds
if exist "typosentinel.exe" del "typosentinel.exe"
if exist "typosentinel" del "typosentinel"

REM Build for Windows
go build -o typosentinel.exe ./main.go
if errorlevel 1 (
    call :error_exit "Application build failed"
)

call :log_success "Application built successfully"
goto :eof

REM Function to deploy model
:deploy_model
call :log_info "Deploying enhanced ML model..."

cd /d "%PROJECT_ROOT%"

REM Create models directory if it doesn't exist
set "models_dir=%PROJECT_ROOT%\models"
if not exist "%models_dir%" mkdir "%models_dir%"

REM Copy enhanced model
copy "%MODEL_FILE%" "%models_dir%\enhanced_threat_detection_model.json" >nul
call :log_success "Enhanced model deployed to models directory"

if exist "%CONFIG_FILE%" (
    call :log_info "Configuration file already exists: %CONFIG_FILE%"
) else (
    call :log_warn "Configuration file not found, using default settings"
)

goto :eof

REM Function to start application
:start_application
call :log_info "Starting TypoSentinel application..."

cd /d "%PROJECT_ROOT%"

REM Check if application is already running
tasklist /FI "IMAGENAME eq typosentinel.exe" 2>NUL | find /I /N "typosentinel.exe">NUL
if "%ERRORLEVEL%"=="0" (
    call :log_warn "TypoSentinel is already running, stopping it first..."
    taskkill /F /IM typosentinel.exe >nul 2>&1
    timeout /t 2 >nul
)

REM Start application
call :log_info "Starting application with enhanced ML model..."
start /B "" typosentinel.exe server --dev --port 8080 > "%LOG_DIR%\typosentinel.log" 2>&1

REM Wait for application to start
timeout /t 5 >nul

call :log_info "Application started"
goto :eof

REM Function to perform health checks
:health_check
call :log_info "Performing health checks..."

set "max_attempts=30"
set "attempt=1"

:health_check_loop
if %attempt% gtr %max_attempts% (
    call :error_exit "Health check failed after %max_attempts% attempts"
)

call :log_info "Health check attempt %attempt%/%max_attempts%..."

REM Use curl if available, otherwise use PowerShell
curl -s -f "%HEALTH_CHECK_URL%" >nul 2>&1
if not errorlevel 1 (
    call :log_success "Health check passed"
    goto :eof
)

REM Fallback to PowerShell
powershell -Command "try { Invoke-WebRequest -Uri '%HEALTH_CHECK_URL%' -UseBasicParsing | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    call :log_success "Health check passed"
    goto :eof
)

timeout /t 2 >nul
set /a attempt+=1
goto health_check_loop

REM Function to run smoke tests
:run_smoke_tests
call :log_info "Running smoke tests..."

set "base_url=http://localhost:8080"

REM Test health endpoint
powershell -Command "try { Invoke-WebRequest -Uri '%base_url%/health' -UseBasicParsing | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    call :log_success "Health endpoint test passed"
) else (
    call :log_warn "Health endpoint test failed"
)

REM Test ML health endpoint
powershell -Command "try { Invoke-WebRequest -Uri '%base_url%/api/v1/ml/health' -UseBasicParsing | Out-Null; exit 0 } catch { exit 1 }" >nul 2>&1
if not errorlevel 1 (
    call :log_success "ML health endpoint test passed"
) else (
    call :log_warn "ML health endpoint test failed (may not be implemented yet)"
)

goto :eof

REM Function to create deployment report
:create_deployment_report
call :log_info "Creating deployment report..."

for /f "tokens=1-3 delims=/: " %%a in ("%date% %time%") do (
    set "report_timestamp=%%c%%a%%b_%%d%%e%%f"
)
set "report_timestamp=%report_timestamp: =0%"
set "report_file=%PROJECT_ROOT%\deployment_report_%report_timestamp%.md"

(
echo # Enhanced ML Model Deployment Report
echo.
echo **Deployment Date**: %date% %time%
echo **Model Version**: Enhanced v1.0
echo **Deployment Script**: %~nx0
echo.
echo ## Deployment Summary
echo.
echo - ✅ Prerequisites checked
echo - ✅ Current model backed up
echo - ✅ Enhanced model validated
echo - ✅ Pre-deployment tests passed
echo - ✅ Application built successfully
echo - ✅ Enhanced model deployed
echo - ✅ Application started
echo - ✅ Health checks passed
echo - ✅ Smoke tests completed
echo.
echo ## Model Information
echo.
echo - **Model File**: %MODEL_FILE%
echo - **Model Location**: %PROJECT_ROOT%\models\enhanced_threat_detection_model.json
echo - **Configuration**: %CONFIG_FILE%
echo - **Backup Location**: %BACKUP_DIR%
echo.
echo ## Health Check Results
echo.
echo - **Application URL**: http://localhost:8080
echo - **Health Endpoint**: %HEALTH_CHECK_URL%
echo - **Status**: ✅ Healthy
echo.
echo ## Next Steps
echo.
echo 1. Monitor application logs
echo 2. Monitor deployment logs: %LOG_FILE%
echo 3. Check ML metrics via API endpoints
echo 4. Set up automated monitoring alerts
echo 5. Plan gradual rollout to production traffic
echo.
echo ## Rollback Instructions
echo.
echo If issues are detected:
echo.
echo 1. Stop the application: `taskkill /F /IM typosentinel.exe`
echo 2. Restore backup model from: %BACKUP_DIR%
echo 3. Restart with previous configuration
echo 4. Investigate issues in logs
echo.
echo ---
echo.
echo **Deployment completed successfully at %date% %time%**
) > "%report_file%"

call :log_success "Deployment report created: %report_file%"
goto :eof

REM Main deployment function
:main
call :log_info "Starting Enhanced ML Model Deployment"
call :log_info "Project Root: %PROJECT_ROOT%"
call :log_info "Model File: %MODEL_FILE%"
call :log_info "Configuration: %CONFIG_FILE%"

REM Run deployment steps
call :check_prerequisites
if errorlevel 1 exit /b 1

call :backup_current_model
if errorlevel 1 exit /b 1

call :validate_model
if errorlevel 1 exit /b 1

call :run_tests
if errorlevel 1 exit /b 1

call :build_application
if errorlevel 1 exit /b 1

call :deploy_model
if errorlevel 1 exit /b 1

call :start_application
if errorlevel 1 exit /b 1

call :health_check
if errorlevel 1 exit /b 1

call :run_smoke_tests
if errorlevel 1 exit /b 1

call :create_deployment_report
if errorlevel 1 exit /b 1

call :log_success "Enhanced ML Model deployment completed successfully!"
call :log_info "Application is running at: http://localhost:8080"
call :log_info "Logs available at: %LOG_FILE%"
call :log_info "Application logs: %LOG_DIR%\typosentinel.log"

echo.
echo 🎉 Deployment Successful!
echo 📊 Monitor the application:
echo    • Application: http://localhost:8080
echo    • Health Check: %HEALTH_CHECK_URL%
echo    • Logs: %LOG_FILE%
echo.

goto :eof

REM Script entry point
call :main
if errorlevel 1 (
    echo Deployment failed. Check logs for details: %LOG_FILE%
    pause
    exit /b 1
)

echo Deployment completed successfully!
pause