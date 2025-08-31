@echo off
REM TypoSentinel Windows Build Script
REM This script builds the TypoSentinel application for Windows

setlocal enabledelayedexpansion

REM Configuration
set APP_NAME=typosentinel
set VERSION=1.0.0
set BUILD_DIR=.\bin
set LDFLAGS=-X main.version=%VERSION% -X main.buildTime=%date%_%time% -w -s

echo [INFO] Building TypoSentinel for Windows...

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

REM Try different build approaches
echo [INFO] Attempting to build with CGO disabled...
set CGO_ENABLED=0
set GOOS=windows
set GOARCH=amd64

REM Try simple build first
go build -ldflags "%LDFLAGS%" -o "%BUILD_DIR%\%APP_NAME%.exe" main.go
if %errorlevel% equ 0 (
    echo [SUCCESS] Built %APP_NAME%.exe successfully!
    goto :test_binary
)

echo [WARNING] Standard build failed, trying alternative approach...

REM Try building without ldflags
go build -o "%BUILD_DIR%\%APP_NAME%.exe" main.go
if %errorlevel% equ 0 (
    echo [SUCCESS] Built %APP_NAME%.exe successfully (without ldflags)!
    goto :test_binary
)

echo [ERROR] Build failed. Checking if we can use the existing enterprise binary...
if exist "typosentinel-enterprise" (
    echo [INFO] Found existing enterprise binary, copying as fallback...
    copy "typosentinel-enterprise" "%BUILD_DIR%\%APP_NAME%-enterprise.exe"
    echo [WARNING] Using existing enterprise binary as fallback
    goto :end
)

echo [ERROR] All build attempts failed.
goto :end

:test_binary
echo [INFO] Testing the built binary...
if exist "%BUILD_DIR%\%APP_NAME%.exe" (
    echo [SUCCESS] Binary exists at %BUILD_DIR%\%APP_NAME%.exe
    "%BUILD_DIR%\%APP_NAME%.exe" --version 2>nul
    if %errorlevel% equ 0 (
        echo [SUCCESS] Binary is functional!
    ) else (
        echo [WARNING] Binary exists but may have runtime issues
    )
) else (
    echo [ERROR] Binary was not created
)

:end
echo [INFO] Build process completed.
pause