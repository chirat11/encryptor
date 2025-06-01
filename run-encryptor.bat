@echo off
title Encryptor - Secure File Protection
echo Starting Encryptor...
echo.

if not exist "encryptor.exe" (
    echo Error: encryptor.exe not found in the current directory.
    echo Please make sure encryptor.exe is in the same folder as this batch file.
    echo.
    pause
    exit /b 1
)

encryptor.exe

if errorlevel 1 (
    echo.
    echo Encryptor encountered an error.
    pause
) 