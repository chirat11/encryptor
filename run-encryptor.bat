@echo off
title encryptor
echo Starting encryptor...
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
    echo encryptor encountered an error.
    pause
) 