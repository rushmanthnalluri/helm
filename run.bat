@echo off
title Helm - Windows Desktop Assistant
cd /d "%~dp0"
python app.py %*
if errorlevel 1 (
    echo.
    echo Helm exited with an error.
    pause
)
