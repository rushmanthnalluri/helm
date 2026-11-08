@echo off
title Homie - Windows Desktop Assistant
cd /d "%~dp0"
python app.py %*
if errorlevel 1 (
    echo.
    echo Homie exited with an error.
    pause
)
