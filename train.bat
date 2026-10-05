@echo off
title Train Phishing Model
cd /d "%~dp0"

if not exist venv\Scripts\activate.bat (
    echo Could not find the venv folder. Create it first with:
    echo   py -3.11 -m venv venv
    echo   venv\Scripts\activate
    echo   pip install -r requirements.txt
    pause
    exit /b 1
)

call venv\Scripts\activate.bat

echo Training the model. This takes a few minutes...
python train.py

echo.
echo Done. Now double-click run.bat to start the app.
pause
