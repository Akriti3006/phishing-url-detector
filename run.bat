@echo off
title Phishing URL Detector
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

if not defined DB_PASSWORD set /p DB_PASSWORD=Enter MySQL password: 

if not exist model.joblib (
    echo No trained model found. Training now, this takes a few minutes...
    python train.py
)

echo Starting the app. Your browser will open in a few seconds.
start "" cmd /c "timeout /t 4 >nul & start http://127.0.0.1:5000"
python app.py

pause
