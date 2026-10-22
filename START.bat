@echo off
cd /d "%~dp0"
where py >nul 2>nul && (set PY=py) || (set PY=python)
%PY% --version >nul 2>nul || (
  echo Python is not installed. Get it from https://www.python.org/downloads/ ^(tick "Add to PATH"^), then run this again.
  pause
  exit /b
)
echo.
echo PromptGuard: prompt injection test of an AI email filter.
echo You will be asked for your Gemini API key. Right-click to paste, then press Enter.
echo The key is not shown, not saved, and only sent to Google.
echo.
%PY% run.py
echo.
echo Done. Results are in the "results" folder.
pause
