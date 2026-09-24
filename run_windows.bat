@echo off
setlocal
cd /d "%~dp0"
echo PhishGuard local launcher
echo [1] Install Python and frontend dependencies
echo [2] Train and evaluate models
echo [3] Start backend
echo [4] Start frontend
echo [5] Start backend and frontend
set /p choice=Choose an option (1-5): 
if "%choice%"=="1" (
  python -m pip install -r requirements.txt
  if errorlevel 1 exit /b 1
  pushd frontend
  call npm install
  if errorlevel 1 exit /b 1
  popd
)
if "%choice%"=="2" python -m src.train
if "%choice%"=="3" python -m uvicorn backend.app:app --host 127.0.0.1 --port 8010
if "%choice%"=="4" (cd frontend && npm run dev)
if "%choice%"=="5" (
  start "PhishGuard API" cmd /k "cd /d ""%~dp0"" && python -m uvicorn backend.app:app --host 127.0.0.1 --port 8010"
  start "PhishGuard Frontend" cmd /k "cd /d ""%~dp0frontend"" && npm run dev"
  echo Open http://127.0.0.1:5173
)
if not "%choice%"=="1" if not "%choice%"=="2" if not "%choice%"=="3" if not "%choice%"=="4" if not "%choice%"=="5" echo Invalid option.
endlocal
