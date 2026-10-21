@echo off
echo Starting Security Log Analyzer...
echo.

echo [1/2] Starting Backend...
cd backend
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate
pip install -r requirements.txt
start "Backend" cmd /k "python main.py"
cd ..

echo [2/2] Starting Frontend...
cd frontend
if not exist node_modules (
    echo Installing frontend dependencies...
    call npm install
)
start "Frontend" cmd /k "npm run dev"
cd ..

echo.
echo Both servers are starting...
echo Backend: http://localhost:8000
echo Frontend: http://localhost:5173
echo.
echo Press any key to exit...
pause >nul
