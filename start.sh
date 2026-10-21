#!/bin/bash

echo "Starting Security Log Analyzer..."
echo

echo "[1/2] Starting Backend..."
cd backend
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi
source venv/bin/activate
pip install -r requirements.txt
python main.py &
BACKEND_PID=$!
cd ..

echo "[2/2] Starting Frontend..."
cd frontend
if [ ! -d "node_modules" ]; then
    echo "Installing frontend dependencies..."
    npm install
fi
npm run dev &
FRONTEND_PID=$!
cd ..

echo
echo Both servers are starting...
echo Backend: http://localhost:8000
echo Frontend: http://localhost:5173
echo
echo "Press Ctrl+C to stop both servers"

# Handle Ctrl+C
trap "kill $BACKEND_PID $FRONTEND_PID" EXIT

wait
