#!/usr/bin/env bash
# ==============================================================================
# CyberSOC: AI-Powered IoT Security Command Center - Linux Startup Script
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo "========================================================"
echo "🛡️  CyberSOC: Bayesian-Markov Hybrid Security Command Center"
echo "========================================================"

# 1. Environment Verification
echo "[1/5] Checking runtime environments..."
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required but not installed."
    exit 1
fi

if ! command -v node &> /dev/null; then
    echo "❌ Error: Node.js is required but not installed."
    exit 1
fi

echo "   Python version: $(python3 --version)"
echo "   Node version:   $(node --version)"

# 2. Python Dependencies
echo "[2/5] Verifying Python dependencies..."
pip install -r requirements.txt --quiet

# 3. Database Initialization (Non-destructive)
echo "[3/5] Initializing persistent threat database..."
python3 init_db.py

# 4. Running Mathematical Model Tests
echo "[4/5] Executing test suite..."
pytest -q tests/

# 5. Starting Backend and Frontend Services
echo "[5/5] Launching CyberSOC Command Center..."

# Trap SIGINT/SIGTERM to stop background processes cleanly
cleanup() {
    echo ""
    echo "Shutting down CyberSOC background processes..."
    if [ -n "$FLASK_PID" ]; then
        kill "$FLASK_PID" 2>/dev/null || true
    fi
    if [ -n "$REACT_PID" ]; then
        kill "$REACT_PID" 2>/dev/null || true
    fi
    exit 0
}
trap cleanup SIGINT SIGTERM EXIT

# Start Flask Backend in background
echo "-> Starting Flask Backend on http://127.0.0.1:5000..."
python3 app.py &
FLASK_PID=$!

# Wait for Flask to boot
sleep 2

# Start React Frontend
echo "-> Starting React Frontend on http://localhost:3000..."
cd frontend
npm start &
REACT_PID=$!

echo ""
echo "========================================================"
echo "✓ CyberSOC Services Running:"
echo "   - Backend API:  http://127.0.0.1:5000"
echo "   - Web Frontend: http://localhost:3000"
echo "Press Ctrl+C to terminate all services."
echo "========================================================"

wait
