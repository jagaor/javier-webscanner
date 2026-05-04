#!/bin/bash
# ============================================================================
# JAVIER WEBSCANNER - Launcher
# ============================================================================
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

if [ ! -d "$PROJECT_DIR/venv" ]; then
    echo "[!] venv no existe. Ejecuta primero: ./install.sh"
    exit 1
fi

# shellcheck disable=SC1091
source "$PROJECT_DIR/venv/bin/activate"

echo "=========================================="
echo "  Javier WebScanner"
echo "  http://127.0.0.1:5000"
echo "  Ctrl+C para detener"
echo "=========================================="

python3 app.py
