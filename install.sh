#!/bin/bash
# ============================================================================
# JAVIER WEBSCANNER - Installer (Kali Linux)
# ============================================================================
set -e

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJECT_DIR"

echo "=========================================="
echo "  Javier WebScanner - Installer"
echo "=========================================="

if ! grep -q "kali" /etc/os-release 2>/dev/null; then
    echo "[!] Optimizado para Kali Linux. Continuando de todas formas..."
fi

echo "[*] Instalando herramientas de pentesting (apt)..."
sudo apt update -y
sudo apt install -y \
    nikto nmap sqlmap dirb gobuster whatweb wafw00f \
    dnsutils whois openssl curl \
    python3 python3-venv python3-pip \
    dirbuster wordlists || true

echo "[*] Creando entorno virtual..."
python3 -m venv "$PROJECT_DIR/venv"
# shellcheck disable=SC1091
source "$PROJECT_DIR/venv/bin/activate"

echo "[*] Instalando dependencias Python..."
pip install --upgrade pip
pip install -r requirements.txt

echo "[*] Creando directorios..."
mkdir -p "$PROJECT_DIR/reports" "$PROJECT_DIR/logs"

deactivate

echo ""
echo "[+] Instalación completada!"
echo ""
echo "Iniciar:    ./start.sh"
echo "URL:        http://127.0.0.1:5000"
echo "Informes:   $PROJECT_DIR/reports/"
echo ""
