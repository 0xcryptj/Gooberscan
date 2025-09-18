#!/usr/bin/env bash
set -euo pipefail

# Docker Permission Fix Script for GooberScan
# This script fixes common Docker permission issues

echo "╔══════════════════════════════════════════════════════════════════════════════╗"
echo "║                                                                              ║"
echo "║                    GooberScan Docker Fix Script                              ║"
echo "║                                                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════════════╝"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
    echo "[!] This script should not be run as root"
    echo "[*] Please run as regular user: ./fix-docker.sh"
    exit 1
fi

echo "[*] Current user: $USER"
echo "[*] Checking Docker installation..."

# Check if Docker is installed
if ! command -v docker >/dev/null 2>&1; then
    echo "[!] Docker is not installed"
    echo "[*] Installing Docker..."
    sudo apt update
    sudo apt install -y docker.io
    sudo systemctl enable --now docker
    echo "[+] Docker installed successfully"
else
    echo "[+] Docker is installed"
fi

# Check Docker service status
echo "[*] Checking Docker service status..."
if ! sudo systemctl is-active --quiet docker; then
    echo "[!] Docker service is not running"
    echo "[*] Starting Docker service..."
    sudo systemctl start docker
    sudo systemctl enable docker
    echo "[+] Docker service started"
else
    echo "[+] Docker service is running"
fi

# Check Docker permissions
echo "[*] Checking Docker permissions..."
if ! docker ps >/dev/null 2>&1; then
    echo "[!] Docker permission denied"
    echo "[*] Adding user to docker group..."
    sudo usermod -aG docker "$USER"
    
    echo "[*] Starting Docker service..."
    sudo systemctl start docker
    
    echo ""
    echo "╔══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                                                                              ║"
    echo "║                    IMPORTANT: Docker Group Membership                        ║"
    echo "║                                                                              ║"
    echo "║  You have been added to the docker group, but you need to:                  ║"
    echo "║                                                                              ║"
    echo "║  1. Log out and log back in, OR                                             ║"
    echo "║  2. Run: newgrp docker                                                      ║"
    echo "║                                                                              ║"
    echo "║  Then test with: docker ps                                                   ║"
    echo "║                                                                              ║"
    echo "╚══════════════════════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Try to apply group membership immediately
    echo "[*] Attempting to apply group membership immediately..."
    if newgrp docker <<< "docker ps" >/dev/null 2>&1; then
        echo "[+] Docker permissions fixed!"
        echo "[*] You can now run GooberScan with Docker support"
    else
        echo "[!] Please log out and back in, then run: docker ps"
    fi
else
    echo "[+] Docker permissions are working correctly"
fi

# Test Docker functionality
echo "[*] Testing Docker functionality..."
if docker run --rm hello-world >/dev/null 2>&1; then
    echo "[+] Docker is working correctly"
    
    # Pull required images
    echo "[*] Pulling required Docker images..."
    docker pull owasp/zap2docker-stable:latest || echo "[!] Failed to pull ZAP image"
    docker pull wpscanteam/wpscan || echo "[!] Failed to pull WPScan image"
    
    echo ""
    echo "🎉 Docker setup complete!"
    echo "[*] GooberScan can now use Docker for ZAP and WPScan scans"
else
    echo "[!] Docker test failed"
    echo "[*] Please check Docker installation and permissions"
fi

# Alternative: Install ZAP locally if Docker fails
echo ""
echo "[*] Checking for alternative ZAP installation..."
if ! command -v zaproxy >/dev/null 2>&1; then
    echo "[*] Installing ZAP locally as backup..."
    sudo apt update
    sudo apt install -y zaproxy || echo "[!] Failed to install ZAP locally"
    
    if command -v zaproxy >/dev/null 2>&1; then
        echo "[+] ZAP installed locally as backup"
        echo "[*] GooberScan will use local ZAP if Docker fails"
    fi
else
    echo "[+] ZAP is already available locally"
fi

echo ""
echo "📋 Summary:"
echo "  - Docker service: $(sudo systemctl is-active docker)"
echo "  - Docker permissions: $(docker ps >/dev/null 2>&1 && echo "Working" || echo "Needs logout/login")"
echo "  - Local ZAP: $(command -v zaproxy >/dev/null 2>&1 && echo "Available" || echo "Not installed")"
echo ""
echo "🚀 You can now run GooberScan with full Docker support!"
