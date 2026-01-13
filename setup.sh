#!/bin/bash
# Real-Time Network IDS Setup Script for macOS (Apple Silicon)
# Run with: chmod +x setup.sh && ./setup.sh

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Real-Time Network Intrusion Detection System Setup          ║"
echo "║  Optimized for MacBook Air M1 (Apple Silicon)                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check if running on macOS
if [[ "$OSTYPE" != "darwin"* ]]; then
    echo -e "${RED}Error: This script is designed for macOS only.${NC}"
    exit 1
fi

# Check for Apple Silicon
ARCH=$(uname -m)
if [[ "$ARCH" != "arm64" ]]; then
    echo -e "${YELLOW}Warning: Not running on Apple Silicon. Performance may vary.${NC}"
fi

echo -e "${BLUE}[1/6] Checking Homebrew...${NC}"
if ! command -v brew &> /dev/null; then
    echo "Installing Homebrew..."
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
else
    echo -e "${GREEN}✓ Homebrew already installed${NC}"
fi

echo ""
echo -e "${BLUE}[2/6] Installing system dependencies...${NC}"
brew install libpcap || true
brew install argp-standalone || true
echo -e "${GREEN}✓ System dependencies installed${NC}"

echo ""
echo -e "${BLUE}[3/6] Setting up Python virtual environment...${NC}"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "${GREEN}✓ Virtual environment created${NC}"
else
    echo -e "${GREEN}✓ Virtual environment already exists${NC}"
fi

source venv/bin/activate

echo ""
echo -e "${BLUE}[4/6] Installing Python dependencies...${NC}"
pip install --upgrade pip
pip install -r requirements.txt
echo -e "${GREEN}✓ Python dependencies installed${NC}"

echo ""
echo -e "${BLUE}[5/6] Creating directory structure...${NC}"
mkdir -p models/pretrained
mkdir -p capture
mkdir -p alerts
mkdir -p dashboard
mkdir -p logs
mkdir -p tests

# Create __init__.py files
touch models/__init__.py
touch capture/__init__.py
touch alerts/__init__.py
touch dashboard/__init__.py
touch tests/__init__.py

echo -e "${GREEN}✓ Directory structure created${NC}"

echo ""
echo -e "${BLUE}[6/6] Setting up environment file...${NC}"
if [ ! -f ".env" ]; then
    cat > .env << 'EOF'
# Telegram Bot Configuration
# Get your bot token from @BotFather on Telegram
TELEGRAM_BOT_TOKEN=your_bot_token_here

# Get your chat ID by messaging @userinfobot on Telegram
TELEGRAM_CHAT_ID=your_chat_id_here

# Network Interface (default: en0 for WiFi)
IDS_INTERFACE=en0

# Anomaly Detection Threshold (0.0 - 1.0)
IDS_ANOMALY_THRESHOLD=0.5
EOF
    echo -e "${YELLOW}⚠ Created .env file - Please edit with your Telegram credentials${NC}"
else
    echo -e "${GREEN}✓ .env file already exists${NC}"
fi

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Setup Complete! 🎉                        ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Next steps:                                                 ║"
echo "║  1. Edit .env with your Telegram bot token and chat ID      ║"
echo "║  2. Activate venv: source venv/bin/activate                  ║"
echo "║  3. Run: sudo python main.py --interface en0                 ║"
echo "╚══════════════════════════════════════════════════════════════╝"
