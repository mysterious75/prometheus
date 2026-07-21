#!/bin/bash
# ============================================
# PROJECT PROMETHEUS - Kali Linux Setup Script
# ============================================
# Run: chmod +x install.sh && ./install.sh
# ============================================

set -e

RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "============================================"
echo "  PROJECT PROMETHEUS - Kali Linux Setup"
echo "============================================"
echo -e "${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Run as root: sudo ./install.sh${NC}"
    exit 1
fi

echo -e "${YELLOW}[1/8] Updating system...${NC}"
apt update -y && apt upgrade -y

echo -e "${YELLOW}[2/8] Installing Python dependencies...${NC}"
apt install -y python3 python3-pip python3-venv

echo -e "${YELLOW}[3/8] Installing Go tools (bug bounty)...${NC}"
if ! command -v go &> /dev/null; then
    echo "  Installing Go..."
    wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    export PATH=$PATH:/usr/local/go/bin
    rm /tmp/go.tar.gz
fi
echo -e "  ${GREEN}Go: $(go version 2>/dev/null || echo 'installed')${NC}"

echo -e "${YELLOW}[4/8] Installing Nuclei (vulnerability scanner)...${NC}"
if ! command -v nuclei &> /dev/null; then
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    echo 'export PATH=$PATH:~/go/bin' >> /etc/profile
    export PATH=$PATH:~/go/bin
    nuclei -update-templates 2>/dev/null || true
fi
echo -e "  ${GREEN}Nuclei: $(nuclei -version 2>&1 | head -1)${NC}"

echo -e "${YELLOW}[5/8] Installing subfinder (subdomain enum)...${NC}"
if ! command -v subfinder &> /dev/null; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
fi
echo -e "  ${GREEN}Subfinder installed${NC}"

echo -e "${YELLOW}[6/8] Installing httpx (HTTP probing)...${NC}"
if ! command -v httpx &> /dev/null; then
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
fi
echo -e "  ${GREEN}httpx installed${NC}"

echo -e "${YELLOW}[7/8] Installing naabu (port scanner)...${NC}"
if ! command -v naabu &> /dev/null; then
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
fi
echo -e "  ${GREEN}naabu installed${NC}"

echo -e "${YELLOW}[8/8] Installing additional tools...${NC}"
# katana (web crawler)
if ! command -v katana &> /dev/null; then
    go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true
fi
# gau (get all urls)
if ! command -v gau &> /dev/null; then
    go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true
fi
# waybackurls
if ! command -v waybackurls &> /dev/null; then
    go install github.com/tomnomnom/waybackurls@latest 2>/dev/null || true
fi
# ffuf (fuzzing)
if ! command -v ffuf &> /dev/null; then
    go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || true
fi
# amass
if ! command -v amass &> /dev/null; then
    go install -v github.com/owasp-amass/amass/v4/...@master 2>/dev/null || true
fi
echo -e "  ${GREEN}Additional tools installed${NC}"

# Install Python venv
echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
echo -e "  ${GREEN}Python dependencies installed${NC}"

# Verify installation
echo ""
echo -e "${CYAN}============================================"
echo "  VERIFICATION"
echo "============================================${NC}"

check_tool() {
    if command -v $1 &> /dev/null; then
        echo -e "  ${GREEN}[OK]${NC} $1"
    else
        echo -e "  ${RED}[MISSING]${NC} $1"
    fi
}

check_tool nuclei
check_tool subfinder
check_tool httpx
check_tool naabu
check_tool katana
check_tool gau
check_tool waybackurls
check_tool ffuf
check_tool amass

echo ""
echo -e "${GREEN}============================================"
echo "  SETUP COMPLETE!"
echo "============================================${NC}"
echo ""
echo -e "Run Prometheus:"
echo -e "  cd $SCRIPT_DIR"
echo -e "  source venv/bin/activate"
echo -e "  python -m src.main"
echo ""
echo -e "Bug bounty tools are ready in Kali Linux!"
echo ""
