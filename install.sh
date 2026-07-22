#!/bin/bash
# ============================================
# PROJECT PROMETHEUS - Kali Linux Setup
# Smart installer: checks version, installs only if missing/outdated
# ============================================
# Run: chmod +x install.sh && sudo ./install.sh
# ============================================

set -e

RED='\033[0;31m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "============================================"
echo "  PROJECT PROMETHEUS - Smart Setup"
echo "============================================"
echo -e "${NC}"

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[!] Run as root: sudo ./install.sh${NC}"
    exit 1
fi

# Add Go to PATH
export PATH=$PATH:/usr/local/go/bin:~/go/bin

# ========== HELPER FUNCTIONS ==========

get_installed_version() {
    local tool=$1
    case $tool in
        nuclei)     nuclei -version 2>&1 | grep -oP 'v[\d.]+' | head -1 ;;
        subfinder)  subfinder -version 2>&1 | grep -oP 'v[\d.]+' | head -1 ;;
        httpx)      httpx -version 2>&1 | grep -oP 'v[\d.]+' | head -1 ;;
        naabu)      naabu -version 2>&1 | grep -oP 'v[\d.]+' | head -1 ;;
        katana)     katana -version 2>&1 | grep -oP 'v[\d.]+' | head -1 ;;
        gau)        gau --version 2>&1 | grep -oP 'v[\d.]+' | head -1 ;;
        ffuf)       ffuf -V 2>&1 | grep -oP 'v[\d.]+' | head -1 ;;
        *)          echo "unknown" ;;
    esac
}

install_tool() {
    local tool=$1
    local repo=$2
    local name=$3

    if command -v $tool &> /dev/null; then
        local installed_ver=$(get_installed_version $tool)
        echo -e "  ${GREEN}[INSTALLED]${NC} $name ($installed_ver)"
        echo -e "  ${YELLOW}[UPDATE]${NC} $name - updating to latest..."
        go install $repo@latest 2>/dev/null && \
            echo -e "  ${GREEN}[UPDATED]${NC} $name" || \
            echo -e "  ${YELLOW}[SKIP]${NC} $name update failed (keeping current)"
    else
        echo -e "  ${YELLOW}[NEW]${NC} $name - installing..."
        go install $repo@latest 2>/dev/null && \
            echo -e "  ${GREEN}[INSTALLED]${NC} $name" || \
            echo -e "  ${RED}[FAIL]${NC} $name installation failed"
    fi
}

# ========== STEP 1: SYSTEM ==========
echo -e "${YELLOW}[1/6] Updating system packages...${NC}"
apt update -y 2>/dev/null
apt install -y python3 python3-pip python3-venv wget curl 2>/dev/null

# ========== STEP 2: GO ==========
echo -e "${YELLOW}[2/6] Checking Go...${NC}"
if command -v go &> /dev/null; then
    GO_VER=$(go version | grep -oP 'go[\d.]+')
    echo -e "  ${GREEN}[INSTALLED]${NC} Go $GO_VER"
else
    echo -e "  ${YELLOW}[NEW]${NC} Installing Go..."
    wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz
    tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin:~/go/bin' >> /etc/profile
    rm /tmp/go.tar.gz
    echo -e "  ${GREEN}[INSTALLED]${NC} Go"
fi

# ========== STEP 3: BUG BOUNTY TOOLS ==========
echo -e "${YELLOW}[3/6] Checking bug bounty tools...${NC}"

install_tool "nuclei"     "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"     "Nuclei (vuln scanner)"
install_tool "subfinder"  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder" "Subfinder (subdomain enum)"
install_tool "httpx"      "github.com/projectdiscovery/httpx/cmd/httpx"           "httpx (HTTP probe)"
install_tool "naabu"      "github.com/projectdiscovery/naabu/v2/cmd/naabu"        "Naabu (port scanner)"
install_tool "katana"     "github.com/projectdiscovery/katana/cmd/katana"         "Katana (web crawler)"
install_tool "gau"        "github.com/lc/gau/v2/cmd/gau"                          "gau (get all URLs)"
install_tool "ffuf"       "github.com/ffuf/ffuf/v2"                               "ffuf (fuzzing)"
install_tool "assetfinder" "github.com/tomnomnom/assetfinder"                     "Assetfinder (subdomains)"
go install github.com/tomnomnom/waybackurls@latest 2>/dev/null && \
    echo -e "  ${GREEN}[INSTALLED]${NC} Waybackurls" || true

# Update nuclei templates
if command -v nuclei &> /dev/null; then
    echo -e "${YELLOW}[4/6] Updating Nuclei templates...${NC}"
    nuclei -update-templates 2>/dev/null || echo -e "  ${YELLOW}[SKIP]${NC} Template update failed"
fi

# ========== STEP 5: PYTHON VENV ==========
echo -e "${YELLOW}[5/6] Setting up Python environment...${NC}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d "venv" ]; then
    python3 -m venv venv
    echo -e "  ${GREEN}[CREATED]${NC} Virtual environment"
else
    echo -e "  ${GREEN}[EXISTS]${NC} Virtual environment"
fi

source venv/bin/activate
pip install -r requirements.txt -q 2>/dev/null
echo -e "  ${GREEN}[OK]${NC} Python packages installed"

# ========== STEP 6: VERIFY ==========
echo -e "${YELLOW}[6/6] Verification...${NC}"
echo ""

check_tool_full() {
    local tool=$1
    local name=$2
    if command -v $tool &> /dev/null; then
        local ver=$(get_installed_version $tool)
        echo -e "  ${GREEN}[OK]${NC} $name $ver"
    else
        echo -e "  ${RED}[MISSING]${NC} $name"
    fi
}

check_tool_full nuclei "Nuclei"
check_tool_full subfinder "Subfinder"
check_tool_full httpx "httpx"
check_tool_full naabu "Naabu"
check_tool_full katana "Katana"
check_tool_full gau "gau"
check_tool_full ffuf "ffuf"
check_tool_full assetfinder "Assetfinder"

echo ""
echo -e "${GREEN}============================================"
echo "  SETUP COMPLETE!"
echo "============================================${NC}"
echo ""
echo -e "Run:"
echo -e "  cd $SCRIPT_DIR"
echo -e "  source venv/bin/activate"
echo -e "  python -m src.main"
echo ""
echo -e "Inside Prometheus, type ${CYAN}tools${NC} to check status anytime."
echo ""
