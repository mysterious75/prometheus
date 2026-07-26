#!/usr/bin/env bash
# ============================================================
# Prometheus — One-Click Installer
# ============================================================
# Usage: curl -sSL https://raw.githubusercontent.com/mysterious75/prometheus/main/install.sh | bash
# Or:    bash install.sh
#
# After install, run from ANY directory:
#   prometheus                    # Interactive CLI
#   prometheus scan example.com   # Direct scan
#   prometheus --help             # Show help
# ============================================================

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

PROMETHEUS_DIR="${PROMETHEUS_DIR:-$HOME/.prometheus}"
INSTALL_DIR="/usr/local/bin"
PYTHON_MIN_VERSION="3.10"

# ============================================================
# Helper functions
# ============================================================
log_info()  { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()    { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "\n${CYAN}${BOLD}▸ $1${NC}"; }

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

version_ge() {
    [ "$(printf '%s\n' "$1" "$2" | sort -V | head -n1)" = "$2" ]
}

# ============================================================
# Banner
# ============================================================
echo -e "${RED}${BOLD}"
echo "    ██████╗ ██████╗  ██████╗ ███╗   ███╗███████╗████████╗██╗  ██╗███████╗██╗   ██╗███████╗"
echo "    ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔════╝╚══██╔══╝██║  ██║██╔════╝██║   ██║██╔════╝"
echo "    ██████╔╝██████╔╝██║   ██║██╔████╔██║█████╗     ██║   ███████║█████╗  ██║   ██║███████╗"
echo "    ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██╔══╝  ██║   ██║╚════██║"
echo "    ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ██║  ██║███████╗╚██████╔╝███████║"
echo "    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝"
echo -e "${NC}"
echo -e "${CYAN}    v3.0 — AI-Powered Autonomous Security Testing Platform${NC}"
echo -e "${DIM}    One-click installer — sets up everything automatically${NC}"
echo ""

# ============================================================
# Step 1: Check Python
# ============================================================
log_step "Checking Python..."

PYTHON_CMD=""
for cmd in python3.12 python3.11 python3.10 python3 python; do
    if command_exists "$cmd"; then
        version=$("$cmd" --version 2>&1 | grep -oP '\d+\.\d+\.\d+' | head -1)
        if version_ge "$version" "$PYTHON_MIN_VERSION"; then
            PYTHON_CMD="$cmd"
            break
        fi
    fi
done

if [ -z "$PYTHON_CMD" ]; then
    log_error "Python $PYTHON_MIN_VERSION+ not found!"
    log_info "Installing Python..."
    
    # Detect OS and install
    if command_exists apt-get; then
        sudo apt-get update -qq
        sudo apt-get install -y -qq python3 python3-pip python3-venv
    elif command_exists yum; then
        sudo yum install -y python3 python3-pip
    elif command_exists brew; then
        brew install python@3.12
    elif command_exists pacman; then
        sudo pacman -S --noconfirm python python-pip
    else
        log_error "Cannot auto-install Python. Please install Python $PYTHON_MIN_VERSION+ manually."
        exit 1
    fi
    
    PYTHON_CMD="python3"
fi

PY_VERSION=$("$PYTHON_CMD" --version 2>&1 | grep -oP '\d+\.\d+\.\d+')
log_ok "Python $PY_VERSION found ($PYTHON_CMD)"

# ============================================================
# Step 2: Clone or update Prometheus
# ============================================================
log_step "Setting up Prometheus..."

if [ -d "$PROMETHEUS_DIR" ]; then
    log_info "Existing installation found at $PROMETHEUS_DIR"
    log_info "Updating..."
    cd "$PROMETHEUS_DIR"
    git pull --quiet 2>/dev/null || log_warn "Could not update (not a git repo)"
else
    log_info "Cloning Prometheus to $PROMETHEUS_DIR..."
    git clone --quiet https://github.com/mysterious75/prometheus.git "$PROMETHEUS_DIR"
fi

cd "$PROMETHEUS_DIR"
log_ok "Prometheus source ready at $PROMETHEUS_DIR"

# ============================================================
# Step 3: Create virtual environment
# ============================================================
log_step "Setting up Python environment..."

if [ ! -d "$PROMETHEUS_DIR/venv" ]; then
    $PYTHON_CMD -m venv "$PROMETHEUS_DIR/venv"
    log_ok "Virtual environment created"
else
    log_ok "Virtual environment exists"
fi

# Activate
source "$PROMETHEUS_DIR/venv/bin/activate"

# Upgrade pip
pip install --quiet --upgrade pip 2>/dev/null

# ============================================================
# Step 4: Install Python dependencies
# ============================================================
log_step "Installing Python dependencies..."

pip install --quiet -r requirements.txt 2>/dev/null && log_ok "Python dependencies installed" || {
    log_warn "Some dependencies failed, trying with --no-deps..."
    pip install --quiet --no-deps -r requirements.txt 2>/dev/null
}

# ============================================================
# Step 5: Install external security tools (optional but recommended)
# ============================================================
log_step "Installing external security tools..."

install_go_tool() {
    local tool_name=$1
    local tool_path=$2
    
    if command_exists "$tool_name"; then
        log_ok "$tool_name already installed"
        return
    fi
    
    if command_exists go; then
        log_info "Installing $tool_name via Go..."
        go install -v "$tool_path@latest" 2>/dev/null && log_ok "$tool_name installed" || log_warn "Failed to install $tool_name"
    else
        log_warn "Go not found — $tool_name will use Python fallback"
    fi
}

# Nuclei — template-based vulnerability scanner (12,000+ templates)
install_go_tool "nuclei" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"

# Subfinder — passive subdomain enumeration (40+ sources)
install_go_tool "subfinder" "github.com/projectdiscovery/subfinder/v2/cmd/subfinder"

# httpx — HTTP probing and analysis
install_go_tool "httpx" "github.com/projectdiscovery/httpx/cmd/httpx"

# Nmap — port scanning (install via package manager)
if command_exists nmap; then
    log_ok "nmap already installed"
else
    log_info "Installing nmap..."
    if command_exists apt-get; then
        sudo apt-get install -y -qq nmap 2>/dev/null && log_ok "nmap installed" || log_warn "Could not install nmap"
    elif command_exists yum; then
        sudo yum install -y nmap 2>/dev/null && log_ok "nmap installed" || log_warn "Could not install nmap"
    elif command_exists brew; then
        brew install nmap 2>/dev/null && log_ok "nmap installed" || log_warn "Could not install nmap"
    elif command_exists pacman; then
        sudo pacman -S --noconfirm nmap 2>/dev/null && log_ok "nmap installed" || log_warn "Could not install nmap"
    else
        log_warn "Cannot auto-install nmap — will use Python fallback"
    fi
fi

# SQLMap — SQL injection tool
if command_exists sqlmap; then
    log_ok "sqlmap already installed"
else
    log_info "Installing sqlmap..."
    pip install --quiet sqlmap 2>/dev/null && log_ok "sqlmap installed" || log_warn "Could not install sqlmap"
fi

# Sherlock — username search (400+ platforms)
if command_exists sherlock; then
    log_ok "sherlock already installed"
else
    log_info "Installing sherlock..."
    pip install --quiet sherlock-project 2>/dev/null && log_ok "sherlock installed" || log_warn "Could not install sherlock"
fi

# ============================================================
# Step 6: Download Nuclei templates (if nuclei installed)
# ============================================================
if command_exists nuclei; then
    log_step "Downloading Nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null && log_ok "Nuclei templates updated" || log_warn "Could not update templates"
fi

# ============================================================
# Step 7: Create global command
# ============================================================
log_step "Setting up global 'prometheus' command..."

# Create wrapper script
cat > "$PROMETHEUS_DIR/prometheus" << 'WRAPPER'
#!/usr/bin/env bash
# Prometheus CLI wrapper — works from any directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/venv/bin/activate"
cd "$SCRIPT_DIR"
python3 -m src.entry "$@"
WRAPPER

chmod +x "$PROMETHEUS_DIR/prometheus"

# Symlink to /usr/local/bin (requires sudo)
if [ -w "$INSTALL_DIR" ]; then
    ln -sf "$PROMETHEUS_DIR/prometheus" "$INSTALL_DIR/prometheus" 2>/dev/null && log_ok "Global command created: prometheus" || {
        # Try with sudo
        sudo ln -sf "$PROMETHEUS_DIR/prometheus" "$INSTALL_DIR/prometheus" 2>/dev/null && log_ok "Global command created: prometheus" || {
            log_warn "Could not create global command — add to PATH manually:"
            log_warn "  export PATH=\"$PROMETHEUS_DIR:\$PATH\""
        }
    }
else
    sudo ln -sf "$PROMETHEUS_DIR/prometheus" "$INSTALL_DIR/prometheus" 2>/dev/null && log_ok "Global command created: prometheus" || {
        log_warn "Could not create global command — add to PATH manually:"
        log_warn "  export PATH=\"$PROMETHEUS_DIR:\$PATH\""
    }
fi

# Also add to PATH in shell profile
SHELL_RC=""
if [ -f "$HOME/.bashrc" ]; then
    SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.zshrc" ]; then
    SHELL_RC="$HOME/.zshrc"
fi

if [ -n "$SHELL_RC" ]; then
    if ! grep -q "PROMETHEUS_DIR" "$SHELL_RC" 2>/dev/null; then
        echo "" >> "$SHELL_RC"
        echo "# Prometheus Security Testing Platform" >> "$SHELL_RC"
        echo "export PROMETHEUS_DIR=\"$PROMETHEUS_DIR\"" >> "$SHELL_RC"
        echo "export PATH=\"\$PROMETHEUS_DIR:\$PATH\"" >> "$SHELL_RC"
        log_ok "Added to PATH in $SHELL_RC"
    fi
fi

# ============================================================
# Step 8: Create .env if not exists
# ============================================================
if [ ! -f "$PROMETHEUS_DIR/.env" ]; then
    cp "$PROMETHEUS_DIR/.env.example" "$PROMETHEUS_DIR/.env" 2>/dev/null
    log_ok "Created .env file (add API keys for AI-guided scanning)"
fi

# ============================================================
# Step 9: Verify installation
# ============================================================
log_step "Verifying installation..."

TOOLS_STATUS=""
for tool in nuclei subfinder httpx nmap sqlmap sherlock; do
    if command_exists "$tool"; then
        TOOLS_STATUS="$TOOLS_STATUS  ✓ $tool (binary)\n"
    else
        TOOLS_STATUS="$TOOLS_STATUS  ⚠ $tool (Python fallback)\n"
    fi
done

# ============================================================
# Done!
# ============================================================
echo ""
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}${BOLD}  ✅ Prometheus installed successfully!${NC}"
echo -e "${GREEN}${BOLD}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo -e "  ${BOLD}Location:${NC} $PROMETHEUS_DIR"
echo -e "  ${BOLD}Command:${NC}  prometheus"
echo ""
echo -e "  ${BOLD}Tool Status:${NC}"
echo -e "$TOOLS_STATUS"
echo -e "  ${BOLD}Quick Start:${NC}"
echo -e "    ${CYAN}prometheus${NC}                          # Interactive CLI"
echo -e "    ${CYAN}prometheus scan example.com${NC}          # Direct scan"
echo -e "    ${CYAN}prometheus --help${NC}                   # Show help"
echo ""
echo -e "  ${BOLD}First Time:${NC}"
echo -e "    1. Edit ${CYAN}~/.prometheus/.env${NC} — add at least one API key"
echo -e "    2. Run ${CYAN}prometheus${NC}"
echo -e "    3. Type ${CYAN}authorize example.com${NC}"
echo -e "    4. Type ${CYAN}scan example.com${NC}"
echo ""
echo -e "  ${BOLD}Note:${NC} Without API keys, Prometheus runs in offline mode"
echo -e "  (still fully functional for scanning)"
echo ""
echo -e "${DIM}  Source: https://github.com/mysterious75/prometheus${NC}"
echo ""
