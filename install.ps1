# ============================================================
# Prometheus — Windows One-Click Installer
# ============================================================
# Usage: powershell -ExecutionPolicy Bypass -c "iwr https://raw.githubusercontent.com/mysterious75/prometheus/main/install.ps1 | iex"
# ============================================================

$ErrorActionPreference = "Continue"
$PROMETHEUS_DIR = "$env:USERPROFILE\.prometheus"

Write-Host ""
Write-Host "    ██████╗ ██████╗  ██████╗ ███╗   ███╗███████╗████████╗██╗  ██╗███████╗██╗   ██╗███████╗" -ForegroundColor Red
Write-Host "    ██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔════╝╚══██╔══╝██║  ██║██╔════╝██║   ██║██╔════╝" -ForegroundColor Red
Write-Host "    ██████╔╝██████╔╝██║   ██║██╔████╔██║█████╗     ██║   ███████║█████╗  ██║   ██║███████╗" -ForegroundColor Red
Write-Host "    ██╔═══╝ ██╔══██╗██║   ██║██║╚██╔╝██║██╔══╝     ██║   ██╔══██║██╔══╝  ██║   ██║╚════██║" -ForegroundColor Red
Write-Host "    ██║     ██║  ██║╚██████╔╝██║ ╚═╝ ██║███████╗   ██║   ██║  ██║███████╗╚██████╔╝███████║" -ForegroundColor Red
Write-Host "    ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚══════╝" -ForegroundColor Red
Write-Host ""
Write-Host "    v3.0 — Windows Installer" -ForegroundColor Cyan
Write-Host ""

# Check Python
Write-Host "[1/6] Checking Python..." -ForegroundColor Yellow
$pythonCmd = $null
foreach ($cmd in @("python3.12", "python3.11", "python3.10", "python3", "python")) {
    $version = & $cmd --version 2>&1
    if ($version -match "3\.(\d+)") {
        $pythonCmd = $cmd
        Write-Host "  OK: $version" -ForegroundColor Green
        break
    }
}

if (-not $pythonCmd) {
    Write-Host "  Python 3.10+ not found. Installing..." -ForegroundColor Red
    winget install Python.Python.3.12 --silent
    $pythonCmd = "python"
}

# Clone or update
Write-Host "[2/6] Setting up Prometheus..." -ForegroundColor Yellow
if (Test-Path $PROMETHEUS_DIR) {
    Write-Host "  Updating existing installation..." -ForegroundColor Gray
    Set-Location $PROMETHEUS_DIR
    git pull --quiet 2>$null
} else {
    Write-Host "  Cloning to $PROMETHEUS_DIR..." -ForegroundColor Gray
    git clone --quiet https://github.com/mysterious75/prometheus.git $PROMETHEUS_DIR
}
Set-Location $PROMETHEUS_DIR
Write-Host "  OK" -ForegroundColor Green

# Create venv
Write-Host "[3/6] Setting up Python environment..." -ForegroundColor Yellow
if (-not (Test-Path "$PROMETHEUS_DIR\venv")) {
    & $pythonCmd -m venv "$PROMETHEUS_DIR\venv"
}
& "$PROMETHEUS_DIR\venv\Scripts\pip.exe" install --quiet --upgrade pip 2>$null
Write-Host "  OK" -ForegroundColor Green

# Install dependencies
Write-Host "[4/6] Installing dependencies..." -ForegroundColor Yellow
& "$PROMETHEUS_DIR\venv\Scripts\pip.exe" install --quiet -r requirements.txt 2>$null
Write-Host "  OK" -ForegroundColor Green

# Install external tools
Write-Host "[5/6] Checking external tools..." -ForegroundColor Yellow
$tools = @("nuclei", "subfinder", "httpx", "nmap", "sqlmap")
foreach ($tool in $tools) {
    $found = Get-Command $tool -ErrorAction SilentlyContinue
    if ($found) {
        Write-Host "  OK: $tool" -ForegroundColor Green
    } else {
        Write-Host "  FALLBACK: $tool (will use Python fallback)" -ForegroundColor Gray
    }
}

# Create launcher
Write-Host "[6/6] Creating launcher..." -ForegroundColor Yellow
$launcherContent = @"
@echo off
cd /d "$PROMETHEUS_DIR"
call venv\Scripts\activate.bat
python -m src.entry %*
"@
$launcherContent | Out-File -FilePath "$PROMETHEUS_DIR\prometheus.bat" -Encoding ASCII

# Add to PATH
$currentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($currentPath -notlike "*$PROMETHEUS_DIR*") {
    [Environment]::SetEnvironmentVariable("Path", "$currentPath;$PROMETHEUS_DIR", "User")
    Write-Host "  Added to PATH" -ForegroundColor Green
}

# Create .env
if (-not (Test-Path "$PROMETHEUS_DIR\.env")) {
    Copy-Item "$PROMETHEUS_DIR\.env.example" "$PROMETHEUS_DIR\.env"
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Green
Write-Host "  Prometheus installed successfully!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Location: $PROMETHEUS_DIR" -ForegroundColor White
Write-Host "  Command:  prometheus" -ForegroundColor White
Write-Host ""
Write-Host "  Quick Start:" -ForegroundColor White
Write-Host "    prometheus                          " -ForegroundColor Cyan -NoNewline; Write-Host "# Interactive CLI"
Write-Host "    prometheus scan example.com          " -ForegroundColor Cyan -NoNewline; Write-Host "# Direct scan"
Write-Host "    prometheus --help                   " -ForegroundColor Cyan -NoNewline; Write-Host "# Show help"
Write-Host ""
Write-Host "  First Time:" -ForegroundColor White
Write-Host "    1. Edit $PROMETHEUS_DIR\.env — add API keys" -ForegroundColor Gray
Write-Host "    2. Run: prometheus" -ForegroundColor Gray
Write-Host "    3. Type: authorize example.com" -ForegroundColor Gray
Write-Host "    4. Type: scan example.com" -ForegroundColor Gray
Write-Host ""
