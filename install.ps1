# ============================================
# PROJECT PROMETHEUS - Windows Setup (PowerShell)
# ============================================
# Run: .\install.ps1
# ============================================

$ErrorActionPreference = "Continue"

Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  PROJECT PROMETHEUS - Windows Setup" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""

# Check admin
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Run as Administrator for full setup" -ForegroundColor Yellow
    Write-Host "    Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
}

# Step 1: Check Python
Write-Host "[1/5] Checking Python..." -ForegroundColor Yellow
$python = Get-Command python -ErrorAction SilentlyContinue
if ($python) {
    $pyVer = python --version 2>&1
    Write-Host "  [OK] $pyVer" -ForegroundColor Green
} else {
    Write-Host "  [MISSING] Python not found!" -ForegroundColor Red
    Write-Host "  Install from: https://www.python.org/downloads/" -ForegroundColor Yellow
    Write-Host "  Make sure to check 'Add Python to PATH' during install" -ForegroundColor Yellow
}

# Step 2: Check Go
Write-Host "[2/5] Checking Go..." -ForegroundColor Yellow
$go = Get-Command go -ErrorAction SilentlyContinue
if ($go) {
    $goVer = go version 2>&1
    Write-Host "  [OK] $goVer" -ForegroundColor Green
} else {
    Write-Host "  [MISSING] Go not found!" -ForegroundColor Red
    Write-Host "  Install from: https://go.dev/dl/go1.22.0.windows-amd64.msi" -ForegroundColor Yellow
    Write-Host "  Or run: winget install GoLang.Go" -ForegroundColor Yellow
}

# Step 3: Setup Python venv
Write-Host "[3/5] Setting up Python environment..." -ForegroundColor Yellow
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

if (-not (Test-Path "venv")) {
    python -m venv venv
    Write-Host "  [CREATED] Virtual environment" -ForegroundColor Green
} else {
    Write-Host "  [EXISTS] Virtual environment" -ForegroundColor Green
}

& .\venv\Scripts\Activate.ps1
pip install -r requirements.txt -q 2>$null
Write-Host "  [OK] Python packages installed" -ForegroundColor Green

# Step 4: Check/Install Go tools
Write-Host "[4/5] Checking bug bounty tools..." -ForegroundColor Yellow

$tools = @(
    @{Name="nuclei"; Repo="github.com/projectdiscovery/nuclei/v3/cmd/nuclei"},
    @{Name="subfinder"; Repo="github.com/projectdiscovery/subfinder/v2/cmd/subfinder"},
    @{Name="httpx"; Repo="github.com/projectdiscovery/httpx/cmd/httpx"},
    @{Name="katana"; Repo="github.com/projectdiscovery/katana/cmd/katana"},
    @{Name="gau"; Repo="github.com/lc/gau/v2/cmd/gau"},
    @{Name="ffuf"; Repo="github.com/ffuf/ffuf/v2"}
)

foreach ($tool in $tools) {
    $cmd = Get-Command $tool.Name -ErrorAction SilentlyContinue
    if ($cmd) {
        Write-Host "  [OK] $($tool.Name)" -ForegroundColor Green
    } else {
        Write-Host "  [NEW] $($tool.Name) - installing..." -ForegroundColor Yellow
        if ($go) {
            go install "$($tool.Repo)@latest" 2>$null
            if ($LASTEXITCODE -eq 0) {
                Write-Host "  [INSTALLED] $($tool.Name)" -ForegroundColor Green
            } else {
                Write-Host "  [SKIP] $($tool.Name) - install failed (run: go install $($tool.Repo)@latest)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "  [SKIP] $($tool.Name) - Go not installed" -ForegroundColor Yellow
        }
    }
}

# Step 5: Verify
Write-Host "[5/5] Verification..." -ForegroundColor Yellow
Write-Host ""
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "  SETUP COMPLETE!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Run Prometheus:"
Write-Host "  cd $scriptDir"
Write-Host "  .\venv\Scripts\Activate.ps1"
Write-Host "  python -m src.main"
Write-Host ""
Write-Host "Inside Prometheus, type 'tools' to check status." -ForegroundColor Cyan
Write-Host ""
