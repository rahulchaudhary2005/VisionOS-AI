<#
Runs a complete local build & test flow for the VisionOS-AI backend.

Usage (from repo root):
  .\run-build.ps1

  .\run-build.ps1 -StartServer  //To run everything and start the dev server:


This script does the following:
  - creates or reuses a Python virtual environment in `.venv`
  - installs runtime requirements from `backend/requirements.txt`
  - installs dev tools: black, ruff, isort, pre-commit, pytest, pytest-cov, alembic, uvicorn
  - installs pre-commit hooks and runs them across the repo
  - sets a local SQLite database URL
  - applies Alembic migrations via `alembic upgrade head`
  - runs unit tests with coverage
  - optionally starts the FastAPI server
#>

param(
    [switch]$StartServer
)

$ErrorActionPreference = 'Stop'

function Write-Ok($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Info($msg) { Write-Host "[..] $msg" -ForegroundColor Cyan }
function Write-Err($msg) { Write-Host "[!!] $msg" -ForegroundColor Red }
function Assert-LastExitOk($msg) {
    if ($LASTEXITCODE -ne 0) {
        Write-Err $msg
        exit $LASTEXITCODE
    }
}

try {
    Write-Info "Checking repository structure..."
    if (-not (Test-Path -Path "./backend")) {
        Write-Err "This script must be run from the repository root (directory containing 'backend'). Aborting."
        exit 1
    }

    $Root = (Get-Location).Path
    $VENV = Join-Path $Root ".venv"
    $PY = Join-Path $VENV "Scripts\python.exe"

    if (-not (Test-Path $PY)) {
        Write-Info "Creating virtual environment at $VENV..."
        python -m venv $VENV
        Write-Ok "Virtual environment created."
    } else {
        Write-Info "Virtual environment already exists."
    }

    if (-not (Test-Path $PY)) {
        Write-Err "Python executable not found in $VENV. Ensure Python is installed and re-run."
        exit 1
    }

    Write-Info "Upgrading pip in venv..."
    & $PY -m pip install --upgrade pip setuptools wheel
    Assert-LastExitOk "Failed to upgrade pip in the virtual environment. Check network connectivity and proxy settings."
    Write-Ok "pip upgraded."

    Write-Info "Installing runtime requirements from backend/requirements.txt..."
    & $PY -m pip install -r backend/requirements.txt
    Assert-LastExitOk "Failed to install runtime requirements from backend/requirements.txt. Check network connectivity and package availability."
    Write-Ok "Runtime dependencies installed."

    Write-Info "Installing developer tools (black, ruff, isort, pre-commit, pytest, pytest-cov, alembic, uvicorn)..."
    & $PY -m pip install black ruff isort pre-commit pytest pytest-cov alembic uvicorn
    Assert-LastExitOk "Failed to install developer tools. Check network connectivity and package availability."
    Write-Ok "Dev tools installed."

    Write-Info "Installing pre-commit hooks..."
    pushd backend > $null
    & $PY -m pre_commit install
    popd > $null
    Write-Ok "pre-commit installed."

    Write-Info "Running pre-commit on all files (auto-fixes where configured)..."
    $attempt = 0
    $precommitExit = 1
    while ($attempt -lt 5) {
        & $PY -m pre_commit run --all-files
        $precommitExit = $LASTEXITCODE
        if ($precommitExit -eq 0) { break }
        $attempt++
        Write-Info "pre-commit modified files; re-running (attempt $attempt)..."
    }
    if ($precommitExit -ne 0) {
        Write-Err "pre-commit failed after multiple attempts. Inspect the repository and rerun the script."
        exit $precommitExit
    }
    Write-Ok "pre-commit completed."

    Write-Info "Configuring local SQLite database for migrations/tests..."
    $AbsBackend = (Resolve-Path "./backend").Path
    $DBFile = Join-Path $AbsBackend "visionos_local.db"
    if (Test-Path $DBFile) {
        Write-Info "Removing stale local DB at $DBFile"
        Remove-Item $DBFile -Force
    }
    foreach ($suffix in @("-shm", "-wal")) {
        $aux = "$DBFile$suffix"
        if (Test-Path $aux) {
            Remove-Item $aux -Force
        }
    }
    $DBFileForward = $DBFile -replace "\\","/"
    $env:DATABASE_URL = "sqlite:///$DBFileForward"
    Write-Ok "DATABASE_URL set to $env:DATABASE_URL"

    Write-Info "Applying Alembic migrations (upgrade head)..."
    pushd backend > $null
    & $PY -m alembic upgrade head
    popd > $null
    Write-Ok "Migrations applied."

    Write-Info "Running unit tests with coverage..."
    pushd backend > $null
    & $PY -m pytest --cov=app --cov-report=xml:coverage.xml tests/unit -q
    $testExit = $LASTEXITCODE
    popd > $null

    if ($testExit -ne 0) {
        Write-Err "Unit tests failed (exit code $testExit). Check output above."
        exit $testExit
    }

    Write-Ok "Unit tests passed. Coverage saved to backend/coverage.xml"

    if ($StartServer) {
        Write-Info "Starting development server on 127.0.0.1:8000..."
        pushd backend > $null
        & $PY -m uvicorn main:app --reload --host 127.0.0.1 --port 8000
        popd > $null
    } else {
        Write-Info "Build & test complete. To start the dev server run:"
        Write-Host "  $PY -m uvicorn main:app --reload --host 127.0.0.1 --port 8000" -ForegroundColor Yellow
    }

    Write-Ok "Flow finished successfully."
    exit 0
}
catch {
    Write-Err "An error occurred: $($_.Exception.Message)"
    if ($_.Exception.InnerException) { Write-Err "Inner: $($_.Exception.InnerException.Message)" }
    exit 1
}
