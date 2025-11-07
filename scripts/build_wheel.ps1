# Build wheel for Aegis Seal (Windows PowerShell)
# Usage: .\scripts\build_wheel.ps1

$ErrorActionPreference = "Stop"

Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Aegis Seal - Build Wheel Script" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host ""

# Check Python version
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python version: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Error: Python not found. Please install Python 3.11 or higher." -ForegroundColor Red
    exit 1
}

# Check if we're in the right directory
if (-not (Test-Path "pyproject.toml")) {
    Write-Host "❌ Error: pyproject.toml not found. Run this script from the project root." -ForegroundColor Red
    exit 1
}

Write-Host "✓ Found pyproject.toml" -ForegroundColor Green

# Clean previous builds
Write-Host ""
Write-Host "Cleaning previous builds..." -ForegroundColor Yellow
Remove-Item -Path "dist" -Recurse -ErrorAction SilentlyContinue
Remove-Item -Path "build" -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "." -Filter "*.egg-info" -Recurse | Remove-Item -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path "src" -Filter "*.egg-info" -Recurse | Remove-Item -Recurse -ErrorAction SilentlyContinue
Write-Host "✓ Cleaned build artifacts" -ForegroundColor Green

# Install build dependencies
Write-Host ""
Write-Host "Installing build dependencies..." -ForegroundColor Yellow
python -m pip install --upgrade pip build twine
Write-Host "✓ Build dependencies installed" -ForegroundColor Green

# Build wheel
Write-Host ""
Write-Host "Building wheel..." -ForegroundColor Yellow
python -m build
Write-Host "✓ Wheel built successfully" -ForegroundColor Green

# List built artifacts
Write-Host ""
Write-Host "Built artifacts:" -ForegroundColor Cyan
Get-ChildItem -Path "dist" | Format-Table Name, Length, LastWriteTime
Write-Host ""

# Get wheel file
$wheelFile = Get-ChildItem -Path "dist" -Filter "*.whl" | Select-Object -First 1

if ($null -eq $wheelFile) {
    Write-Host "❌ Error: No wheel file found in dist/" -ForegroundColor Red
    exit 1
}

# Check package with twine
Write-Host ""
Write-Host "Checking package with twine..." -ForegroundColor Yellow
python -m twine check dist/*
Write-Host "✓ Package check passed" -ForegroundColor Green

# Display summary
Write-Host ""
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Build Summary" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Host "Wheel file: $($wheelFile.Name)" -ForegroundColor White
Write-Host "Size: $([math]::Round($wheelFile.Length / 1KB, 2)) KB" -ForegroundColor White
Write-Host ""
Write-Host "To install locally:" -ForegroundColor Yellow
Write-Host "  pip install dist\$($wheelFile.Name)" -ForegroundColor White
Write-Host ""
Write-Host "To upload to PyPI:" -ForegroundColor Yellow
Write-Host "  python -m twine upload dist\*" -ForegroundColor White
Write-Host ""
Write-Host "✅ Build completed successfully!" -ForegroundColor Green
