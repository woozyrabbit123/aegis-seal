#!/usr/bin/env bash
# Build wheel for Aegis Seal (Unix/Linux/macOS)
set -euo pipefail

echo "========================================="
echo "Aegis Seal - Build Wheel Script"
echo "========================================="
echo ""

# Check Python version
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
echo "✓ Python version: $PYTHON_VERSION"

# Check if we're in the right directory
if [ ! -f "pyproject.toml" ]; then
    echo "❌ Error: pyproject.toml not found. Run this script from the project root."
    exit 1
fi

echo "✓ Found pyproject.toml"

# Clean previous builds
echo ""
echo "Cleaning previous builds..."
rm -rf dist/ build/ *.egg-info src/*.egg-info
echo "✓ Cleaned build artifacts"

# Install build dependencies
echo ""
echo "Installing build dependencies..."
python3 -m pip install --upgrade pip build twine
echo "✓ Build dependencies installed"

# Build wheel
echo ""
echo "Building wheel..."
python3 -m build
echo "✓ Wheel built successfully"

# List built artifacts
echo ""
echo "Built artifacts:"
ls -lh dist/
echo ""

# Verify wheel contents
echo "Verifying wheel contents..."
WHEEL_FILE=$(ls dist/*.whl | head -n 1)
if command -v unzip &> /dev/null; then
    echo ""
    echo "Wheel contents:"
    unzip -l "$WHEEL_FILE" | grep -E "\.(py|yaml)$" | head -20
fi

# Check package with twine
echo ""
echo "Checking package with twine..."
python3 -m twine check dist/*
echo "✓ Package check passed"

# Display summary
echo ""
echo "========================================="
echo "Build Summary"
echo "========================================="
echo "Wheel file: $WHEEL_FILE"
echo "Size: $(du -h "$WHEEL_FILE" | cut -f1)"
echo ""
echo "To install locally:"
echo "  pip install $WHEEL_FILE"
echo ""
echo "To upload to PyPI:"
echo "  python3 -m twine upload dist/*"
echo ""
echo "✅ Build completed successfully!"
