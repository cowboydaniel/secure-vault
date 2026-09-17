#!/bin/bash

# Install system dependencies
echo "Installing system dependencies..."
sudo apt-get update
sudo apt-get install -y \
    build-essential \
    cmake \
    ninja-build \
    python3-dev \
    python3-pip

# Install liboqs and Python bindings
echo "Installing liboqs and Python bindings..."
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake -GNinja ..
ninja
sudo ninja install
sudo ldconfig
cd ../..

# Install the pinned command-line runtime. GUI, test, development, and
# platform-specific environments have separate composable requirement files.
echo "Installing Python runtime packages..."
pip3 install -r requirements.txt

echo "Regenerating SBOM from dependency snapshot..."
# Generate the latest SBOM alongside dependency refresh
make sbom
echo "Installation complete!"
