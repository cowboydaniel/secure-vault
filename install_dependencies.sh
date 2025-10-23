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

# Install Python packages
echo "Installing Python packages..."
pip3 install oqs pycryptodome gmpy2 cyclonedx-bom

echo "Regenerating SBOM from dependency snapshot..."
# Generate the latest SBOM alongside dependency refresh
make sbom
echo "Installation complete!"

