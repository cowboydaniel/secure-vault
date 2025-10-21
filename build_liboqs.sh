#!/bin/bash
# Build and install liboqs for ML-KEM support

echo "Building liboqs for ML-KEM-1024 support..."

# Install dependencies
sudo apt-get update
sudo apt-get install -y build-essential cmake ninja-build libssl-dev python3-dev

# Clone liboqs
git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
cd liboqs

# Build liboqs
mkdir build && cd build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=/usr/local ..
ninja
sudo ninja install

# Install Python wrapper
cd ..
pip3 install liboqs-python

echo "liboqs installation complete!"
echo "Restart your application to use real ML-KEM-1024."
