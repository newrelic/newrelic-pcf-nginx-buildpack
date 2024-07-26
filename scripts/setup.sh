#!/bin/bash

# Function to compare version numbers
version_greater_or_equal() {
  printf '%s\n%s\n' "$2" "$1" | sort -V -C
}

# Check Go version
GO_VERSION=$(go version 2>/dev/null)
if [[ $? -ne 0 ]]; then
  echo "Go is not installed. Please install Go version 1.19 or higher."
  exit 1
fi

GO_VERSION_NUMBER=$(echo "$GO_VERSION" | awk '{print $3}' | sed 's/go//')
MIN_GO_VERSION="1.19"

if version_greater_or_equal "$GO_VERSION_NUMBER" "$MIN_GO_VERSION"; then
  echo "Go version $GO_VERSION_NUMBER is installed."
else
  echo "Go version 1.19 or higher is required. Please upgrade Go."
  exit 1
fi

# Install Tile Generator
echo "Installing Tile Generator..."
wget https://github.com/cf-platform-eng/tile-generator/releases/download/v15.1.1/tile_linux-64bit
sudo mv tile_linux-64bit /usr/local/bin/tile
sudo chmod +x /usr/local/bin/tile
echo "Tile Generator installed successfully."
tile --version

# Install BOSH CLI
echo "Installing BOSH CLI..."
wget https://github.com/cloudfoundry/bosh-cli/releases/download/v7.6.2/bosh-cli-7.6.2-linux-amd64
chmod +x bosh-cli-7.6.2-linux-amd64
sudo mv bosh-cli-7.6.2-linux-amd64 /usr/local/bin/bosh
echo "BOSH CLI installed successfully."
bosh --version

