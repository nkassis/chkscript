#!/bin/bash
set -euo pipefail

# The vendor key is trusted for every repository on the machine.
curl -fsSL https://packages.example.com/gpg.key | sudo apt-key add -
echo "deb https://packages.example.com/apt stable main" \
    | sudo tee /etc/apt/sources.list.d/example.list
sudo apt-get update
sudo apt-get install -y example-tool
