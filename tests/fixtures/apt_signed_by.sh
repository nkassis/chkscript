#!/bin/bash
set -euo pipefail

# The vendor key is pinned to this repository only (signed-by).
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://packages.example.com/gpg.key \
    | sudo gpg --dearmor -o /etc/apt/keyrings/example.gpg
echo "deb [signed-by=/etc/apt/keyrings/example.gpg] https://packages.example.com/apt stable main" \
    | sudo tee /etc/apt/sources.list.d/example.list
sudo apt-get update
sudo apt-get install -y example-tool
