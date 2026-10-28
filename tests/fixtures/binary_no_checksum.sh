#!/bin/bash
set -euo pipefail

url="https://releases.example.com/tool/v1.2.3/tool-linux-amd64"
curl -fsSL -o /tmp/tool "$url"
chmod +x /tmp/tool
sudo mv /tmp/tool /usr/local/bin/tool
