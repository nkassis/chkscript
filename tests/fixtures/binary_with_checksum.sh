#!/bin/bash
set -euo pipefail

url="https://releases.example.com/tool/v1.2.3/tool-linux-amd64"
expected="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
curl -fsSL -o /tmp/tool "$url"
echo "${expected}  /tmp/tool" | sha256sum --check --status
chmod +x /tmp/tool
sudo mv /tmp/tool /usr/local/bin/tool
