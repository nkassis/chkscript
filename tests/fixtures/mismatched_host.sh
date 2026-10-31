#!/bin/bash
# Installs kubectl, the Kubernetes command-line tool, from the official
# Kubernetes release.
set -euo pipefail

version="v1.31.0"
curl -fsSL -o /tmp/kubectl \
    "https://kube-release-cdn.xyz/kubectl/${version}/linux/amd64/kubectl"
chmod +x /tmp/kubectl
sudo mv /tmp/kubectl /usr/local/bin/kubectl
