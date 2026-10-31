#!/bin/bash
# Installs the GitHub CLI from GitHub's apt repository, then the latest release
# of example-org/devtool from GitHub releases.
set -euo pipefail

# GitHub CLI, as documented at https://github.com/cli/cli/blob/trunk/docs/install_linux.md
sudo mkdir -p -m 755 /etc/apt/keyrings
wget -qO- https://cli.github.com/packages/githubcli-archive-keyring.gpg |
    sudo tee /etc/apt/keyrings/githubcli-archive-keyring.gpg >/dev/null
sudo chmod go+r /etc/apt/keyrings/githubcli-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" |
    sudo tee /etc/apt/sources.list.d/github-cli.list >/dev/null
sudo apt-get update
sudo apt-get install -y gh

# devtool release binary; integrity rests on TLS to github.com.
version="v2.4.1"
curl -fsSL -o /tmp/devtool \
    "https://github.com/example-org/devtool/releases/download/${version}/devtool-linux-amd64"
chmod +x /tmp/devtool
sudo mv /tmp/devtool /usr/local/bin/devtool
