#!/bin/bash
set -euo pipefail

# Let the current user run docker without sudo: membership in the docker
# group is root in practice (root-equivalent-group).
sudo usermod -aG docker "$USER"

# Granting sudo is a different rule (rogue-account, NIM-110), not this one.
sudo usermod -aG sudo "$USER"
