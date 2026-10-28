#!/bin/bash
set -euo pipefail

curl -fsSL -o /tmp/tool.tar.gz http://downloads.example.com/tool.tar.gz
tar -xzf /tmp/tool.tar.gz -C /tmp
