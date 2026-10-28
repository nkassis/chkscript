#!/bin/bash
set -euo pipefail

payload="ZWNobyBoZWxsbwo="
echo "$payload" | base64 -d | bash
