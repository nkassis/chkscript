#!/bin/bash
set -euo pipefail

name="${1:-world}"
printf 'Hello, %s!\n' "$name"
