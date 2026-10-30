#!/bin/bash
set -euo pipefail

c=curl
s=sh
$c -fsSL https://get.example.com/install.sh | $s
