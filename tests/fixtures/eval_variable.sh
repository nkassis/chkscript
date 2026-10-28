#!/bin/bash
set -euo pipefail

cmd="$(cat /etc/chkscript-demo/next-step)"
eval "$cmd"
