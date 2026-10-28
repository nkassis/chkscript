#!/bin/bash
# No set -e, unquoted variables, cd without a guard.
target=$1
cd $target
for f in $(ls *.conf); do
    echo Processing $f
done
