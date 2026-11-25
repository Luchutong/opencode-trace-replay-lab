#!/usr/bin/env bash
set -eu
cd -- "$(dirname -- "$0")"
npm install --prefix .runtime --ignore-scripts --no-audit --no-fund --save-exact opencode-linux-x64@1.19.6
.runtime/node_modules/opencode-linux-x64/bin/opencode --version
