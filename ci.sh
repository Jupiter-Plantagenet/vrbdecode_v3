#!/usr/bin/env bash
set -euo pipefail
export PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
python -m pytest -q
cargo test --quiet

if [[ "${VRBDECODE_CI_SLOW:-0}" == "1" ]]; then
  cargo test -p vrbdecode-zk --test groth16_smoke -- --ignored
  cargo test -p vrbdecode-zk --test r1cs_vectors -- --ignored
fi
