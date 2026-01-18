$ErrorActionPreference = "Stop"
$env:PYTEST_DISABLE_PLUGIN_AUTOLOAD = "1"
python -m pytest -q
cargo test --quiet

if ($env:VRBDECODE_CI_SLOW -eq "1") {
    cargo test -p vrbdecode-zk --test groth16_smoke -- --ignored
    cargo test -p vrbdecode-zk --test r1cs_vectors -- --ignored
}
