#!/bin/sh
# Full check for the Acta Rust core: unit and property tests, the
# conformance runner against the Python prototype fixtures, clippy
# with the workspace float ban, and the no-float grep gate.
#
# Author: Gavin Blacklock
#
# Usage, from this directory: ./run_tests.sh
# Exit code 0 means every gate is green.
# Note: cargo is installed under ~/.cargo/bin on the build machine,
# which is not always on PATH for non-login shells.
set -e
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")"

echo "== cargo test =="
cargo test --workspace --offline

echo "== conformance against the Python prototype fixtures =="
cargo run --quiet --offline --bin conformance -- \
    ../code/fixtures ../code/fixtures/test_secret.txt

echo "== clippy (workspace lints deny float arithmetic) =="
cargo clippy --workspace --all-targets --offline -- -D warnings

echo "== grep gate: no float types in the core crates =="
if grep -rnE '\bf(32|64)\b' crates/acta-core/src crates/acta-core/tests crates/institutio-core/src crates/institutio-core/tests; then
    echo "FAIL: floating point type found in a core crate"
    exit 1
fi
echo "no float types in acta-core or institutio-core"

echo "== grep gate: no HashMap in the core crates =="
if grep -rn 'HashMap' crates/acta-core/src crates/institutio-core/src crates/institutio-core/tests; then
    echo "FAIL: HashMap found in a core crate (BTreeMap only, rule D5)"
    exit 1
fi
echo "no HashMap in acta-core or institutio-core"

echo "OVERALL: GREEN"
