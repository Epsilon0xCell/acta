#!/bin/sh
# Every gate for the Go second implementation, one command:
# build, go vet, Go unit tests, the 34-fixture conformance run,
# the Python differential and repair-round oracle suites, the
# three-way differential, and the em dash scan. Ends with an
# explicit OVERALL verdict line.
#
# Author: Gavin Blacklock
set -u
cd "$(dirname "$0")"
ROOT="$PWD"
FAIL=0

# Locate a Go toolchain: PATH first, then the workspace toolchains.
if command -v go >/dev/null 2>&1; then
  GO=go
elif [ -x "$HOME/workspace/tools/go1.23.4/bin/go" ]; then
  GO="$HOME/workspace/tools/go1.23.4/bin/go"
  export GOCACHE="${GOCACHE:-$HOME/workspace/tools/gocache}"
elif [ -x "$HOME/workspace/tools/go/bin/go" ]; then
  GO="$HOME/workspace/tools/go/bin/go"
else
  echo "FAIL: no Go toolchain found on PATH or under ~/workspace/tools"
  echo "OVERALL: FAIL"
  exit 1
fi
echo "toolchain: $($GO version)"

step() {
  name="$1"; shift
  echo ""
  echo "== $name"
  if "$@"; then
    echo "-- $name: PASS"
  else
    echo "-- $name: FAIL"
    FAIL=1
  fi
}

mkdir -p bin
step "build" $GO build -o bin/acta-verify ./cmd/acta-verify
if [ "$FAIL" = 0 ]; then
  $GO build -o bin/conformance ./cmd/conformance || FAIL=1
fi
step "go vet" $GO vet ./...
step "go tests" $GO test ./...
step "conformance (34 fixtures)" ./bin/conformance ../code/fixtures ../code/fixtures/test_secret.txt

# The Python differential and repair-round suites are the
# Python-Rust oracle leg of the differential (they drive the Rust
# conformance runner through the Python harness).
echo ""
echo "== python oracle suites (differential, repair rounds 5 and 6)"
if (cd ../code && python3 -m unittest tests.test_differential tests.test_repair_round5 tests.test_repair_round6 2>&1 | tail -4); then
  echo "-- python oracle suites: PASS"
else
  echo "-- python oracle suites: FAIL"
  FAIL=1
fi

step "three-way differential" python3 tools/differential.py "$ROOT/bin/acta-verify"

echo ""
echo "== em dash scan"
if grep -rP '\x{2014}' . --exclude-dir=bin 2>/dev/null; then
  echo "-- em dash scan: FAIL (em dash found above)"
  FAIL=1
else
  echo "-- em dash scan: PASS (zero em dashes)"
fi

echo ""
if [ "$FAIL" = 0 ]; then
  echo "OVERALL: PASS"
else
  echo "OVERALL: FAIL"
  exit 1
fi
