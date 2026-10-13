#!/usr/bin/env bash
# CPU-only checks of the worker (no GPU needed):
#  1) core.h reference vectors, 2) 300 random candidates vs the Rust binary,
#  3) the real worker.cu control flow in CPU emulation, result confirmed by Rust.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(cd .. && pwd); BIN="$ROOT/target/release/gram-vanity"
[ -x "$BIN" ] || (cd "$ROOT" && cargo build --release)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
c++ -O2 -std=c++17 -Wno-unused-function -o "$T/test_host" tests/test_host.cpp
"$T/test_host" vectors
"$T/test_host" random 300 > "$T/c.txt"
cut -f1 "$T/c.txt" | "$BIN" debug-address > "$T/rust.txt"
cut -f2 "$T/c.txt" | cmp -s - "$T/rust.txt" && echo "300 random candidates: C == Rust" || { echo "MISMATCH C vs Rust"; exit 1; }
python3 - "$T" <<'PY'
import re, sys
s = open("worker.cu").read()
s = re.sub(r'(\w+)<<<([^,]+), ([^>]+)>>>\(([^;]*)\);', r'LAUNCH(\2, \3, \1, \4);', s)
open(sys.argv[1] + "/worker_emu.cpp", "w").write(s)
PY
c++ -O2 -std=c++17 -Wno-unused-function -Itests/cuda_emu -I. -o "$T/worker_emu" "$T/worker_emu.cpp" host_core.cpp
"$T/worker_emu" --suffix Ab --blocks 4 --threads 8 --per-thread 1 2>/dev/null > "$T/out.txt"
ADDR=$(sed -n 's/^address: //p' "$T/out.txt")
GOT=$(sed -n 's/^anchor:  //p' "$T/out.txt" | "$BIN" debug-address | cut -d' ' -f1)
[ "$ADDR" = "$GOT" ] && [ "${ADDR: -2}" = "Ab" ] && echo "emulated worker found $ADDR, Rust confirms" || { echo "worker emulation FAILED"; exit 1; }
echo "OK"
