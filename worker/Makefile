# GPU worker. Needs the CUDA toolkit (nvcc). ARCH: native (CUDA >= 11.6), or e.g. sm_89 (RTX 40xx), sm_86 (RTX 30xx), sm_80 (A100), sm_90 (H100).
NVCC ?= nvcc
ARCH ?= native
NVFLAGS ?= -O3 -std=c++17 -arch=$(ARCH) -Xptxas -O3 -lineinfo

vanity-worker: worker.cu host_core.cpp core.h bip39_en.h ed25519/*.c ed25519/*.h
	$(NVCC) $(NVFLAGS) -o $@ worker.cu host_core.cpp

# CPU-only checks (no GPU): vectors, C vs Rust, emulated worker run.
test:
	./tests/run_emu.sh

clean:
	rm -f vanity-worker

.PHONY: test clean
