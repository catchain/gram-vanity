// CPU emulation of the few CUDA runtime calls worker.cu uses. Tests only (tests/run_emu.sh):
// it runs the real worker control flow and core.h on the CPU, one "thread" at a time.
#pragma once
#include <cstddef>
#include <cstdlib>
#include <cstring>
typedef int cudaError_t;
enum { cudaSuccess = 0, cudaMemcpyHostToDevice = 1, cudaMemcpyDeviceToHost = 2 };
struct cudaDeviceProp { char name[256]; int multiProcessorCount; };
inline const char *cudaGetErrorString(cudaError_t) { return ""; }
inline cudaError_t cudaSetDevice(int) { return 0; }
inline cudaError_t cudaGetDeviceCount(int *n) { *n = 1; return 0; }
inline cudaError_t cudaGetDeviceProperties(cudaDeviceProp *p, int) { strcpy(p->name, "CPU-emulated"); p->multiProcessorCount = 1; return 0; }
template <class T> cudaError_t cudaMalloc(T **p, size_t n) { *p = (T *)malloc(n); return 0; }
inline cudaError_t cudaFree(void *p) { free(p); return 0; }
inline cudaError_t cudaMemcpy(void *d, const void *s, size_t n, int) { memcpy(d, s, n); return 0; }
inline cudaError_t cudaMemset(void *d, int v, size_t n) { memset(d, v, n); return 0; }
inline cudaError_t cudaGetLastError() { return 0; }
struct dim3_ { unsigned x; };
static thread_local dim3_ blockIdx, threadIdx, blockDim;
inline unsigned atomicCAS(unsigned *a, unsigned c, unsigned v) { unsigned e = c; __atomic_compare_exchange_n(a, &e, v, false, __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST); return e; }
inline void __threadfence() {}
#define __global__
#define __device__
#define __forceinline__ inline
#define __restrict__
#define LAUNCH(B, T, K, ...) do { blockDim.x = (T); for (unsigned b_ = 0; b_ < (unsigned)(B); b_++) { blockIdx.x = b_; \
  for (unsigned t_ = 0; t_ < (unsigned)(T); t_++) { threadIdx.x = t_; K(__VA_ARGS__); } } } while (0)
