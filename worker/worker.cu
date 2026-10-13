// Gram Vanity GPU worker: searches a TG Wallet ANCHOR (12 BIP39 words) whose address matches
// a prefix/suffix. The anchor only fixes the address. After the key change (done from the
// user's own wallet in Gram Vanity) the anchor controls nothing, so this can run on a rented GPU.
//
// Build: make            (needs CUDA toolkit; see README.md)
// Run:   ./vanity-worker --suffix _Gram [--prefix A] [--ci]
#include "core.h"
#include <cuda_runtime.h>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

void host_candidate(const uint8_t ent[16], char phrase[112], uint8_t pub[32], char addr[49]);
int host_match(const Pattern *p, const char addr[48]);
void host_entropy(const uint8_t seed[32], uint64_t gid, uint64_t iter, uint8_t ent[16]);

#define CUDA_OK(x) do { cudaError_t e_ = (x); if (e_ != cudaSuccess) { \
  fprintf(stderr, "CUDA error %s at %s:%d\n", cudaGetErrorString(e_), __FILE__, __LINE__); exit(3); } } while (0)

struct Found { unsigned int flag; uint8_t ent[16]; };

// One candidate = two kernels (like hashcat's init/loop/comp split). pbkdf2_kernel runs only the
// SHA-512 loop, so it needs few registers and keeps more threads per SM. address_kernel does the
// rest (SLIP-0010, ed25519, address, pattern). BIP39 seeds go between them through global memory
// as 8 big-endian words per candidate, laid out word-major for coalesced access.
//
// Candidate c = k * nthr + gid (k < per_thread). Its entropy is ents[c] if ents is given (self-test),
// else derive_entropy(seed, gid, iter_base + k).
__device__ __forceinline__ void cand_entropy(const uint8_t *__restrict__ seed_g, uint64_t iter_base, uint64_t gid, int k,
                                             const uint8_t *__restrict__ ents, uint64_t c, uint8_t ent[16]) {
  if (ents) { for (int i = 0; i < 16; i++) ent[i] = ents[16 * c + i]; return; }
  uint8_t seed[32];
  for (int i = 0; i < 32; i++) seed[i] = seed_g[i];
  derive_entropy(seed, gid, iter_base + k, ent);
}

__global__ void pbkdf2_kernel(const uint8_t *__restrict__ seed_g, uint64_t iter_base, int per_thread, uint64_t nthr, uint64_t n,
                              const uint8_t *__restrict__ ents, uint64_t *__restrict__ seeds) {
  const uint64_t gid = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
  for (int k = 0; k < per_thread; k++) {
    const uint64_t c = k * nthr + gid;
    if (c >= n) return;
    uint8_t ent[16];
    char phrase[112];
    uint64_t acc[8];
    cand_entropy(seed_g, iter_base, gid, k, ents, c, ent);
    uint32_t len = bip39_phrase(ent, phrase);
    bip39_seed_words((const uint8_t *)phrase, len, acc);
    for (int j = 0; j < 8; j++) seeds[j * n + c] = acc[j];
  }
}

// found != null: search (stop on match). pubs/addrs != null: self-test output for every candidate.
__global__ void address_kernel(const uint8_t *__restrict__ seed_g, uint64_t iter_base, int per_thread, uint64_t nthr, uint64_t n,
                               const uint8_t *__restrict__ ents, const uint64_t *__restrict__ seeds, Pattern pat, Found *found,
                               uint8_t *pubs, char *addrs) {
  const uint64_t gid = (uint64_t)blockIdx.x * blockDim.x + threadIdx.x;
  for (int k = 0; k < per_thread; k++) {
    const uint64_t c = k * nthr + gid;
    if (c >= n) return;
    if (found && *(volatile unsigned int *)&found->flag) return;
    uint8_t seed[64], pub[32];
    char addr[48];
    for (int j = 0; j < 8; j++) store_be64(seed + 8 * j, seeds[j * n + c]);
    seed_to_address(seed, pub, addr);
    if (pubs) {
      for (int i = 0; i < 32; i++) pubs[32 * c + i] = pub[i];
      for (int i = 0; i < 48; i++) addrs[48 * c + i] = addr[i];
    }
    if (found && pattern_match(&pat, addr)) {
      if (atomicCAS(&found->flag, 0u, 1u) == 0u) {
        uint8_t ent[16];
        cand_entropy(seed_g, iter_base, gid, k, ents, c, ent);
        for (int i = 0; i < 16; i++) found->ent[i] = ent[i];
        __threadfence();
      }
      return;
    }
  }
}

static void urandom(uint8_t *b, size_t n) {
  std::ifstream f("/dev/urandom", std::ios::binary);
  if (!f.read((char *)b, n)) { fprintf(stderr, "cannot read /dev/urandom\n"); exit(2); }
}

static double expected_attempts(const Pattern &p) {
  double prob = 1;
  auto cp = [&](char c) { return (p.ci && ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) ? 2.0 / 64 : 1.0 / 64; };
  for (int i = 0; i < p.plen; i++) prob *= i == 0 ? 0.25 : cp(p.prefix[i]);
  for (int i = 0; i < p.slen; i++) prob *= cp(p.suffix[i]);
  return 1 / prob;
}

static std::string human(double s) {
  char b[64];
  if (!std::isfinite(s)) return "—";
  if (s < 90) snprintf(b, sizeof b, "%.0f s", s);
  else if (s < 5400) snprintf(b, sizeof b, "%.0f min", s / 60);
  else if (s < 172800) snprintf(b, sizeof b, "%.1f h", s / 3600);
  else snprintf(b, sizeof b, "%.1f d", s / 86400);
  return b;
}

static bool gpu_selftest(int dev) {
  CUDA_OK(cudaSetDevice(dev));
  const int n = 64;
  std::vector<uint8_t> ents(16 * n, 0), pubs(32 * n);
  std::vector<char> addrs(48 * n);
  uint8_t seed[32];
  urandom(seed, 32);
  for (int i = 1; i < n; i++) host_entropy(seed, i, i, &ents[16 * i]);  // entropy 0 = Acton vector
  uint8_t *d_e, *d_p; char *d_a; uint64_t *d_s;
  CUDA_OK(cudaMalloc(&d_e, ents.size())); CUDA_OK(cudaMalloc(&d_p, pubs.size())); CUDA_OK(cudaMalloc(&d_a, addrs.size()));
  CUDA_OK(cudaMalloc(&d_s, 64 * n));
  CUDA_OK(cudaMemcpy(d_e, ents.data(), ents.size(), cudaMemcpyHostToDevice));
  // The same two kernels as the search, on known entropies.
  pbkdf2_kernel<<<1, n>>>(nullptr, 0, 1, n, n, d_e, d_s);
  CUDA_OK(cudaGetLastError());
  address_kernel<<<1, n>>>(nullptr, 0, 1, n, n, d_e, d_s, Pattern{}, nullptr, d_p, d_a);
  CUDA_OK(cudaGetLastError());
  CUDA_OK(cudaMemcpy(pubs.data(), d_p, pubs.size(), cudaMemcpyDeviceToHost));
  CUDA_OK(cudaMemcpy(addrs.data(), d_a, addrs.size(), cudaMemcpyDeviceToHost));
  cudaFree(d_e); cudaFree(d_p); cudaFree(d_a); cudaFree(d_s);
  for (int i = 0; i < n; i++) {
    char phrase[112], addr[49]; uint8_t pub[32];
    host_candidate(&ents[16 * i], phrase, pub, addr);
    if (memcmp(pub, &pubs[32 * i], 32) || memcmp(addr, &addrs[48 * i], 48)) {
      fprintf(stderr, "GPU %d self-test FAILED at candidate %d\n", dev, i);
      return false;
    }
  }
  static const uint8_t acton[4] = {0x79, 0x52, 0xe9, 0x41};  // 7952e941... (Acton anchor vector)
  if (memcmp(&pubs[0], acton, 4)) { fprintf(stderr, "GPU %d self-test FAILED: reference vector\n", dev); return false; }
  return true;
}

static void usage() {
  fprintf(stderr,
    "vanity-worker — GPU search of a TG Wallet anchor for Gram Vanity\n\n"
    "  --suffix S        address ending\n"
    "  --prefix P        chars right after \"UQ\" (first: A, B, C or D)\n"
    "  --ci              case-insensitive\n"
    "  --devices 0,1     GPUs to use (default: all)\n"
    "  --blocks N        blocks per launch (default: 8 x SMs)\n"
    "  --threads N       threads per block (default: 128)\n"
    "  --per-thread N    candidates per thread per launch (default: 2)\n");
}

int main(int argc, char **argv) {
  Pattern pat = {};
  std::vector<int> devs;
  int blocks = 0, threads = 128, per_thread = 2;
  std::string prefix, suffix;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    auto next = [&]() -> std::string { if (i + 1 >= argc) { usage(); exit(2); } return argv[++i]; };
    if (a == "--suffix") suffix = next();
    else if (a == "--prefix") prefix = next();
    else if (a == "--ci") pat.ci = 1;
    else if (a == "--blocks") blocks = atoi(next().c_str());
    else if (a == "--threads") threads = atoi(next().c_str());
    else if (a == "--per-thread") per_thread = atoi(next().c_str());
    else if (a == "--devices") { std::string s = next(); size_t p = 0; while (p < s.size()) { devs.push_back(atoi(s.c_str() + p)); p = s.find(',', p); if (p == std::string::npos) break; p++; } }
    else { usage(); return a == "-h" || a == "--help" ? 0 : 2; }
  }
  const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  if (prefix.empty() && suffix.empty()) { usage(); return 2; }
  if (prefix.size() + suffix.size() > 10) { fprintf(stderr, "at most 10 characters in total\n"); return 2; }
  for (char c : prefix + suffix) if (alphabet.find(c) == std::string::npos) { fprintf(stderr, "char '%c' never appears in an address\n", c); return 2; }
  if (!prefix.empty() && std::string(pat.ci ? "ABCDabcd" : "ABCD").find(prefix[0]) == std::string::npos) {
    fprintf(stderr, "first char after UQ can only be A, B, C or D\n"); return 2;
  }
  memcpy(pat.prefix, prefix.data(), prefix.size()); pat.plen = (int)prefix.size();
  memcpy(pat.suffix, suffix.data(), suffix.size()); pat.slen = (int)suffix.size();

  int count = 0;
  CUDA_OK(cudaGetDeviceCount(&count));
  if (devs.empty()) for (int d = 0; d < count; d++) devs.push_back(d);
  if (devs.empty()) { fprintf(stderr, "no CUDA devices\n"); return 3; }

  for (int d : devs) {
    cudaDeviceProp prop; CUDA_OK(cudaGetDeviceProperties(&prop, d));
    fprintf(stderr, "GPU %d: %s, %d SMs — self-test… ", d, prop.name, prop.multiProcessorCount);
    if (!gpu_selftest(d)) return 4;
    fprintf(stderr, "OK\n");
  }
  const double expected = expected_attempts(pat);
  fprintf(stderr, "Pattern: UQ%s…%s%s, expected attempts: %.0f\n", prefix.c_str(), suffix.c_str(), pat.ci ? " (any case)" : "", expected);

  std::atomic<uint64_t> attempts{0};
  std::atomic<bool> stop{false};
  std::mutex out_mu;
  std::string result_addr, result_phrase;
  auto t0 = std::chrono::steady_clock::now();

  std::vector<std::thread> workers;
  for (int d : devs) workers.emplace_back([&, d]() {
    CUDA_OK(cudaSetDevice(d));
    cudaDeviceProp prop; CUDA_OK(cudaGetDeviceProperties(&prop, d));
    int nb = blocks > 0 ? blocks : prop.multiProcessorCount * 8;
    uint8_t seed[32]; urandom(seed, 32);
    const uint64_t nthr = (uint64_t)nb * threads, per_launch = nthr * per_thread;
    uint8_t *d_seed; Found *d_found; uint64_t *d_seeds;
    CUDA_OK(cudaMalloc(&d_seed, 32)); CUDA_OK(cudaMalloc(&d_found, sizeof(Found)));
    CUDA_OK(cudaMalloc(&d_seeds, 64 * per_launch));
    CUDA_OK(cudaMemcpy(d_seed, seed, 32, cudaMemcpyHostToDevice));
    CUDA_OK(cudaMemset(d_found, 0, sizeof(Found)));
    uint64_t iter = 0;
    while (!stop.load()) {
      pbkdf2_kernel<<<nb, threads>>>(d_seed, iter, per_thread, nthr, per_launch, nullptr, d_seeds);
      CUDA_OK(cudaGetLastError());
      address_kernel<<<nb, threads>>>(d_seed, iter, per_thread, nthr, per_launch, nullptr, d_seeds, pat, d_found, nullptr, nullptr);
      CUDA_OK(cudaGetLastError());
      Found f; CUDA_OK(cudaMemcpy(&f, d_found, sizeof f, cudaMemcpyDeviceToHost));  // also syncs
      iter += per_thread;
      attempts += per_launch;
      if (!f.flag) continue;
      char phrase[112], addr[49]; uint8_t pub[32];
      host_candidate(f.ent, phrase, pub, addr);
      if (!host_match(&pat, addr)) {  // never print a result the CPU does not confirm
        fprintf(stderr, "\nGPU %d returned a result that the CPU does not confirm; ignored\n", d);
        CUDA_OK(cudaMemset(d_found, 0, sizeof(Found)));
        continue;
      }
      std::lock_guard<std::mutex> g(out_mu);
      if (!stop.exchange(true)) { result_addr = addr; result_phrase = phrase; }
    }
    cudaFree(d_seed); cudaFree(d_found); cudaFree(d_seeds);
  });

  std::thread progress([&]() {
    while (!stop.load()) {
      for (int i = 0; i < 50 && !stop.load(); i++) std::this_thread::sleep_for(std::chrono::milliseconds(100));
      double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
      double n = (double)attempts.load(), rate = n / el;
      std::lock_guard<std::mutex> g(out_mu);
      if (!stop.load())
        fprintf(stderr, "\r%.3g attempts, %.0f/s, %s elapsed, average left %s      ", n, rate, human(el).c_str(),
                human(n < expected ? (expected - n) / rate : expected / rate).c_str());
    }
  });
  for (auto &w : workers) w.join();
  progress.join();

  double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
  fprintf(stderr, "\nFound in %s (%.3g attempts). Paste the anchor into Gram Vanity.\n", human(el).c_str(), (double)attempts.load());
  printf("address: %s\nanchor:  %s\n", result_addr.c_str(), result_phrase.c_str());
  fflush(stdout);
  return 0;
}
