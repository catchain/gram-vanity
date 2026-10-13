// Host build of worker/core.h: reference vectors + random candidates for comparison with Rust.
// Build: c++ -O2 -std=c++17 -o test_host worker/tests/test_host.cpp
// Usage: ./test_host vectors | ./test_host random N | ./test_host bench SECONDS
#include "../core.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>

static void hex(const uint8_t *b, int n, char *out) { for (int i = 0; i < n; i++) snprintf(out + 2*i, 3, "%02x", b[i]); }
static void rnd(uint8_t *b, size_t n) { std::ifstream f("/dev/urandom", std::ios::binary); f.read((char *)b, n); }

int main(int argc, char **argv) {
  const char *mode = argc > 1 ? argv[1] : "vectors";
  if (!strcmp(mode, "vectors")) {
    int fails = 0;
    uint8_t ent[16] = {0}, pub[32]; char addr[49] = {0}, phrase[112], h[65];
    uint32_t n = bip39_phrase(ent, phrase); phrase[n] = 0;
    if (strcmp(phrase, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")) { puts("FAIL phrase"); fails++; }
    candidate(ent, pub, addr); hex(pub, 32, h);
    // Acton rotation_keys_match_wallet_engine anchor vector
    if (strcmp(h, "7952e94118f34607c75e23258dd9220d66ccac5a3ee074125c25068e8107bfbf")) { printf("FAIL pubkey %s\n", h); fails++; }
    // Real mainnet wallet: anchor pubkey -> on-chain address
    const char *pk = "f51b2dff5df6815a45aa34035829d516ab115c887d39607af94d31ba5ba516d8"; uint8_t p2[32];
    for (int i = 0; i < 32; i++) sscanf(pk + 2*i, "%2hhx", &p2[i]);
    tg_address(p2, addr);
    if (strcmp(addr, "UQCxGaegN4EDL2LiDXlGnuw4nmvexTRWxqxpe0sRTXSCAMER")) { printf("FAIL address %s\n", addr); fails++; }
    Pattern pt = {}; strcpy(pt.suffix, "scamer"); pt.slen = 6; pt.ci = 1;
    if (!pattern_match(&pt, addr)) { puts("FAIL ci match"); fails++; }
    pt.ci = 0; if (pattern_match(&pt, addr)) { puts("FAIL cs match"); fails++; }
    strcpy(pt.prefix, "Cx"); pt.plen = 2; strcpy(pt.suffix, "AMER"); pt.slen = 4;
    if (!pattern_match(&pt, addr)) { puts("FAIL prefix+suffix"); fails++; }
    puts(fails ? "VECTORS FAILED" : "vectors OK");
    return fails != 0;
  }
  if (!strcmp(mode, "random")) {
    int count = argc > 2 ? atoi(argv[2]) : 50;
    uint8_t seed[32]; rnd(seed, 32);
    for (int i = 0; i < count; i++) {
      uint8_t ent[16], pub[32]; char addr[49] = {0}, phrase[112], h[65];
      derive_entropy(seed, (uint64_t)i * 7919, (uint64_t)i, ent);
      uint32_t n = bip39_phrase(ent, phrase); phrase[n] = 0;
      candidate(ent, pub, addr); hex(pub, 32, h);
      printf("%s\t%s %s\n", phrase, addr, h);
    }
    return 0;
  }
  if (!strcmp(mode, "bench")) {
    double secs = argc > 2 ? atof(argv[2]) : 3;
    uint8_t seed[32] = {1}, ent[16], pub[32]; char addr[48]; uint64_t k = 0;
    auto t0 = std::chrono::steady_clock::now();
    while (std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count() < secs) {
      derive_entropy(seed, 0, k++, ent); candidate(ent, pub, addr);
    }
    printf("host 1 thread: %.0f candidates/s\n", k / secs);
    return 0;
  }
  return 2;
}
