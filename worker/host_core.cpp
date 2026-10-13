// Host (CPU) build of core.h, used by worker.cu to verify every GPU result before printing it.
#define VANITY_HOST_ONLY
#include "core.h"

void host_candidate(const uint8_t ent[16], char phrase[112], uint8_t pub[32], char addr[49]) {
  uint32_t n = bip39_phrase(ent, phrase);
  phrase[n] = 0;
  candidate(ent, pub, addr);
  addr[48] = 0;
}

int host_match(const Pattern *p, const char addr[48]) { return pattern_match(p, addr); }

void host_entropy(const uint8_t seed[32], uint64_t gid, uint64_t iter, uint8_t ent[16]) {
  derive_entropy(seed, gid, iter, ent);
}
