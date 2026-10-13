/* Modified for Gram Vanity (marked per zlib license): DEV_FN/DEV_CONST qualifiers for
   CUDA + host builds, prototypes removed, select() renamed to ge_select(). Original: github.com/orlp/ed25519 */
#pragma once
#include <stdint.h>
typedef int32_t fe[10];
typedef struct { fe X; fe Y; fe Z; } ge_p2;
typedef struct { fe X; fe Y; fe Z; fe T; } ge_p3;
typedef struct { fe X; fe Y; fe Z; fe T; } ge_p1p1;
typedef struct { fe yplusx; fe yminusx; fe xy2d; } ge_precomp;
typedef struct { fe YplusX; fe YminusX; fe Z; fe T2d; } ge_cached;
