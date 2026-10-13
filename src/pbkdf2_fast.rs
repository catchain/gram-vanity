//! PBKDF2-HMAC-SHA512 specialised for BIP39 (salt "mnemonic", 64-byte output, one block).
//! Same result as the `pbkdf2` crate (checked in tests), but calls the SHA-512
//! compression function directly: 2 compressions per iteration, no buffering.

use sha2::digest::generic_array::GenericArray;
use sha2::{Digest, Sha512};

const IV: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];

#[inline(always)]
fn compress(state: &mut [u64; 8], block: &[u8; 128]) {
    sha2::compress512(state, core::slice::from_ref(GenericArray::from_slice(block)));
}

#[inline(always)]
fn put(state: &[u64; 8], out: &mut [u8]) {
    for (i, w) in state.iter().enumerate() {
        out[i * 8..i * 8 + 8].copy_from_slice(&w.to_be_bytes());
    }
}

/// Block template for hashing a 64-byte message after one 128-byte key block.
fn tail_block() -> [u8; 128] {
    let mut b = [0u8; 128];
    b[64] = 0x80;
    b[120..].copy_from_slice(&((128u64 + 64) * 8).to_be_bytes());
    b
}

pub fn bip39_seed(password: &[u8], rounds: u32, out: &mut [u8; 64]) {
    let mut key = [0u8; 128];
    if password.len() > 128 {
        key[..64].copy_from_slice(&Sha512::digest(password));
    } else {
        key[..password.len()].copy_from_slice(password);
    }
    let (mut ipad, mut opad) = ([0u8; 128], [0u8; 128]);
    for i in 0..128 {
        ipad[i] = key[i] ^ 0x36;
        opad[i] = key[i] ^ 0x5c;
    }
    let (mut istate, mut ostate) = (IV, IV);
    compress(&mut istate, &ipad);
    compress(&mut ostate, &opad);

    // U1 = HMAC(P, "mnemonic" || INT(1))
    let mut b = [0u8; 128];
    b[..8].copy_from_slice(b"mnemonic");
    b[8..12].copy_from_slice(&1u32.to_be_bytes());
    b[12] = 0x80;
    b[120..].copy_from_slice(&((128u64 + 12) * 8).to_be_bytes());
    let mut s = istate;
    compress(&mut s, &b);

    let mut blk = tail_block();
    put(&s, &mut blk[..64]);
    let mut u = ostate;
    compress(&mut u, &blk);
    let mut acc = u;

    for _ in 1..rounds {
        put(&u, &mut blk[..64]);
        let mut s = istate;
        compress(&mut s, &blk);
        put(&s, &mut blk[..64]);
        u = ostate;
        compress(&mut u, &blk);
        for i in 0..8 {
            acc[i] ^= u[i];
        }
    }
    put(&acc, out);
    key.fill(0);
    ipad.fill(0);
    opad.fill(0);
    blk.fill(0);
}

#[cfg(test)]
mod tests {
    #[test]
    fn matches_pbkdf2_crate() {
        for pw in ["", "abandon about", &"zoo ".repeat(40), "legal winner thank year wave sausage worth useful legal winner thank yellow"] {
            let mut a = [0u8; 64];
            let mut b = [0u8; 64];
            pbkdf2::pbkdf2_hmac::<sha2::Sha512>(pw.as_bytes(), b"mnemonic", 2048, &mut a);
            super::bip39_seed(pw.as_bytes(), 2048, &mut b);
            assert_eq!(a, b, "password {pw:?}");
        }
    }
}
