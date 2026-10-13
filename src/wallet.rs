//! TG Wallet (Telegram Wallet, Money) address derivation.
//!
//! Source of truth:
//! - contract: https://github.com/ton-blockchain/tg-wallet-contract
//! - mnemonic "rotation" scheme: ton-blockchain/acton, libs/rston/src/mnemonic.rs
//!
//! A 12-word BIP39 "anchor" mnemonic -> SLIP-0010 ed25519 at m/44'/607'/0' -> pubkey.
//! Address = hash(StateInit{ code: trampoline, data: [rev u8=0][seqno u32=0][wallet_id u32][pubkey 256] }).
//! Before any key rotation the anchor key is also the signing key, so 12 words fully own the wallet.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

/// Trampoline code cell data (24 bytes, no refs). BOC: contracts/WalletTrampoline.boc.
const TRAMPOLINE: [u8; 24] = [
    0xff, 0x00, 0x20, 0x98, 0x21, 0xd7, 0x49, 0x83, 0x08, 0xb9, 0xf2, 0x40, 0xdf, 0x80, 0x85, 0xf8,
    0x33, 0xd0, 0xed, 0x1e, 0x20, 0xed, 0x53, 0xd9,
];
/// Expected trampoline code hash (from the contract repo and Acton).
pub const TRAMPOLINE_HASH_HEX: &str =
    "9149ae51c1e4689710cebf7830297b16acfbadb363a920a537893e7ffeeca768";
pub const WALLET_ID_MAINNET: u32 = 0x7FFF_7F11;

type HmacSha512 = Hmac<Sha512>;

pub struct Keys {
    pub public: [u8; 32],
}

/// BIP39 seed + SLIP-0010 m/44'/607'/0'. `phrase` must be normalized (lowercase ASCII words, single spaces).
pub fn keys_from_phrase(phrase: &str) -> Keys {
    Keys { public: signing_key(phrase).verifying_key().to_bytes() }
}

/// Full ed25519 signing key (zeroized on drop by ed25519-dalek).
pub fn signing_key(phrase: &str) -> ed25519_dalek::SigningKey {
    let mut seed = Zeroizing::new([0u8; 64]);
    crate::pbkdf2_fast::bip39_seed(phrase.as_bytes(), 2048, &mut seed);

    let mut mac = HmacSha512::new_from_slice(b"ed25519 seed").unwrap();
    mac.update(&*seed);
    let mut d = Zeroizing::new(<[u8; 64]>::from(mac.finalize().into_bytes()));
    for index in [44u32, 607, 0] {
        let mut mac = HmacSha512::new_from_slice(&d[32..]).unwrap();
        mac.update(&[0]);
        mac.update(&d[..32]);
        mac.update(&(index | 0x8000_0000).to_be_bytes());
        d = Zeroizing::new(<[u8; 64]>::from(mac.finalize().into_bytes()));
    }
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&d[..32]);
    ed25519_dalek::SigningKey::from_bytes(&secret)
}

/// Normalize and validate a 12-word BIP39 phrase.
pub fn normalize_words(words: &str) -> Result<Zeroizing<String>, String> {
    let norm: Vec<String> = words.split_whitespace().map(|w| w.to_lowercase()).collect();
    if norm.len() != 12 {
        return Err(format!("нужно 12 слов, получено {}", norm.len()));
    }
    let phrase = Zeroizing::new(norm.join(" "));
    bip39::Mnemonic::parse_in_normalized(bip39::Language::English, &phrase)
        .map_err(|e| format!("неверная мнемоника: {e}"))?;
    Ok(phrase)
}

/// 12 fresh BIP39 words from the OS CSPRNG.
pub fn new_words() -> Zeroizing<String> {
    let mut e = Zeroizing::new([0u8; 16]);
    getrandom::getrandom(&mut *e).expect("OS RNG unavailable");
    let m = bip39::Mnemonic::from_entropy(&*e).unwrap();
    Zeroizing::new(m.words().collect::<Vec<_>>().join(" "))
}

pub const TRAMPOLINE_CODE: &[u8; 24] = &TRAMPOLINE;

pub fn code_hash() -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([0x00, 0x30]); // d1: 0 refs; d2: 24 full bytes
    h.update(TRAMPOLINE);
    h.finalize().into()
}

/// Raw account hash (workchain 0).
pub fn address_hash(code_hash: &[u8; 32], pubkey: &[u8; 32], wallet_id: u32) -> [u8; 32] {
    // data cell: 8 + 32 + 32 + 256 = 328 bits = 41 bytes
    let mut h = Sha256::new();
    h.update([0x00, 82]);
    h.update([0u8; 5]); // revision 0, seqno 0
    h.update(wallet_id.to_be_bytes());
    h.update(pubkey);
    let data_hash: [u8; 32] = h.finalize().into();

    // StateInit: bits "00110" (no split_depth, no special, code, data, no library), refs [code, data]
    let mut h = Sha256::new();
    h.update([0x02, 0x01, 0x34]);
    h.update([0, 0, 0, 0]); // depths of both refs = 0
    h.update(code_hash);
    h.update(data_hash);
    h.finalize().into()
}

fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// User-friendly non-bounceable mainnet address (UQ...), 48 chars.
pub fn friendly(hash: &[u8; 32]) -> String {
    let mut raw = [0u8; 36];
    raw[0] = 0x51; // non-bounceable, mainnet
    raw[1] = 0x00; // workchain 0
    raw[2..34].copy_from_slice(hash);
    let crc = crc16_xmodem(&raw[..34]);
    raw[34..].copy_from_slice(&crc.to_be_bytes());
    let mut out = String::with_capacity(48);
    for c in raw.chunks(3) {
        let n = (c[0] as u32) << 16 | (c[1] as u32) << 8 | c[2] as u32;
        for s in [18, 12, 6, 0] {
            out.push(B64URL[(n >> s & 63) as usize] as char);
        }
    }
    out
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Validate 12 words (BIP39 English + checksum) and return the address.
pub fn address_from_words(words: &str) -> Result<(String, [u8; 32]), String> {
    let phrase = normalize_words(words)?;
    let k = keys_from_phrase(&phrase);
    Ok((friendly(&address_hash(&code_hash(), &k.public, WALLET_ID_MAINNET)), k.public))
}

/// Refuse to mine if derivation does not match known reference vectors.
pub fn self_test() -> Result<(), String> {
    if hex(&code_hash()) != TRAMPOLINE_HASH_HEX {
        return Err("trampoline code hash mismatch".into());
    }
    // Acton rotation_keys_match_wallet_engine test vector.
    let k = keys_from_phrase(
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
    );
    if hex(&k.public) != "7952e94118f34607c75e23258dd9220d66ccac5a3ee074125c25068e8107bfbf" {
        return Err("BIP39/SLIP-0010 derivation mismatch".into());
    }
    // Real mainnet TG wallet: init-state anchor pubkey -> its on-chain address.
    let mut pk = [0u8; 32];
    let src = "f51b2dff5df6815a45aa34035829d516ab115c887d39607af94d31ba5ba516d8";
    for i in 0..32 {
        pk[i] = u8::from_str_radix(&src[i * 2..i * 2 + 2], 16).unwrap();
    }
    let addr = friendly(&address_hash(&code_hash(), &pk, WALLET_ID_MAINNET));
    if addr != "UQCxGaegN4EDL2LiDXlGnuw4nmvexTRWxqxpe0sRTXSCAMER" {
        return Err(format!("address derivation mismatch: {addr}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn reference_vectors() {
        super::self_test().unwrap();
    }
}
