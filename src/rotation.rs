//! "Vanity-style" 24 words: anchor (12, fixes the address) + signing (12, the real key).
//!
//! The user's own wallet (Telegram Wallet (Money), via TON Connect) sends ONE internal message:
//! value + StateInit + `ChangePublicKeyRequestI` signed by the anchor key, with a rotation
//! proof signed by the new key. Funding, deploy and key change happen atomically, so funds
//! never sit on the address under the anchor key. Formats: tg-wallet-contract
//! contracts/WalletTg/messages.tolk and wrappers/utils.tolk (`prepareChangePublicKeyI`).
//!
//! Network: toncenter.com read-only (public account state), optional API key from .env.
//! Words and keys never leave this process.

use crate::cell::{to_boc, Builder, Cell};
use crate::wallet;
use ed25519_dalek::{Signer, SigningKey};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const OP_CHANGE_KEY_INTERNAL: u64 = 0xFBBA_99C7;
const KEY_ROTATION_TAG: &[u8; 12] = b"KEY_ROTATION";
const API: &str = "https://toncenter.com/api/v2";
/// Value the user's wallet attaches: pays deploy + key change, the rest stays on the address.
pub const DEPLOY_VALUE_NANO: u128 = 10_000_000; // 0.01 GRAM: gas ~0.0005, rest stays on the address
/// Lifetime of a signed key-change request (and of the TON Connect request): under 5 minutes.
pub const VALID_FOR_SECS: u32 = 4 * 60;

pub fn code_cell() -> Arc<Cell> {
    Builder::new().bytes(wallet::TRAMPOLINE_CODE).build()
}

pub fn data_cell(anchor_pub: &[u8; 32], wallet_id: u32) -> Arc<Cell> {
    Builder::new().uint(0, 8).uint(0, 32).uint(wallet_id as u64, 32).bytes(anchor_pub).build()
}

pub fn state_init(anchor_pub: &[u8; 32], wallet_id: u32) -> Arc<Cell> {
    // split_depth:none special:none code:just data:just library:none
    Builder::new()
        .bit(false).bit(false).bit(true).bit(true).bit(false)
        .reference(code_cell())
        .reference(data_cell(anchor_pub, wallet_id))
        .build()
}

/// KeyRotationProofPayload { tag uint96, walletWorkchain int8, walletAddrHash uint256 }.
pub fn rotation_proof(addr_hash: &[u8; 32], new_key: &SigningKey) -> [u8; 64] {
    let payload = Builder::new().bytes(KEY_ROTATION_TAG).uint(0, 8).bytes(addr_hash).build();
    new_key.sign(&payload.hash()).to_bytes()
}

/// What the user's own wallet sends via TON Connect: one internal message to the vanity
/// address with `value`, the StateInit (deploy) and the signed key change (body).
pub struct Deploy {
    pub address: String,
    pub new_public: [u8; 32],
    /// None when the account is already deployed (anchor key still active).
    pub state_init: Option<Vec<u8>>,
    pub body: Vec<u8>,
}

/// `SignedRequest<ChangePublicKeyRequestI>`: anchor signature over the request cell hash,
/// then op, SeqnoHeader{subwalletId, validUntil, seqno}, newPublicKey, ^rotationSignature, ^encryptedOldPrivateKey.
pub fn deploy(
    anchor: &SigningKey,
    signing: &SigningKey,
    wallet_id: u32,
    seqno: u32,
    valid_until: u32,
    with_init: bool,
) -> Deploy {
    let anchor_pub = anchor.verifying_key().to_bytes();
    let new_pub = signing.verifying_key().to_bytes();
    let init = state_init(&anchor_pub, wallet_id);
    let addr_hash = init.hash();

    let request = Builder::new()
        .uint(OP_CHANGE_KEY_INTERNAL, 32)
        .uint(wallet_id as u64, 32)
        .uint(valid_until as u64, 32)
        .uint(seqno as u64, 32)
        .bytes(&new_pub)
        .reference(Builder::new().bytes(&rotation_proof(&addr_hash, signing)).build())
        // Not checked by the contract; zero, like vanity.tg (no old encrypted messages exist).
        .reference(Builder::new().bytes(&[0u8; 32]).build());
    // On-chain check is `rest.hash()` = hash of this request cell.
    let signature = anchor.sign(&request.clone().build().hash()).to_bytes();
    let body = Builder::new().bytes(&signature).append(&request).build();

    Deploy {
        address: wallet::friendly(&addr_hash),
        new_public: new_pub,
        state_init: with_init.then(|| to_boc(&init)),
        body: to_boc(&body),
    }
}

// ---------------- toncenter ----------------

pub struct Account {
    pub state: String,
    pub balance: u128,
}

/// toncenter API key (from .env / env), sent only as the X-API-Key header.
static API_KEY: OnceLock<Option<String>> = OnceLock::new();

pub fn set_api_key(key: Option<String>) {
    let _ = API_KEY.set(key.filter(|k| !k.trim().is_empty()).map(|k| k.trim().to_string()));
}

pub fn has_api_key() -> bool {
    api_key().is_some()
}

fn api_key() -> Option<&'static str> {
    API_KEY.get().and_then(|k| k.as_deref())
}

/// toncenter limits: 1 request/s without a key, 10/s with one. All calls go through this gate.
fn throttle() {
    static LAST: Mutex<Option<Instant>> = Mutex::new(None);
    let gap = Duration::from_millis(if api_key().is_some() { 120 } else { 1100 });
    let mut last = LAST.lock().unwrap();
    if let Some(wait) = last.map(|t| gap.saturating_sub(t.elapsed())) {
        std::thread::sleep(wait);
    }
    *last = Some(Instant::now());
}

fn request(path: &str, body: Option<&serde_json::Value>) -> Result<serde_json::Value, String> {
    const TRIES: u64 = 4;
    for attempt in 1..=TRIES {
        throttle();
        let method = if body.is_some() { "POST" } else { "GET" };
        let mut req = ureq::request(method, &format!("{API}/{path}")).timeout(Duration::from_secs(15));
        if let Some(k) = api_key() {
            req = req.set("X-API-Key", k);
        }
        let resp = match body {
            Some(b) => req.send_json(b),
            None => req.call(),
        };
        let v: serde_json::Value = match resp {
            Ok(r) => r.into_json().map_err(|e| format!("toncenter: {e}"))?,
            Err(ureq::Error::Status(429, _)) if attempt < TRIES => {
                std::thread::sleep(Duration::from_millis(700 * attempt));
                continue;
            }
            Err(ureq::Error::Status(code, r)) => {
                r.into_json().map_err(|_| format!("toncenter: HTTP {code}"))?
            }
            Err(e) => return Err(format!("toncenter: {e}")),
        };
        if v["ok"] != true {
            return Err(format!("toncenter: {}", v["error"]));
        }
        return Ok(v["result"].clone());
    }
    Err("toncenter: too many requests".into())
}

pub fn account(address: &str) -> Result<Account, String> {
    let r = request(&format!("getAddressInformation?address={address}"), None)?;
    let balance = r["balance"].as_str().map(str::to_string).unwrap_or_else(|| r["balance"].to_string());
    Ok(Account {
        state: r["state"].as_str().unwrap_or("unknown").to_string(),
        balance: balance.trim_matches('"').parse().unwrap_or(0),
    })
}

fn get_num(address: &str, method: &str) -> Result<String, String> {
    let r = request("runGetMethod", Some(&serde_json::json!({"address": address, "method": method, "stack": []})))?;
    if r["exit_code"] != 0 {
        return Err(format!("{method}: exit code {}", r["exit_code"]));
    }
    r["stack"][0][1].as_str().map(str::to_string).ok_or_else(|| format!("{method}: empty stack"))
}

pub fn seqno(address: &str) -> Result<u32, String> {
    let h = get_num(address, "seqno")?;
    u32::from_str_radix(h.trim_start_matches("0x"), 16).map_err(|e| e.to_string())
}

pub fn public_key(address: &str) -> Result<String, String> {
    let h = get_num(address, "get_public_key")?;
    Ok(format!("{:0>64}", h.trim_start_matches("0x")))
}

pub fn now() -> u32 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as u32
}
