# Gram Vanity

A vanity address for your Telegram Wallet (Money): `UQ…_Gram`, `UQDurov…`, any short text.

The search runs on your computer or your own GPU server. You get **24 words** and import them into Telegram. Only you know the key.

Same scheme as [vanity.tg](https://vanity.tg) (TG Wallet contract, 24 words, one key change). The difference: the key change goes from **your own wallet**, and everything runs locally.

## How it works

1. **Search.** Find 12 BIP39 words (1–12) whose address contains your text. Each character makes the search ~64× longer.
2. **Your key.** Words 13–24 come from the OS random generator. They never leave your computer.
3. **Key change.** Your wallet (TON Connect) sends one message: 0.01 GRAM + deploy + key change. After it, words 1–12 control nothing.
4. **Import** the 24 words into Telegram.

Only the public key of words 13–24 and one signature go to the network.

## Import into Telegram

Telegram keeps one wallet.

1. **Settings → Money** («Настройки → Деньги»).
2. Move coins out of the old wallet, or save its phrase. Delete it.
3. Import the 24 words in order.
4. Check that the address ends with your text.

## Run

Needs [Rust](https://rustup.rs) 1.85+.

```bash
git clone https://github.com/catchain/gram-vanity
cd gram-vanity
cargo run --release
```

The program opens `http://127.0.0.1:PORT/#t=…` in your browser.

**Manifest.** The wallet downloads [`ui/tonconnect-manifest.json`](ui/tonconnect-manifest.json) from this repo. Nothing to set up. For your own: `--manifest-url https://…`.

**Settings.** Copy [`.env.example`](.env.example) to `.env`. Environment variables win.

| Key | Meaning |
|---|---|
| `TONCENTER_API_KEY` | Optional. Without it: 1 request/s, enough. With it: 10/s. |
| `VANITY_MANIFEST_URL` | Optional. Same as `--manifest-url`. |

**Terminal only:**

```bash
cargo run --release -- mine --suffix _Gram   # CPU search, prints words 1–12
cargo run --release -- bench                 # CPU speed
```

## Speed

| Hardware | Rate | 6 chars, exact case |
|---|---|---|
| Apple M2, 8 threads | ~15,000/s | ~55 days |
| 4× RTX 5090 (measured) | ~6,000,000/s | ~3 hours |

Any case is much faster. For 6+ characters use the GPU: [`worker/README.md`](worker/README.md). The GPU tab starts it over SSH.

## Security

- **Key stays local.** Words 13–24 live only in memory. No disk, no core dumps.
- **GPU server sees only words 1–12.** Until the key change, its owner could take the address (not funds). Change the key right after the search.
- **Atomic.** Top-up, deploy and key change are one message. No funds sit under words 1–12.
- **Two origins.** The words page (`/`) has a strict CSP and no external requests. TON Connect runs on a second port and cannot read it.
- **Local only.** Listens on `127.0.0.1`. Token + `Host` + `Origin` checks (CSRF, DNS rebinding).
- **Read-only network.** Only public account state from toncenter.
- **Self-test at start:** code hash, Acton vector, a real mainnet address.
- **Foreign key check.** Refuses to build a key change if the on-chain key is somebody else's.
- **«Стереть»** zeroizes word buffers (not HTTP buffer copies). The clipboard clears 60 s after a copy. Write the words on paper.

**If the key change fails** (the request is valid 4 minutes), the address is still deployed with the key of words 1–12. The page shows «развёрнут, ключ ещё не ваш». Send again: the program rebuilds it without deploy, with the current seqno.

## Technical details

- **Contract:** [tg-wallet-contract](https://github.com/ton-blockchain/tg-wallet-contract), subwallet `0x7FFF7F11`.
- **Address:** `hash(StateInit{trampoline, [rev 0][seqno 0][0x7FFF7F11][pubkey of words 1–12]})`.
- **Keys:** BIP39 seed (PBKDF2-HMAC-SHA512, 2048 rounds), SLIP-0010 ed25519 `m/44'/607'/0'`.
- **Key change:** `ChangePublicKeyRequestI` (op `0xFBBA99C7`) signed by words 1–12, with a `KEY_ROTATION` proof signed by words 13–24.
- **Reference:** [Acton](https://github.com/ton-blockchain/acton) (`MnemonicScheme::Rotation`). Output matches vanity.tg byte for byte.

## Tests

```bash
cargo test --release                     # reference vectors, fast PBKDF2
(cd tests/js && npm install && npm test) # e2e in @ton/sandbox, live mainnet config
(cd worker && make test)                 # GPU core vs Rust, emulated, no GPU needed
```

The sandbox test checks the key change, seqno, replay and old-key rejection, expiry and the recovery path. Not automated: a real mainnet transaction, the Telegram import, the CUDA build.

## Contributing

Issues and PRs are welcome. Run the tests first. Security problems: [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE). Third-party code keeps its license:

| Path | Source | License |
|---|---|---|
| `ui/vendor/tonconnect-ui.min.js` | [@tonconnect/ui](https://github.com/ton-connect/sdk) 3.0.2 | Apache-2.0 |
| `worker/ed25519/` | [orlp/ed25519](https://github.com/orlp/ed25519), modified for CUDA | zlib |
| `ui/fonts/` | Onest, JetBrains Mono | SIL OFL 1.1 |
