# vanity-worker (CUDA)

The GPU worker finds an **anchor**: 12 BIP39 words whose TG Wallet address matches your prefix or suffix. It does not create your key. Gram Vanity creates the signing half (words 13–24) on your computer, and your own wallet changes the key in one transaction.

## Why a rented GPU is acceptable

After the key change, the anchor controls nothing. The server owner can learn the anchor, but cannot use it after step 3 below.

One window remains: between "anchor found" and "key changed". In that window, the server owner could change the key first. You then lose the address and the rental cost, not your funds. The key change is atomic (top-up + deploy + key change in one message from your wallet), so funds never sit on the address under the anchor. To keep the window short, do the key change right after you get the anchor.

## Start from Gram Vanity

In the GPU tab, enter the server's SSH address (`root@1.2.3.4`) and port.

**«Запустить».** Gram Vanity starts your local `ssh` itself. It uploads the worker, builds it and starts the search. The page shows the log and the speed. When the worker finds an anchor, Gram Vanity checks it on the CPU and opens the 24 words. You do not copy anything.

- Use an SSH key (or ssh-agent). Password login does not work: ssh runs with `BatchMode=yes`.
- On the first connection, ssh adds the server key to `known_hosts` (`StrictHostKeyChecking=accept-new`).
- «Остановить» closes ssh. The remote worker stops within about 5 s (SIGPIPE on its next progress line).

**Manual command.** The page also builds one command for your local terminal:

```bash
curl -sf http://127.0.0.1:PORT/worker.tar.gz | ssh root@1.2.3.4 '…; tar xzf -; make -s; ./vanity-worker --suffix _Gram'
```

It takes the worker sources from your local Gram Vanity, uploads them over SSH, installs `make`/`g++` if missing, checks `nvcc`, builds and starts the search. The anchor prints in your local terminal.

## Manual run on a rented GPU (vast.ai, RunPod, Lambda, …)

1. Rent a machine with an NVIDIA GPU and a CUDA image (for example `nvidia/cuda:12.4.1-devel-ubuntu22.04`).
2. Copy this folder to the machine and build:

   ```bash
   cd worker
   make            # or: make ARCH=sm_89 for RTX 40xx
   ```

3. Start the search. Gram Vanity shows the exact command in the GPU tab:

   ```bash
   ./vanity-worker --suffix _Gram
   ./vanity-worker --prefix A --suffix Gram --ci
   ```

   At start, every GPU runs a self-test against the CPU and the Acton reference vector. If it fails, the worker stops.

4. Output:

   ```
   address: UQ…_Gram
   anchor:  word1 … word12
   ```

   The CPU re-checks every GPU result before it prints anything.

5. Paste the anchor into the GPU tab («Слова 1–12 из воркера»), write down the 24 words and change the key from your wallet.
6. Destroy the rented machine.

## Options

| Option | Meaning |
|---|---|
| `--suffix S` | address ending |
| `--prefix P` | chars right after `UQ` (first: A, B, C or D) |
| `--ci` | case-insensitive |
| `--devices 0,1` | GPUs to use (default: all) |
| `--blocks N` `--threads N` `--per-thread N` | launch tuning (default: 8×SMs, 128, 2) |

## Speed

Measured: about 1.5 million candidates/s on one RTX 5090 (before the two-kernel split). The worker prints the real rate every 5 seconds. If it is much lower, try `--threads 64` or `--blocks` = 16×SMs.

Almost all time goes to PBKDF2 (2048 rounds, 4096 SHA-512 compressions per candidate). To make it faster, the worker:

- runs PBKDF2 in its own kernel (`pbkdf2_kernel`), and SLIP-0010, ed25519 and the address in a second kernel (`address_kernel`). The PBKDF2 kernel needs fewer registers, so more threads run on each SM.
- uses a SHA-512 with fixed padding words (`sha512_compress_64`) in the PBKDF2 loop. The compiler removes the constant words from the first rounds and the message schedule.

The upper limit is the hashcat speed for PBKDF2-HMAC-SHA512: about 2.1 million/s at 2048 rounds on one RTX 5090.

## Checks without a GPU

```bash
make test
```

This runs on any machine with a C++ compiler:

1. `core.h` reference vectors (Acton anchor vector, a real mainnet address).
2. 300 random candidates compared with the Rust binary, byte for byte.
3. The real `worker.cu` control flow in CPU emulation (`tests/cuda_emu`); the result is confirmed by the Rust binary.

The CUDA build itself (`nvcc`) and the GPU speed are **not** tested by `make test`.

## Third-party code

`ed25519/` is from [orlp/ed25519](https://github.com/orlp/ed25519) (zlib license, see `ed25519/license.txt`), modified for CUDA as noted in each file.
