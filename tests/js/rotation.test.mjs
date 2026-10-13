// End-to-end check of the atomic deploy + key change in @ton/sandbox with the live mainnet
// config (WalletTg bytecode at config param -123). The "user wallet" is a sandbox treasury that
// sends exactly what TON Connect would send: one internal message with value, StateInit, payload.
// Run: cargo build --release && cd tests/js && npm i && npm test
import { Blockchain } from "@ton/sandbox";
import { Cell, Address, toNano, loadStateInit, beginCell, internal } from "@ton/core";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const bin = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../target/release/gram-vanity");
const ANCHOR = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const SIGNING = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong";
const fail = m => { console.error("FAIL:", m); process.exit(1); };
const payload = (validUntil, seqno) => {
  const [addr, pub, init, body] = execFileSync(bin, ["debug-deploy", String(validUntil), String(seqno)], { input: `${ANCHOR}\n${SIGNING}\n` })
    .toString().trim().split("\n");
  return { address: Address.parse(addr), pub, init: init === "-" ? null : loadStateInit(Cell.fromHex(init).beginParse()), body: Cell.fromHex(body) };
};

const cfg = await (await fetch("https://toncenter.com/api/v2/getConfigAll")).json();
if (!cfg.ok) fail("cannot load mainnet config");
const blockchain = await Blockchain.create({ config: Cell.fromBase64(cfg.result.config.bytes) });
const now = Math.floor(Date.now() / 1000);
blockchain.now = now;

const p = payload(now + 900, 0);
if (p.pub !== "5d6320a0546c2df0908f0477e1ade79226faf854d041548f846b58872de5213e") fail("signing key != Acton vector");
if (!p.init) fail("no StateInit");

const user = await blockchain.treasury("user-wallet");
const res = await user.send({ to: p.address, value: toNano("0.05"), bounce: false, init: p.init, body: p.body });
const tx = res.transactions.find(t => t.inMessage?.info.type === "internal" && t.inMessage.info.dest.equals(p.address));
const d = tx.description;
console.log("vanity tx:", d.computePhase.type === "vm" ? `exit=${d.computePhase.exitCode} gas=${d.computePhase.gasUsed}` : d.computePhase.type,
  "| status:", tx.endStatus, "| fees:", Number(tx.totalFees.coins) / 1e9, "GRAM");
if (d.aborted || d.computePhase.exitCode !== 0 || tx.endStatus !== "active") fail("deploy + key change failed");

const getPk = async () => (await blockchain.runGetMethod(p.address, "get_public_key")).stackReader.readBigNumber().toString(16).padStart(64, "0");
const pk = await getPk();
const seqno = (await blockchain.runGetMethod(p.address, "seqno")).stackReader.readNumber();
const bal = (await blockchain.getContract(p.address)).balance;
console.log("address:", p.address.toString({ bounceable: false }));
console.log("public key:", pk, "| seqno:", seqno, "| balance:", Number(bal) / 1e9, "GRAM");
if (pk !== p.pub) fail("public key not changed");
if (seqno !== 1) fail("seqno != 1");

// Replay of the same message: signature is valid but seqno is used -> must not change anything.
await user.send({ to: p.address, value: toNano("0.01"), bounce: false, body: p.body });
if ((await getPk()) !== p.pub) fail("replay changed key");

// Anchor key after rotation: a new anchor-signed request (seqno 1) is ignored (bad signature for new key).
const p2 = payload(now + 900, 1);
await user.send({ to: p.address, value: toNano("0.01"), bounce: false, body: p2.body });
if ((await getPk()) !== p.pub || (await blockchain.runGetMethod(p.address, "seqno")).stackReader.readNumber() !== 1) fail("anchor key still accepted");

// Expired request on a fresh address: the deploy message must not leave a key change behind.
const blockchain2 = await Blockchain.create({ config: Cell.fromBase64(cfg.result.config.bytes) });
blockchain2.now = now + 2000;
const user2 = await blockchain2.treasury("user-wallet");
const r2 = await user2.send({ to: p.address, value: toNano("0.05"), bounce: false, init: p.init, body: p.body });
const t2 = r2.transactions.find(t => t.inMessage?.info.type === "internal" && t.inMessage.info.dest.equals(p.address));
console.log("expired request:", `exit=${t2.description.computePhase.exitCode}`, "| status:", t2.endStatus);
if (t2.description.computePhase.exitCode === 0) fail("expired request accepted");
// The account is now deployed with the ANCHOR key (state applied even though compute failed).
// Recovery: a fresh request (seqno 0) from the user wallet must finish the key change.
const p3 = payload(now + 2000 + 900, 0);
const r3 = await user2.send({ to: p.address, value: toNano("0.01"), bounce: false, init: p3.init, body: p3.body });
const t3 = r3.transactions.find(t => t.inMessage?.info.type === "internal" && t.inMessage.info.dest.equals(p.address));
const pk3 = (await blockchain2.runGetMethod(p.address, "get_public_key")).stackReader.readBigNumber().toString(16).padStart(64, "0");
console.log("recovery after failed deploy:", `exit=${t3.description.computePhase.exitCode}`, "| key changed:", pk3 === p.pub);
if (pk3 !== p.pub) fail("recovery failed");

console.log("OK: atomic deploy + key change works; replay, old anchor key and expired request are rejected");
