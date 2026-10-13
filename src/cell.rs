//! Minimal TON cell builder + BOC serializer (ordinary cells only).
//! Enough for one external message. Verified against @ton/core in tests/js.

use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Clone)]
pub struct Cell {
    data: Vec<u8>,
    bits: usize,
    refs: Vec<Arc<Cell>>,
    hash: [u8; 32],
    depth: u16,
}

impl Cell {
    pub fn hash(&self) -> [u8; 32] {
        self.hash
    }
}

#[derive(Default, Clone)]
pub struct Builder {
    data: Vec<u8>,
    bits: usize,
    refs: Vec<Arc<Cell>>,
}

impl Builder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn bit(mut self, b: bool) -> Self {
        if self.bits % 8 == 0 {
            self.data.push(0);
        }
        if b {
            *self.data.last_mut().unwrap() |= 0x80 >> (self.bits % 8);
        }
        self.bits += 1;
        self
    }

    /// Store the lowest `n` bits of `v`, big-endian.
    pub fn uint(mut self, v: u64, n: usize) -> Self {
        for i in (0..n).rev() {
            self = self.bit(v >> i & 1 == 1);
        }
        self
    }

    pub fn bytes(mut self, b: &[u8]) -> Self {
        for &x in b {
            self = self.uint(x as u64, 8);
        }
        self
    }

    /// Append all bits and refs of another builder.
    pub fn append(mut self, other: &Builder) -> Self {
        for i in 0..other.bits {
            self = self.bit(other.data[i / 8] & (0x80 >> (i % 8)) != 0);
        }
        self.refs.extend(other.refs.iter().cloned());
        self
    }

    pub fn reference(mut self, c: Arc<Cell>) -> Self {
        self.refs.push(c);
        self
    }

    pub fn build(self) -> Arc<Cell> {
        assert!(self.bits <= 1023 && self.refs.len() <= 4, "cell overflow");
        let depth = self.refs.iter().map(|r| r.depth + 1).max().unwrap_or(0);
        let mut h = Sha256::new();
        h.update(descriptors(self.bits, self.refs.len()));
        h.update(padded(&self.data, self.bits));
        for r in &self.refs {
            h.update(r.depth.to_be_bytes());
        }
        for r in &self.refs {
            h.update(r.hash);
        }
        Arc::new(Cell { data: self.data, bits: self.bits, refs: self.refs, hash: h.finalize().into(), depth })
    }
}

fn descriptors(bits: usize, refs: usize) -> [u8; 2] {
    [refs as u8, (bits / 8 + bits.div_ceil(8)) as u8]
}

/// Data bytes with the completion tag when the bit length is not a multiple of 8.
fn padded(data: &[u8], bits: usize) -> Vec<u8> {
    let mut d = data.to_vec();
    if bits % 8 != 0 {
        *d.last_mut().unwrap() |= 0x80 >> (bits % 8);
    }
    d
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0x82F6_3B78 } else { crc >> 1 };
        }
    }
    !crc
}

/// Serialize one root to BOC (no index, with CRC32C). Parents always precede children.
pub fn to_boc(root: &Arc<Cell>) -> Vec<u8> {
    let mut order: Vec<Arc<Cell>> = Vec::new();
    fn visit(c: &Arc<Cell>, order: &mut Vec<Arc<Cell>>) {
        if let Some(pos) = order.iter().position(|x| x.hash == c.hash) {
            // Re-append so it ends up after every parent that references it.
            let x = order.remove(pos);
            order.push(x);
        } else {
            order.push(c.clone());
        }
        for r in &c.refs {
            visit(r, order);
        }
    }
    visit(root, &mut order);
    let index = |h: &[u8; 32]| order.iter().position(|x| &x.hash == h).unwrap();

    let s = 1usize; // < 256 cells
    assert!(order.len() < 256);
    let mut cells = Vec::new();
    for c in &order {
        cells.extend(descriptors(c.bits, c.refs.len()));
        cells.extend(padded(&c.data, c.bits));
        for r in &c.refs {
            cells.push(index(&r.hash) as u8);
        }
    }
    let off = (1..=8).find(|&n| cells.len() < 1usize << (8 * n)).unwrap();

    let mut out = vec![0xb5, 0xee, 0x9c, 0x72, 0x40 | s as u8, off as u8];
    out.push(order.len() as u8); // cells
    out.push(1); // roots
    out.push(0); // absent
    out.extend(&(cells.len() as u64).to_be_bytes()[8 - off..]);
    out.push(0); // root index
    out.extend(cells);
    let crc = crc32c(&out);
    out.extend(crc.to_le_bytes());
    out
}
