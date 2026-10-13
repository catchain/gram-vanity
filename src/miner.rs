use crate::wallet;
use serde::Serialize;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use zeroize::Zeroizing;

const ALPHABET: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
pub const MAX_LEN: usize = 10;

#[derive(Clone, Debug)]
pub struct Pattern {
    /// Characters right after "UQ".
    pub prefix: String,
    pub suffix: String,
    pub case_insensitive: bool,
}

impl Pattern {
    pub fn new(prefix: &str, suffix: &str, case_insensitive: bool) -> Result<Self, String> {
        let (prefix, suffix) = (prefix.trim(), suffix.trim());
        if prefix.is_empty() && suffix.is_empty() {
            return Err("укажите начало или окончание".into());
        }
        if prefix.len() + suffix.len() > MAX_LEN {
            return Err(format!("не больше {MAX_LEN} символов суммарно"));
        }
        if let Some(c) = prefix.chars().chain(suffix.chars()).find(|c| !ALPHABET.contains(*c)) {
            return Err(format!("символ «{c}» не встречается в адресе. Допустимо: A–Z a–z 0–9 - _"));
        }
        if let Some(c) = prefix.chars().next() {
            // Third char of "UQ.." encodes 2 zero bits of the workchain byte + 2 hash bits.
            let ok = if case_insensitive { "ABCDabcd".contains(c) } else { "ABCD".contains(c) };
            if !ok {
                return Err("первый символ после «UQ» может быть только A, B, C или D".into());
            }
        }
        Ok(Self { prefix: prefix.into(), suffix: suffix.into(), case_insensitive })
    }

    /// Expected number of attempts (1 / probability).
    pub fn expected_attempts(&self) -> f64 {
        let char_p = |c: char| {
            if self.case_insensitive && c.is_ascii_alphabetic() { 2.0 / 64.0 } else { 1.0 / 64.0 }
        };
        let mut p = 1.0;
        for (i, c) in self.prefix.chars().enumerate() {
            p *= if i == 0 { 0.25 } else { char_p(c) };
        }
        for c in self.suffix.chars() {
            p *= char_p(c);
        }
        1.0 / p
    }

    pub fn matches(&self, addr: &str) -> bool {
        let a = addr.as_bytes();
        let pre = &a[2..2 + self.prefix.len()];
        let suf = &a[a.len() - self.suffix.len()..];
        if self.case_insensitive {
            pre.eq_ignore_ascii_case(self.prefix.as_bytes())
                && suf.eq_ignore_ascii_case(self.suffix.as_bytes())
        } else {
            pre == self.prefix.as_bytes() && suf == self.suffix.as_bytes()
        }
    }
}

#[derive(Serialize, Clone)]
pub struct Found {
    pub address: String,
    pub words: String,
    pub public_key: String,
    pub attempts: u64,
    pub seconds: f64,
}

impl Drop for Found {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(&mut self.words);
    }
}

pub struct Job {
    pub pattern: Pattern,
    pub want: usize,
    pub threads: usize,
    pub started: Instant,
    pub stop: AtomicBool,
    pub attempts: AtomicU64,
    pub found: Mutex<Vec<Found>>,
    pub finished: Mutex<Option<Instant>>,
}

impl Job {
    pub fn elapsed(&self) -> f64 {
        let end = self.finished.lock().unwrap().unwrap_or_else(Instant::now);
        (end - self.started).as_secs_f64()
    }
    pub fn running(&self) -> bool {
        self.finished.lock().unwrap().is_none()
    }
    pub fn request_stop(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

pub fn default_threads() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4)
}

pub fn start(pattern: Pattern, want: usize, threads: usize) -> Arc<Job> {
    let job = Arc::new(Job {
        pattern,
        want: want.max(1),
        threads: threads.max(1),
        started: Instant::now(),
        stop: AtomicBool::new(false),
        attempts: AtomicU64::new(0),
        found: Mutex::new(Vec::new()),
        finished: Mutex::new(None),
    });
    let live = Arc::new(AtomicU64::new(job.threads as u64));
    for _ in 0..job.threads {
        let job = job.clone();
        let live = live.clone();
        std::thread::spawn(move || {
            worker(&job);
            if live.fetch_sub(1, Ordering::AcqRel) == 1 {
                *job.finished.lock().unwrap() = Some(Instant::now());
            }
        });
    }
    job
}

fn worker(job: &Job) {
    let code_hash = wallet::code_hash();
    let mut entropy = Zeroizing::new([0u8; 16]);
    while !job.stop.load(Ordering::Relaxed) {
        // Fresh 128 bits from the OS CSPRNG for every candidate.
        getrandom::getrandom(&mut *entropy).expect("OS RNG unavailable");
        let m = bip39::Mnemonic::from_entropy(&*entropy).expect("16 bytes is valid entropy");
        let phrase = Zeroizing::new(m.words().collect::<Vec<_>>().join(" "));
        let keys = wallet::keys_from_phrase(&phrase);
        let addr = wallet::friendly(&wallet::address_hash(&code_hash, &keys.public, wallet::WALLET_ID_MAINNET));
        let n = job.attempts.fetch_add(1, Ordering::Relaxed) + 1;
        if job.pattern.matches(&addr) {
            let mut found = job.found.lock().unwrap();
            if found.len() < job.want {
                found.push(Found {
                    address: addr,
                    words: phrase.to_string(),
                    public_key: wallet::hex(&keys.public),
                    attempts: n,
                    seconds: job.started.elapsed().as_secs_f64(),
                });
            }
            if found.len() >= job.want {
                job.request_stop();
            }
        }
    }
}
