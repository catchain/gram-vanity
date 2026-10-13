//! GPU worker run over SSH from this process.
//!
//! Spawns the local `ssh` client (no shell): uploads the worker sources on stdin, builds them and
//! starts the search on the server. The worker prints the anchor on stdout; this module checks it
//! on the CPU and keeps it for the UI. Uses the user's SSH keys/agent; no password prompts.
//!
//! On stop, the local ssh is killed. The remote worker then dies on its next progress write
//! (every 5 s) from SIGPIPE, because its stderr goes to the closed SSH channel.

use crate::{miner, wallet};
use std::collections::VecDeque;
use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use zeroize::Zeroizing;

const LOG_LINES: usize = 40;

pub struct Found {
    pub address: String,
    pub words: Zeroizing<String>,
}

pub struct Job {
    pub pattern: miner::Pattern,
    pub target: String,
    pub started: Instant,
    child: Mutex<Option<Child>>,
    log: Mutex<VecDeque<String>>,
    progress: Mutex<String>,
    pub found: Mutex<Option<Found>>,
    /// Some(message) when ssh has exited.
    exit: Mutex<Option<String>>,
    stopped: std::sync::atomic::AtomicBool,
}

pub struct Status {
    pub running: bool,
    pub log: Vec<String>,
    pub progress: String,
    pub exit: Option<String>,
    pub elapsed: f64,
}

impl Job {
    pub fn running(&self) -> bool {
        self.exit.lock().unwrap().is_none()
    }
    pub fn stop(&self) {
        self.stopped.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(c) = self.child.lock().unwrap().as_mut() {
            let _ = c.kill();
        }
    }
    pub fn status(&self) -> Status {
        Status {
            running: self.running(),
            log: self.log.lock().unwrap().iter().cloned().collect(),
            progress: self.progress.lock().unwrap().clone(),
            exit: self.exit.lock().unwrap().clone(),
            elapsed: self.started.elapsed().as_secs_f64(),
        }
    }
    fn push(&self, line: &str) {
        let line = line.trim_end();
        if line.is_empty() {
            return;
        }
        let mut log = self.log.lock().unwrap();
        if log.len() == LOG_LINES {
            log.pop_front();
        }
        log.push_back(line.to_string());
    }
}

/// `user@host` or `host`: address chars only, no leading "-" (would be an ssh option).
pub fn valid_target(t: &str) -> bool {
    let host_ok = |h: &str| !h.is_empty() && !h.starts_with('-')
        && h.chars().all(|c| c.is_ascii_alphanumeric() || ".:_[]-".contains(c));
    match t.split_once('@') {
        Some((u, h)) => !u.is_empty() && !u.starts_with('-')
            && u.chars().all(|c| c.is_ascii_alphanumeric() || "._-".contains(c)) && host_ok(h),
        None => host_ok(t),
    }
}

/// Remote script. Keep in sync with gpuCmd() in ui/index.html (manual command).
fn remote_script(p: &miner::Pattern) -> String {
    let mut args = Vec::new();
    if !p.prefix.is_empty() {
        args.push(format!("--prefix {}", p.prefix));
    }
    if !p.suffix.is_empty() {
        args.push(format!("--suffix {}", p.suffix));
    }
    if p.case_insensitive {
        args.push("--ci".into());
    }
    [
        "set -e",
        r#"export PATH="$PATH:/usr/local/cuda/bin""#,
        r#"S=$([ "$(id -u)" = 0 ] || echo sudo)"#,
        "command -v make >/dev/null && command -v g++ >/dev/null || { $S apt-get update -qq && $S apt-get install -y -qq build-essential >/dev/null; }",
        r#"command -v nvcc >/dev/null || { echo "nvcc not found: use a CUDA devel image" >&2; exit 1; }"#,
        "mkdir -p ~/vanity-worker && cd ~/vanity-worker && tar xzf -",
        "echo 'building worker…' >&2",
        "make -s",
        &format!("./vanity-worker {}", args.join(" ")),
    ]
    .join("; ")
}

pub fn start(pattern: miner::Pattern, target: &str, port: u16, worker_tar: Vec<u8>) -> Result<Arc<Job>, String> {
    // Pattern chars are [A-Za-z0-9_-] (checked by Pattern::new), so the remote script is shell-safe.
    let mut child = Command::new("ssh")
        .args(["-p", &port.to_string()])
        .args(["-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"])
        .args(["-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=4"])
        .arg("--")
        .arg(target)
        .arg(remote_script(&pattern))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("не удалось запустить ssh: {e}"))?;
    let (mut stdin, stdout, stderr) = (child.stdin.take().unwrap(), child.stdout.take().unwrap(), child.stderr.take().unwrap());
    let job = Arc::new(Job {
        pattern,
        target: target.to_string(),
        started: Instant::now(),
        child: Mutex::new(Some(child)),
        log: Mutex::new(VecDeque::new()),
        progress: Mutex::new(String::new()),
        found: Mutex::new(None),
        exit: Mutex::new(None),
        stopped: Default::default(),
    });
    job.push(&format!("ssh -p {port} {target}"));

    std::thread::spawn(move || {
        let _ = stdin.write_all(&worker_tar);
        // Dropping stdin sends EOF, so the remote `tar xzf -` finishes.
    });

    // stderr: ssh errors, build output and the worker's "\r" progress line.
    let j = job.clone();
    let err_thread = std::thread::spawn(move || {
        let mut r = BufReader::new(stderr);
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while r.read(&mut byte).is_ok_and(|n| n == 1) {
            match byte[0] {
                b'\r' | b'\n' => {
                    let s = String::from_utf8_lossy(&buf).trim().to_string();
                    buf.clear();
                    if s.is_empty() {
                        continue;
                    }
                    if s.contains("attempts,") && s.contains("/s") {
                        *j.progress.lock().unwrap() = s;
                    } else {
                        j.push(&s);
                    }
                }
                b => buf.push(b),
            }
        }
    });

    // stdout: "address: …" and "anchor:  w1 … w12".
    let j = job.clone();
    std::thread::spawn(move || {
        let mut address = String::new();
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { break };
            let line = Zeroizing::new(line);
            if let Some(a) = line.strip_prefix("address:") {
                address = a.trim().to_string();
                j.push(&line);
            } else if let Some(w) = line.strip_prefix("anchor:") {
                j.push("anchor:  ••• (12 слов получены)");
                accept(&j, &address, w);
            } else {
                j.push(&line);
            }
        }
        let _ = err_thread.join();
        let child = j.child.lock().unwrap().take();
        let status = child.and_then(|mut c| c.wait().ok());
        let msg = if j.found.lock().unwrap().is_some() {
            "якорь найден".to_string()
        } else if j.stopped.load(std::sync::atomic::Ordering::Relaxed) {
            "остановлено".to_string()
        } else {
            match status.and_then(|s| s.code()) {
                Some(255) => "ssh не подключился: проверьте адрес, порт и SSH-ключ".into(),
                Some(c) => format!("сервер завершил работу с кодом {c}"),
                None => "ssh прерван".into(),
            }
        };
        *j.exit.lock().unwrap() = Some(msg);
    });
    Ok(job)
}

/// Re-check the worker's result on the CPU before the UI may use it.
fn accept(job: &Job, address: &str, words: &str) {
    let msg = match wallet::normalize_words(&Zeroizing::new(words.trim().to_string())) {
        Err(e) => format!("якорь от сервера отклонён: {e}"),
        Ok(w) => match wallet::address_from_words(&w) {
            Ok((a, _)) if a == address && job.pattern.matches(&a) => {
                *job.found.lock().unwrap() = Some(Found { address: a, words: w });
                return;
            }
            Ok(_) => "якорь от сервера отклонён: адрес не совпадает с проверкой на CPU".into(),
            Err(e) => format!("якорь от сервера отклонён: {e}"),
        },
    };
    job.push(&msg);
}
