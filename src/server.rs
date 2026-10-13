//! Local-only HTTP UI.
//!
//! Binds 127.0.0.1 only. Two pages on two ports, so they are two browser origins:
//! - main port, `/`: shows words. Strict CSP, no external requests. API needs the session token
//!   (printed in the terminal, passed in the URL fragment) + localhost Host/Origin headers.
//! - deploy port, `/deploy`: TON Connect (vendored bundle, talks to wallet bridges). Different
//!   origin, so its scripts cannot reach the main page or its API. It gets a per-session deploy
//!   token that can only read the public transaction payload: never the words.

use crate::{gpu, miner, rotation, wallet};
use base64::Engine;
use serde::Deserialize;
use serde_json::json;
use std::collections::HashMap;
use std::io::Read;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tiny_http::{Header, Method, Request, Response, Server};
use zeroize::Zeroizing;

const INDEX: &str = include_str!("../ui/index.html");
const DEPLOY: &str = include_str!("../ui/deploy.html");
const TONCONNECT_JS: &[u8] = include_bytes!("../ui/vendor/tonconnect-ui.min.js");

macro_rules! fonts {
    ($($name:literal),* $(,)?) => {
        &[$(($name, include_bytes!(concat!("../ui/fonts/", $name)) as &[u8])),*]
    };
}
const FONTS: &[(&str, &[u8])] = fonts![
    "onest-latin-400-normal.woff2", "onest-cyrillic-400-normal.woff2",
    "onest-latin-600-normal.woff2", "onest-cyrillic-600-normal.woff2",
    "onest-latin-700-normal.woff2", "onest-cyrillic-700-normal.woff2",
    "jetbrains-mono-latin-500-normal.woff2", "jetbrains-mono-cyrillic-500-normal.woff2",
    "jetbrains-mono-latin-700-normal.woff2", "jetbrains-mono-cyrillic-700-normal.woff2",
];

/// Worker sources, served as /worker.tar.gz for the one-line SSH install (no secrets inside).
macro_rules! worker_files {
    ($($name:literal),* $(,)?) => {
        &[$(($name, include_bytes!(concat!("../worker/", $name)) as &[u8])),*]
    };
}
const WORKER_FILES: &[(&str, &[u8])] = worker_files![
    "Makefile", "README.md", "worker.cu", "host_core.cpp", "core.h", "bip39_en.h",
    "ed25519/fe.c", "ed25519/ge.c", "ed25519/precomp_data.h", "ed25519/protos.h",
    "ed25519/types.h", "ed25519/license.txt",
];

fn worker_tar_gz() -> Vec<u8> {
    let gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    let mut tar = tar::Builder::new(gz);
    for (name, data) in WORKER_FILES {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        h.set_mtime(0);
        h.set_cksum();
        tar.append_data(&mut h, name, *data).expect("tar");
    }
    tar.into_inner().and_then(|gz| gz.finish()).expect("gzip")
}

const CSP_MAIN: &str = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; \
    connect-src 'self'; font-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const CSP_DEPLOY: &str = "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; \
    connect-src 'self' https: wss:; font-src 'self'; img-src 'self' data: https:; base-uri 'none'; \
    form-action 'none'; frame-ancestors 'none'";

#[derive(Deserialize)]
struct PatternReq {
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    suffix: String,
    #[serde(default)]
    case_insensitive: bool,
    #[serde(default)]
    threads: Option<usize>,
}

#[derive(Deserialize)]
struct GpuReq {
    #[serde(default)]
    prefix: String,
    #[serde(default)]
    suffix: String,
    #[serde(default)]
    case_insensitive: bool,
    host: String,
    #[serde(default)]
    port: Option<u16>,
}

#[derive(Deserialize)]
struct WordsReq {
    words: String,
}

#[derive(Deserialize)]
struct IdReq {
    id: String,
}

struct Session {
    anchor: Zeroizing<String>,
    signing: Zeroizing<String>,
    address: String,
    anchor_pub: String,
    new_public: String,
    deploy_token: String,
}

fn sessions() -> &'static Mutex<HashMap<String, Session>> {
    static S: OnceLock<Mutex<HashMap<String, Session>>> = OnceLock::new();
    S.get_or_init(|| Mutex::new(HashMap::new()))
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    getrandom::getrandom(&mut b).expect("OS RNG unavailable");
    wallet::hex(&b)
}

/// Requests that call toncenter can take seconds, so each port has a few handler threads.
const THREADS_PER_PORT: usize = 4;

struct Ctx {
    token: String,
    main_hosts: [String; 2],
    deploy_hosts: [String; 2],
    deploy_port: u16,
    deploy_page: String,
    job: Mutex<Option<Arc<miner::Job>>>,
    gpu: Mutex<Option<Arc<gpu::Job>>>,
}

/// Public manifest from this repo: the wallet app downloads it, so it cannot be served from localhost.
pub const DEFAULT_MANIFEST_URL: &str = "https://raw.githubusercontent.com/catchain/gram-vanity/main/ui/tonconnect-manifest.json";

pub fn run(port: u16, open_browser: bool, manifest_url: String) -> Result<(), String> {
    let main = Server::http(("127.0.0.1", port)).map_err(|e| format!("не удалось занять порт: {e}"))?;
    let deploy = Server::http(("127.0.0.1", 0)).map_err(|e| format!("не удалось занять порт: {e}"))?;
    let port = main.server_addr().to_ip().map(|a| a.port()).unwrap_or(port);
    let deploy_port = deploy.server_addr().to_ip().map(|a| a.port()).ok_or("нет порта")?;
    if !manifest_url.starts_with("https://") {
        return Err(format!("--manifest-url должен начинаться с https://, получено {manifest_url}"));
    }
    let hosts = |p: u16| [format!("127.0.0.1:{p}"), format!("localhost:{p}")];
    let token = random_hex(24);
    let url = format!("http://127.0.0.1:{port}/#t={token}");
    // JSON string inside an inline <script>: escape "<" so "</script>" cannot appear.
    let manifest_js = json!(manifest_url).to_string().replace('<', "\\u003c");
    let ctx = Arc::new(Ctx {
        token,
        main_hosts: hosts(port),
        deploy_hosts: hosts(deploy_port),
        deploy_port,
        deploy_page: DEPLOY.replace("__MANIFEST_URL__", &manifest_js),
        job: Mutex::new(None),
        gpu: Mutex::new(None),
    });

    println!("Gram Vanity запущен: {url}");
    println!("Сервер слушает только 127.0.0.1. Ctrl+C — остановить и стереть всё из памяти.");
    if !rotation::has_api_key() {
        println!("toncenter без ключа: 1 запрос в секунду. Этого хватает. Ключ (TONCENTER_API_KEY в .env) необязателен.");
    }
    if open_browser {
        open_url(&url);
    }

    let mut threads = Vec::new();
    for (server, is_deploy) in [(Arc::new(main), false), (Arc::new(deploy), true)] {
        for _ in 0..THREADS_PER_PORT {
            let (server, ctx) = (server.clone(), ctx.clone());
            threads.push(std::thread::spawn(move || {
                while let Ok(req) = server.recv() {
                    if is_deploy { serve_deploy(&ctx, req) } else { serve_main(&ctx, req) }
                }
            }));
        }
    }
    for t in threads {
        let _ = t.join();
    }
    Ok(())
}

fn open_url(url: &str) {
    #[cfg(target_os = "macos")]
    let _ = std::process::Command::new("open").arg(url).status();
    #[cfg(target_os = "linux")]
    let _ = std::process::Command::new("xdg-open").arg(url).status();
    #[cfg(target_os = "windows")]
    let _ = std::process::Command::new("cmd").args(["/C", "start", "", url]).status();
}

/// Host must be this port on localhost; Origin, if present, must be this exact origin.
fn local_only(req: &Request, hosts: &[String; 2]) -> bool {
    let host_ok = header(req, "Host").is_some_and(|h| hosts.contains(&h));
    let origin_ok = header(req, "Origin").is_none_or(|o| hosts.iter().any(|h| o == format!("http://{h}")));
    host_ok && origin_ok
}

fn font(path: &str) -> Option<&'static [u8]> {
    let name = path.strip_prefix("/fonts/")?;
    FONTS.iter().find(|(f, _)| *f == name).map(|(_, d)| *d)
}

fn path_of(req: &Request) -> String {
    req.url().split('?').next().unwrap_or("").to_string()
}

fn serve_main(ctx: &Ctx, mut req: Request) {
    if !local_only(&req, &ctx.main_hosts) {
        return respond(req, 403, "text/plain", "forbidden", CSP_MAIN);
    }
    let path = path_of(&req);
    if req.method() == &Method::Get {
        match path.as_str() {
            "/" => return respond(req, 200, "text/html; charset=utf-8", INDEX, CSP_MAIN),
            "/worker.tar.gz" => return respond(req, 200, "application/gzip", worker_tar_gz(), CSP_MAIN),
            _ => {}
        }
        if let Some(data) = font(&path) {
            return respond(req, 200, "font/woff2", data, CSP_MAIN);
        }
    }
    if !path.starts_with("/api/") {
        return respond(req, 404, "text/plain", "not found", CSP_MAIN);
    }
    if header(&req, "X-Token").as_deref() != Some(ctx.token.as_str()) {
        return respond(req, 401, "application/json", json!({"error": "bad token"}).to_string(), CSP_MAIN);
    }
    let mut body = Zeroizing::new(String::new());
    let _ = req.as_reader().take(16 * 1024).read_to_string(&mut body);
    let (code, out) = handle(ctx, req.method(), &path, &body);
    respond(req, code, "application/json", out.to_string(), CSP_MAIN);
}

fn serve_deploy(ctx: &Ctx, mut req: Request) {
    if !local_only(&req, &ctx.deploy_hosts) {
        return respond(req, 403, "text/plain", "forbidden", CSP_DEPLOY);
    }
    let path = path_of(&req);
    if req.method() == &Method::Get {
        match path.as_str() {
            "/deploy" => return respond(req, 200, "text/html; charset=utf-8", ctx.deploy_page.as_str(), CSP_DEPLOY),
            "/vendor/tonconnect-ui.min.js" => {
                return respond(req, 200, "text/javascript; charset=utf-8", TONCONNECT_JS, CSP_DEPLOY);
            }
            _ => {}
        }
        if let Some(data) = font(&path) {
            return respond(req, 200, "font/woff2", data, CSP_DEPLOY);
        }
    }
    if !path.starts_with("/api/deploy/") || req.method() != &Method::Post {
        return respond(req, 404, "text/plain", "not found", CSP_DEPLOY);
    }
    let mut body = String::new();
    let _ = req.as_reader().take(4 * 1024).read_to_string(&mut body);
    let dt = header(&req, "X-Deploy-Token").unwrap_or_default();
    let (code, out) = deploy_api(&path, &body, &dt);
    respond(req, code, "application/json", out.to_string(), CSP_DEPLOY);
}

fn err(c: u16, m: impl Into<String>) -> (u16, serde_json::Value) {
    (c, json!({ "error": m.into() }))
}

fn handle(ctx: &Ctx, method: &Method, path: &str, body: &str) -> (u16, serde_json::Value) {
    let job = &ctx.job;
    match (method, path) {
        (Method::Get, "/api/info") => (200, json!({
            "worker_url": "/worker.tar.gz",
            "threads": miner::default_threads(),
            "max_len": miner::MAX_LEN,
            "deploy_value": rotation::DEPLOY_VALUE_NANO.to_string(),
        })),
        (Method::Post, "/api/estimate") => {
            let Ok(r) = serde_json::from_str::<PatternReq>(body) else { return err(400, "bad json") };
            match miner::Pattern::new(&r.prefix, &r.suffix, r.case_insensitive) {
                Ok(p) => (200, json!({ "expected_attempts": p.expected_attempts() })),
                Err(e) => err(400, e),
            }
        }
        // Local CPU search for an anchor.
        (Method::Post, "/api/start") => {
            let Ok(r) = serde_json::from_str::<PatternReq>(body) else { return err(400, "bad json") };
            let p = match miner::Pattern::new(&r.prefix, &r.suffix, r.case_insensitive) {
                Ok(p) => p,
                Err(e) => return err(400, e),
            };
            let mut slot = job.lock().unwrap();
            if slot.as_ref().is_some_and(|j| j.running()) {
                return err(409, "подбор уже идёт");
            }
            let threads = r.threads.unwrap_or_else(miner::default_threads).clamp(1, 256);
            *slot = Some(miner::start(p, 1, threads));
            (200, json!({ "ok": true }))
        }
        (Method::Post, "/api/stop") => {
            if let Some(j) = job.lock().unwrap().as_ref() {
                j.request_stop();
            }
            (200, json!({ "ok": true }))
        }
        (Method::Post, "/api/clear") => {
            let mut slot = job.lock().unwrap();
            if slot.as_ref().is_some_and(|j| j.running()) {
                return err(409, "сначала остановите подбор");
            }
            let mut g = ctx.gpu.lock().unwrap();
            if g.as_ref().is_some_and(|j| j.running()) {
                return err(409, "сначала остановите подбор на сервере");
            }
            *slot = None; // Found::drop zeroizes the words
            *g = None; // gpu::Found words are Zeroizing
            sessions().lock().unwrap().clear(); // Session strings are Zeroizing
            (200, json!({ "ok": true }))
        }
        (Method::Get, "/api/status") => {
            let slot = job.lock().unwrap();
            let Some(j) = slot.as_ref() else { return (200, json!({ "job": null })) };
            let attempts = j.attempts.load(std::sync::atomic::Ordering::Relaxed);
            let elapsed = j.elapsed();
            let found = j.found.lock().unwrap().clone();
            (200, json!({ "job": {
                "running": j.running(),
                "prefix": j.pattern.prefix,
                "suffix": j.pattern.suffix,
                "case_insensitive": j.pattern.case_insensitive,
                "threads": j.threads,
                "attempts": attempts,
                "elapsed": elapsed,
                "rate": if elapsed > 0.0 { attempts as f64 / elapsed } else { 0.0 },
                "expected_attempts": j.pattern.expected_attempts(),
                "found": found.first().map(|f| json!({
                    "address": f.address, "anchor_words": f.words, "attempts": f.attempts, "seconds": f.seconds,
                })),
            }}))
        }
        // GPU worker over SSH, started from this process.
        (Method::Post, "/api/gpu/start") => {
            let Ok(r) = serde_json::from_str::<GpuReq>(body) else { return err(400, "bad json") };
            let p = match miner::Pattern::new(&r.prefix, &r.suffix, r.case_insensitive) {
                Ok(p) => p,
                Err(e) => return err(400, e),
            };
            let host = r.host.trim();
            if !gpu::valid_target(host) {
                return err(400, "SSH-адрес: user@host или host, без пробелов и опций");
            }
            let port = r.port.unwrap_or(22);
            if port == 0 {
                return err(400, "неверный порт");
            }
            let mut slot = ctx.gpu.lock().unwrap();
            if slot.as_ref().is_some_and(|j| j.running()) {
                return err(409, "подбор на сервере уже идёт");
            }
            match gpu::start(p, host, port, worker_tar_gz()) {
                Ok(j) => {
                    *slot = Some(j);
                    (200, json!({ "ok": true }))
                }
                Err(e) => err(500, e),
            }
        }
        (Method::Post, "/api/gpu/stop") => {
            if let Some(j) = ctx.gpu.lock().unwrap().as_ref() {
                j.stop();
            }
            (200, json!({ "ok": true }))
        }
        (Method::Get, "/api/gpu/status") => {
            let slot = ctx.gpu.lock().unwrap();
            let Some(j) = slot.as_ref() else { return (200, json!({ "gpu": null })) };
            let st = j.status();
            let found = j.found.lock().unwrap();
            (200, json!({ "gpu": {
                "running": st.running,
                "target": j.target,
                "prefix": j.pattern.prefix,
                "suffix": j.pattern.suffix,
                "case_insensitive": j.pattern.case_insensitive,
                "elapsed": st.elapsed,
                "log": st.log,
                "progress": st.progress,
                "exit": st.exit,
                "found": found.as_ref().map(|f| json!({ "address": f.address, "anchor_words": *f.words })),
            }}))
        }
        // Anchor (from CPU search or a GPU worker) -> new signing half, kept in memory.
        (Method::Post, "/api/session") => {
            let Ok(r) = serde_json::from_str::<WordsReq>(body) else { return err(400, "bad json") };
            let anchor = match wallet::normalize_words(&Zeroizing::new(r.words)) {
                Ok(a) => a,
                Err(e) => return err(400, e),
            };
            let mut map = sessions().lock().unwrap();
            if let Some((id, s)) = map.iter().find(|(_, s)| *s.anchor == *anchor) {
                return (200, session_json(ctx, id, s));
            }
            let signing = wallet::new_words();
            let (address, apk) = wallet::address_from_words(&anchor).unwrap();
            let s = Session {
                new_public: wallet::hex(&wallet::keys_from_phrase(&signing).public),
                anchor_pub: wallet::hex(&apk),
                address,
                anchor,
                signing,
                deploy_token: random_hex(24),
            };
            let id = random_hex(12);
            let out = session_json(ctx, &id, &s);
            map.insert(id, s);
            (200, out)
        }
        (Method::Post, "/api/session/state") => {
            let Ok(r) = serde_json::from_str::<IdReq>(body) else { return err(400, "bad json") };
            chain_state(&r.id)
        }
        // 24 words -> address and signing key (local check before import).
        (Method::Post, "/api/verify") => {
            let Ok(r) = serde_json::from_str::<WordsReq>(body) else { return err(400, "bad json") };
            let words = Zeroizing::new(r.words);
            let w: Vec<&str> = words.split_whitespace().collect();
            if w.len() != 24 {
                return err(400, format!("нужно 24 слова, получено {}", w.len()));
            }
            let anchor = Zeroizing::new(w[..12].join(" "));
            let signing = Zeroizing::new(w[12..].join(" "));
            let (address, _) = match wallet::address_from_words(&anchor) {
                Ok(a) => a,
                Err(e) => return err(400, format!("слова 1–12: {e}")),
            };
            let signing = match wallet::normalize_words(&signing) {
                Ok(s) => s,
                Err(e) => return err(400, format!("слова 13–24: {e}")),
            };
            let key = wallet::hex(&wallet::keys_from_phrase(&signing).public);
            let onchain = rotation::public_key(&address).ok();
            (200, json!({ "address": address, "public_key": key, "onchain_key": onchain }))
        }
        _ => err(404, "not found"),
    }
}

fn session_json(ctx: &Ctx, id: &str, s: &Session) -> serde_json::Value {
    json!({
        "id": id,
        "address": s.address,
        "anchor_words": *s.anchor,
        "signing_words": *s.signing,
        "new_public_key": s.new_public,
        "deploy_url": format!("http://127.0.0.1:{}/deploy#s={id}&d={}", ctx.deploy_port, s.deploy_token),
    })
}

/// `chain_state` with a short per-session cache: the main page and the deploy page both poll it,
/// and without an API key toncenter allows only 1 request/s.
fn chain_state(id: &str) -> (u16, serde_json::Value) {
    static CACHE: OnceLock<Mutex<HashMap<String, (Instant, serde_json::Value)>>> = OnceLock::new();
    // toncenter calls are serialised by the throttle anyway: one fetch at a time lets a
    // concurrent poll for the same session take the fresh result instead of fetching again.
    static FETCH: Mutex<()> = Mutex::new(());
    let cache = CACHE.get_or_init(Default::default);
    let cached = || {
        let c = cache.lock().unwrap();
        c.get(id).filter(|(t, _)| t.elapsed() < Duration::from_secs(3)).map(|(_, v)| v.clone())
    };
    if let Some(v) = cached() {
        return (200, v);
    }
    let _fetch = FETCH.lock().unwrap();
    if let Some(v) = cached() {
        return (200, v);
    }
    let (code, v) = fetch_chain_state(id);
    if code == 200 && v.get("network_error").is_none() {
        let mut c = cache.lock().unwrap();
        c.retain(|_, (t, _)| t.elapsed() < Duration::from_secs(60));
        c.insert(id.to_string(), (Instant::now(), v.clone()));
    }
    (code, v)
}

/// Public on-chain phase of a session's address (toncenter, read-only).
fn fetch_chain_state(id: &str) -> (u16, serde_json::Value) {
    let (address, anchor_pub, new_public) = {
        let map = sessions().lock().unwrap();
        let Some(s) = map.get(id) else { return err(404, "сессия не найдена") };
        (s.address.clone(), s.anchor_pub.clone(), s.new_public.clone())
    };
    let acc = match rotation::account(&address) {
        Ok(a) => a,
        Err(e) => return (200, json!({ "address": address, "network_error": e })),
    };
    let key = if acc.state == "active" {
        match rotation::public_key(&address) {
            Ok(k) => Some(k),
            // Unknown key is not "ready": report a network problem instead of a wrong phase.
            Err(e) => return (200, json!({ "address": address, "network_error": e })),
        }
    } else {
        None
    };
    let phase = match key.as_deref() {
        Some(k) if k == new_public => "done",
        Some(k) if k == anchor_pub => "deployed_anchor",
        Some(_) => "foreign",
        None => "ready",
    };
    (200, json!({
        "address": address, "state": acc.state, "balance": acc.balance.to_string(),
        "phase": phase, "public_key": key,
    }))
}

/// Deploy page API: only public data, authorised by the per-session deploy token.
fn deploy_api(path: &str, body: &str, deploy_token: &str) -> (u16, serde_json::Value) {
    let Ok(r) = serde_json::from_str::<IdReq>(body) else { return err(400, "bad json") };
    let ok = sessions().lock().unwrap().get(&r.id).is_some_and(|s| !deploy_token.is_empty() && s.deploy_token == deploy_token);
    if !ok {
        return err(401, "сессия не найдена или стёрта. Откройте страницу кнопкой из Gram Vanity");
    }
    match path {
        "/api/deploy/state" => chain_state(&r.id),
        "/api/deploy/payload" => {
            let (anchor, signing, address, anchor_pub, new_public) = {
                let map = sessions().lock().unwrap();
                let s = &map[&r.id];
                (s.anchor.clone(), s.signing.clone(), s.address.clone(), s.anchor_pub.clone(), s.new_public.clone())
            };
            // Deployed earlier with the anchor key: no StateInit, use its seqno.
            let acc = match rotation::account(&address) {
                Ok(a) => a,
                Err(e) => return err(502, e),
            };
            let (seqno, with_init) = if acc.state == "active" {
                match rotation::public_key(&address) {
                    Ok(k) if k == new_public => return err(409, "ключ уже сменён"),
                    Ok(k) if k != anchor_pub => return err(409, "ключ кошелька уже сменён на чужой. Отправка заблокирована"),
                    Ok(_) => match rotation::seqno(&address) {
                        Ok(n) => (n, false),
                        Err(e) => return err(502, e),
                    },
                    Err(e) => return err(502, e),
                }
            } else {
                (0, true)
            };
            // TON Connect: wallets may reject validUntil more than 5 minutes ahead.
            let valid_until = rotation::now() + rotation::VALID_FOR_SECS;
            let d = rotation::deploy(
                &wallet::signing_key(&anchor), &wallet::signing_key(&signing),
                wallet::WALLET_ID_MAINNET, seqno, valid_until, with_init,
            );
            let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
            (200, json!({
                "address": d.address,
                "amount": rotation::DEPLOY_VALUE_NANO.to_string(),
                "state_init": d.state_init.as_deref().map(b64),
                "payload": b64(&d.body),
                "valid_until": valid_until,
                "new_public_key": wallet::hex(&d.new_public),
            }))
        }
        _ => err(404, "not found"),
    }
}

fn header(req: &Request, name: &'static str) -> Option<String> {
    req.headers()
        .iter()
        .find(|h| h.field.equiv(name))
        .map(|h| h.value.as_str().to_string())
}

fn respond(req: Request, code: u16, ctype: &str, body: impl Into<Vec<u8>>, csp: &str) {
    let h = |k: &str, v: &str| Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap();
    let resp = Response::from_data(body.into())
        .with_status_code(code)
        .with_header(h("Content-Type", ctype))
        .with_header(h("Cache-Control", "no-store"))
        .with_header(h("X-Content-Type-Options", "nosniff"))
        .with_header(h("X-Frame-Options", "DENY"))
        .with_header(h("Referrer-Policy", "no-referrer"))
        .with_header(h("Content-Security-Policy", csp));
    let _ = req.respond(resp);
}
