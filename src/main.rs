mod cell;
mod gpu;
mod miner;
mod pbkdf2_fast;
mod rotation;
mod server;
mod wallet;

use std::io::{BufRead, Write};
use std::time::Duration;

const HELP: &str = "\
gram-vanity — красивый адрес Telegram Wallet (Money) по схеме 24 слов

Использование:
  gram-vanity [--port N] [--no-open] [--manifest-url URL]
                                             веб-интерфейс на 127.0.0.1
  gram-vanity mine [--suffix S] [--prefix P] [--ci] [--threads N]
                                             подбор слов 1–12 на CPU
  gram-vanity bench [--seconds N]           скорость CPU-подбора

Слова 1–12 только задают адрес. Слова 13–24 (ваш ключ) создаёт веб-интерфейс,
а смена ключа уходит одной транзакцией с вашего кошелька через TON Connect.
Для длинных окончаний ищите на GPU: см. worker/README.md.

--prefix — символы сразу после «UQ» (первый: A, B, C или D).
--ci     — без учёта регистра.
--manifest-url — свой tonconnect-manifest.json (https). По умолчанию — манифест из репо.
Настройки можно задать в .env в текущей папке: TONCENTER_API_KEY, VANITY_MANIFEST_URL.
";

/// Value from the process environment, else from ./.env (KEY=value lines, # comments).
fn env(name: &str) -> Option<String> {
    if let Some(v) = std::env::var(name).ok().filter(|v| !v.is_empty()) {
        return Some(v);
    }
    let file = std::fs::read_to_string(".env").ok()?;
    file.lines()
        .map(str::trim)
        .filter(|l| !l.starts_with('#'))
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == name)
        .map(|(_, v)| v.trim().trim_matches(|c| c == '"' || c == '\'').to_string())
        .filter(|v| !v.is_empty())
}

/// A crash must not write the words to a core file.
fn no_core_dumps() {
    #[cfg(unix)]
    unsafe {
        let zero = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
        libc::setrlimit(libc::RLIMIT_CORE, &zero);
    }
}

fn main() {
    no_core_dumps();
    if let Err(e) = wallet::self_test() {
        eprintln!("САМОПРОВЕРКА НЕ ПРОЙДЕНА: {e}. Подбор отключён.");
        std::process::exit(2);
    }
    let args: Vec<String> = std::env::args().skip(1).collect();
    let flag = |name: &str| args.iter().any(|a| a == name);
    let opt = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let num = |name: &str| opt(name).and_then(|v| v.parse::<usize>().ok());
    rotation::set_api_key(env("TONCENTER_API_KEY"));

    let res = match args.first().map(String::as_str) {
        Some("-h" | "--help" | "help") => {
            print!("{HELP}");
            Ok(())
        }
        Some("mine") => mine(
            &opt("--prefix").unwrap_or_default(),
            &opt("--suffix").unwrap_or_default(),
            flag("--ci"),
            num("--threads").unwrap_or_else(miner::default_threads),
        ),
        Some("bench") => bench(num("--seconds").unwrap_or(10)),
        Some("debug-deploy") => debug_deploy(&args),
        Some("debug-address") => debug_address(),
        _ => match opt("--port").map(|v| v.parse::<u16>()) {
            Some(Err(_)) => Err("--port: число от 1 до 65535".into()),
            port => server::run(
                port.and_then(Result::ok).unwrap_or(0),
                !flag("--no-open"),
                opt("--manifest-url").or_else(|| env("VANITY_MANIFEST_URL")).unwrap_or_else(|| server::DEFAULT_MANIFEST_URL.into()),
            ),
        },
    };
    if let Err(e) = res {
        eprintln!("Ошибка: {e}");
        std::process::exit(1);
    }
}

fn mine(prefix: &str, suffix: &str, ci: bool, threads: usize) -> Result<(), String> {
    let p = miner::Pattern::new(prefix, suffix, ci)?;
    eprintln!("Ищу якорь: UQ{}…{}{}, потоков: {threads}, ожидаемо попыток: {:.0}",
        p.prefix, p.suffix, if ci { " (без учёта регистра)" } else { "" }, p.expected_attempts());
    let job = miner::start(p, 1, threads);
    while job.running() {
        std::thread::sleep(Duration::from_millis(1000));
        let n = job.attempts.load(std::sync::atomic::Ordering::Relaxed);
        eprint!("\r{n} попыток, {:.0}/с, {:.0} с   ", n as f64 / job.elapsed(), job.elapsed());
        let _ = std::io::stderr().flush();
    }
    eprintln!();
    for f in job.found.lock().unwrap().iter() {
        println!("Адрес: {}\nЯкорь: {}", f.address, f.words);
    }
    eprintln!("Вставьте якорь в веб-интерфейс, чтобы получить 24 слова и сменить ключ.");
    Ok(())
}

/// Test helper (tests/js): stdin = anchor line, signing line.
/// Prints address, new pubkey, StateInit BOC hex ("-" if none), body BOC hex.
fn debug_deploy(args: &[String]) -> Result<(), String> {
    let mut lines = std::io::stdin().lock().lines();
    let mut read = || lines.next().ok_or("stdin")?.map_err(|e| e.to_string());
    let anchor = wallet::normalize_words(&read()?)?;
    let signing = wallet::normalize_words(&read()?)?;
    let valid_until: u32 = args.get(1).and_then(|v| v.parse().ok()).ok_or("valid_until")?;
    let seqno: u32 = args.get(2).and_then(|v| v.parse().ok()).unwrap_or(0);
    let d = rotation::deploy(&wallet::signing_key(&anchor), &wallet::signing_key(&signing),
        wallet::WALLET_ID_MAINNET, seqno, valid_until, seqno == 0);
    let init = d.state_init.as_deref().map(wallet::hex).unwrap_or_else(|| "-".into());
    println!("{}\n{}\n{}\n{}", d.address, wallet::hex(&d.new_public), init, wallet::hex(&d.body));
    Ok(())
}

/// Test helper (worker/): anchor words per stdin line -> "address pubkey".
fn debug_address() -> Result<(), String> {
    for line in std::io::stdin().lock().lines() {
        let line = line.map_err(|e| e.to_string())?;
        let (a, pk) = wallet::address_from_words(&line)?;
        println!("{a} {}", wallet::hex(&pk));
    }
    Ok(())
}

fn bench(seconds: usize) -> Result<(), String> {
    // Impossible pattern: runs until stopped.
    let p = miner::Pattern::new("", "----------", false)?;
    let threads = miner::default_threads();
    let job = miner::start(p, 1, threads);
    std::thread::sleep(Duration::from_secs(seconds as u64));
    job.request_stop();
    let rate = job.attempts.load(std::sync::atomic::Ordering::Relaxed) as f64 / job.elapsed();
    println!("{threads} потоков: {rate:.0} адресов/с");
    for (n, label) in [(3, "3 символа"), (4, "4 символа"), (5, "5 символов"), (6, "6 символов"), (7, "7 символов")] {
        let sens = 64f64.powi(n) / rate;
        let ci = 32f64.powi(n) / rate; // all letters, case-insensitive
        println!("  {label}: ~{} (с регистром), ~{} (без регистра, только буквы)", human(sens), human(ci));
    }
    Ok(())
}

fn human(s: f64) -> String {
    match s {
        s if s < 90.0 => format!("{s:.0} с"),
        s if s < 5400.0 => format!("{:.0} мин", s / 60.0),
        s if s < 172_800.0 => format!("{:.1} ч", s / 3600.0),
        s => format!("{:.1} дн", s / 86400.0),
    }
}
