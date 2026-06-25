//! atlas-sender — High-Throughput L2 TX Sender
//!
//! Sendet tausende signierte L2-Transaktionen/Sekunde an den Aggregator.
//! Nutzt parallelisiertes Signing (rayon) + Batch-HTTP-Submission.
//!
//! Verwendung:
//!   atlas-sender [OPTIONEN]
//!
//! Optionen:
//!   --url      <URL>    Aggregator-URL          (Standard: http://127.0.0.1:8080)
//!   --count    <N>      Gesamt-TX-Anzahl        (Standard: 10_000)
//!   --senders  <N>      Anzahl Sender-Keypairs  (Standard: 50)
//!   --amount   <N>      Betrag pro TX in ATOM   (Standard: 100)
//!   --fee      <N>      Fee pro TX in ATOM      (Standard: 5)
//!   --tps      <N>      Ziel-TPS (0 = maximum)  (Standard: 0)
//!   --batch    <N>      TXs pro HTTP-Request    (Standard: 200)
//!   --parallel <N>      Parallele HTTP-Tasks    (Standard: 16)

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use atlas_core::crypto::Address;
use atlas_zk::eddsa::EddsaKeypair;
use atlas_zk::l2_state::build_l2_eddsa;
use atlas_core::l2_tx::L2Transaction;
use rayon::prelude::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;

// ── CLI-Argumente ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Config {
    url:      String,       // Aggregator base URL (z.B. "127.0.0.1:8080")
    count:    usize,        // Gesamt-TX-Anzahl
    senders:  usize,        // Anzahl Sender-Keypairs
    amount:   u128,         // ATOM pro TX
    fee:      u128,         // ATOM Fee pro TX
    tps:      u64,          // Ziel-TPS (0 = max)
    batch:    usize,        // TXs pro HTTP-Batch-Request
    parallel: usize,        // Parallele HTTP-Verbindungen
    /// Forced-Inclusion-Modus: genau EINE TX als `forcel2tx` direkt an die
    /// NODE-RPC (Zensurresistenz-Pfad, umgeht den Aggregator). `--url` zeigt
    /// dann auf die Node-RPC (z.B. 127.0.0.1:18634).
    force:        bool,
    seed:         u64,      // Sender-Seed (Genesis: 0xA71A5000 + i)
    nonce:        u64,      // L2-Nonce der Forced-TX
    sender_index: u64,      // Konto-Index im L2-Baum (Bezug für Rejections)
    nonce_base:   u64,      // Bulk-Modus: Start-Nonce je Sender (für Dauer-Last)
    print_addrs:  bool,     // nur Sender-Adressen ausgeben und beenden
}

impl Default for Config {
    fn default() -> Self {
        Config {
            url:      "127.0.0.1:8080".to_string(),
            count:    10_000,
            senders:  50,
            amount:   100,
            fee:      5,
            tps:      0,
            batch:    200,
            parallel: 16,
            force:        false,
            seed:         0xA71A_5000,
            nonce:        0,
            sender_index: 0,
            nonce_base:   0,
            print_addrs:  false,
        }
    }
}

fn parse_args() -> Config {
    let args: Vec<String> = std::env::args().collect();
    let mut cfg = Config::default();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--url"      if i+1 < args.len() => { cfg.url      = args[i+1].trim_start_matches("http://").to_string(); i += 2; }
            "--count"    if i+1 < args.len() => { cfg.count    = args[i+1].parse().unwrap_or(10_000); i += 2; }
            "--senders"  if i+1 < args.len() => { cfg.senders  = args[i+1].parse().unwrap_or(50);     i += 2; }
            "--amount"   if i+1 < args.len() => { cfg.amount   = args[i+1].parse().unwrap_or(100);    i += 2; }
            "--fee"      if i+1 < args.len() => { cfg.fee      = args[i+1].parse().unwrap_or(5);      i += 2; }
            "--tps"      if i+1 < args.len() => { cfg.tps      = args[i+1].parse().unwrap_or(0);      i += 2; }
            "--batch"    if i+1 < args.len() => { cfg.batch    = args[i+1].parse().unwrap_or(200);    i += 2; }
            "--parallel" if i+1 < args.len() => { cfg.parallel = args[i+1].parse().unwrap_or(16);    i += 2; }
            "--force"                        => { cfg.force    = true;                               i += 1; }
            "--seed"     if i+1 < args.len() => { cfg.seed     = parse_u64_maybe_hex(&args[i+1]);    i += 2; }
            "--nonce"    if i+1 < args.len() => { cfg.nonce    = args[i+1].parse().unwrap_or(0);     i += 2; }
            "--index"    if i+1 < args.len() => { cfg.sender_index = args[i+1].parse().unwrap_or(0); i += 2; }
            "--nonce-base" if i+1 < args.len() => { cfg.nonce_base = args[i+1].parse().unwrap_or(0); i += 2; }
            "--print-addrs"                  => { cfg.print_addrs = true;                          i += 1; }
            "--help" | "-h" => {
                eprintln!("atlas-sender — High-Throughput L2 TX Sender");
                eprintln!("  --url      <host:port>  Aggregator-Adresse    (Standard: 127.0.0.1:8080)");
                eprintln!("  --count    <N>          Gesamt-TXs            (Standard: 10000)");
                eprintln!("  --senders  <N>          Sender-Keypairs       (Standard: 50)");
                eprintln!("  --amount   <N>          ATOM pro TX           (Standard: 100)");
                eprintln!("  --fee      <N>          ATOM Fee              (Standard: 5)");
                eprintln!("  --tps      <N>          Ziel-TPS (0=max)      (Standard: 0)");
                eprintln!("  --batch    <N>          TXs/HTTP-Call         (Standard: 200)");
                eprintln!("  --parallel <N>          Parallele Verbindungen(Standard: 16)");
                eprintln!("  --nonce-base <N>        Start-Nonce je Sender (Dauer-Last; Standard: 0)");
                eprintln!();
                eprintln!("Forced Inclusion (Zensurresistenz, direkt an die NODE-RPC):");
                eprintln!("  --force                 EINE TX als forcel2tx einreichen");
                eprintln!("  --seed     <N|0xHEX>    Sender-Keypair-Seed   (Standard: 0xA71A5000)");
                eprintln!("  --nonce    <N>          L2-Nonce              (Standard: 0)");
                eprintln!("  --index    <N>          Konto-Index im Baum   (Standard: 0)");
                eprintln!("  Beispiel: atlas-sender --force --url 127.0.0.1:18634 \\");
                eprintln!("            --seed 0xA71A5003 --nonce 0 --index 4 --amount 100");
                std::process::exit(0);
            }
            _ => { i += 1; }
        }
    }
    cfg
}

/// Parst "123" oder "0xABCD" zu u64.
fn parse_u64_maybe_hex(s: &str) -> u64 {
    if let Some(hexpart) = s.strip_prefix("0x") {
        u64::from_str_radix(hexpart, 16).unwrap_or(0)
    } else {
        s.parse().unwrap_or(0)
    }
}

// ── HTTP-Hilfsfunktionen ───────────────────────────────────────────────────────

/// Sendet einen JSON-Body via POST an host:port/path
/// Gibt den Response-Body zurück oder einen Fehler.
async fn http_post(host: &str, path: &str, body: &[u8]) -> anyhow::Result<String> {
    let mut stream = TcpStream::connect(host).await?;

    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path, host, body.len()
    );

    stream.write_all(request.as_bytes()).await?;
    stream.write_all(body).await?;

    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;

    // Body nach Header-Trenner extrahieren
    let resp_str = String::from_utf8_lossy(&response);
    if let Some(pos) = resp_str.find("\r\n\r\n") {
        Ok(resp_str[pos + 4..].to_string())
    } else {
        Ok(resp_str.to_string())
    }
}

// ── Kern-Logik ────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let cfg = parse_args();

    // ── Adress-Modus: Sender-Adressen (Seed 0xA71A5000 + i) ausgeben ────────
    if cfg.print_addrs {
        for i in 0..cfg.senders {
            let kp = EddsaKeypair::from_seed(0xA71A_5000 + i as u64);
            println!("{} {}", i, hex::encode(kp.public().address20()));
        }
        return Ok(());
    }

    // ── Forced-Inclusion-Modus: eine TX direkt an die Node-RPC ──────────────
    if cfg.force {
        let kp = EddsaKeypair::from_seed(cfg.seed);
        let recipient = Address([0xABu8; 20]);
        let (from, pubkey, sig) =
            build_l2_eddsa(&kp, &recipient.0, cfg.amount, cfg.fee, cfg.nonce);
        let body = format!(
            r#"{{"jsonrpc":"2.0","id":1,"method":"forcel2tx","params":[{{"from":"{}","to":"{}","amount_atom":{},"fee_atom":{},"nonce":{},"pubkey":"{}","sig":"{}","sender_index":{}}}]}}"#,
            hex::encode(from), hex::encode(recipient.0),
            cfg.amount, cfg.fee, cfg.nonce,
            hex::encode(pubkey), hex::encode(sig), cfg.sender_index,
        );
        println!("Forced Inclusion: from={} nonce={} → Node {}",
            hex::encode(from), cfg.nonce, cfg.url);
        let resp = http_post(&cfg.url, "/", body.as_bytes()).await?;
        println!("Antwort: {}", resp.trim());
        return Ok(());
    }

    println!("╔══════════════════════════════════════════════════════╗");
    println!("║         ATLAS High-Throughput L2 Sender              ║");
    println!("╚══════════════════════════════════════════════════════╝");
    println!("  Aggregator:    http://{}", cfg.url);
    println!("  Gesamt-TXs:   {}", cfg.count);
    println!("  Sender-Keys:  {}", cfg.senders);
    println!("  Batch-Größe:  {} TXs/HTTP-Call", cfg.batch);
    println!("  Parallelität: {} Verbindungen", cfg.parallel);
    if cfg.tps > 0 {
        println!("  Ziel-TPS:     {}", cfg.tps);
    } else {
        println!("  Ziel-TPS:     MAXIMUM");
    }
    println!();

    // ── Phase 1: Keypairs generieren ────────────────────────────────────────
    let t0 = Instant::now();
    print!("Generiere {} Sender-Keypairs ... ", cfg.senders);
    let keypairs: Vec<EddsaKeypair> = (0..cfg.senders)
        .map(|i| EddsaKeypair::from_seed(0xA71A_5000 + i as u64))
        .collect();
    // Fester Empfänger (Bucket für alle TXs)
    let recipient = Address([0xABu8; 20]);
    println!("fertig ({:.0}ms)", t0.elapsed().as_millis());

    // ── Phase 2: TXs parallel vorab signieren (rayon) ───────────────────────
    print!("Signiere {} TXs ... ", cfg.count);
    let t1 = Instant::now();

    let txs: Vec<L2Transaction> = (0..cfg.count)
        .into_par_iter()
        .map(|i| {
            let kp    = &keypairs[i % keypairs.len()];
            let nonce = cfg.nonce_base + (i / keypairs.len()) as u64;
            let (from, pubkey, sig) =
                build_l2_eddsa(kp, &recipient.0, cfg.amount, cfg.fee, nonce);
            L2Transaction::from_parts(
                Address(from), recipient, cfg.amount, cfg.fee, nonce, pubkey, sig)
        })
        .collect();

    let sign_ms   = t1.elapsed().as_millis();
    let sign_tps  = cfg.count as f64 / t1.elapsed().as_secs_f64();
    println!("fertig ({} ms → {:.0} Signaturen/s)", sign_ms, sign_tps);

    // ── Phase 3: TXs in Batches aufteilen ───────────────────────────────────
    let batches: Vec<Vec<L2Transaction>> = txs
        .chunks(cfg.batch.max(1))
        .map(|chunk| chunk.to_vec())
        .collect();
    println!("{} HTTP-Batches à {} TXs", batches.len(), cfg.batch);
    println!();
    println!("Sende ... ");

    // ── Phase 4: HTTP-Batches parallel senden ───────────────────────────────
    let accepted_total  = Arc::new(AtomicU64::new(0));
    let rejected_total  = Arc::new(AtomicU64::new(0));
    let errors_total    = Arc::new(AtomicU64::new(0));
    let sem             = Arc::new(Semaphore::new(cfg.parallel));
    let t_start         = Instant::now();
    let t_last_print    = Arc::new(tokio::sync::Mutex::new(Instant::now()));
    let last_accepted   = Arc::new(AtomicU64::new(0));

    // Für Rate-Limiting: falls --tps gesetzt
    let delay_per_batch = if cfg.tps > 0 {
        let batches_per_sec = cfg.tps as f64 / cfg.batch as f64;
        Some(Duration::from_secs_f64(1.0 / batches_per_sec))
    } else {
        None
    };

    let mut handles = Vec::with_capacity(batches.len());

    for (batch_idx, batch) in batches.into_iter().enumerate() {
        // Rate-Limiting
        if let Some(delay) = delay_per_batch {
            let expected_time = delay * batch_idx as u32;
            let elapsed = t_start.elapsed();
            if elapsed < expected_time {
                tokio::time::sleep(expected_time - elapsed).await;
            }
        }

        let permit         = sem.clone().acquire_owned().await?;
        let url            = cfg.url.clone();
        let accepted_c     = accepted_total.clone();
        let rejected_c     = rejected_total.clone();
        let errors_c       = errors_total.clone();
        let t_last_c       = t_last_print.clone();
        let last_acc_c     = last_accepted.clone();

        let handle = tokio::spawn(async move {
            let _permit = permit; // dropped am Ende → gibt Semaphore frei

            let body = serde_json::to_vec(&batch).unwrap_or_default();
            match http_post(&url, "/submit_batch", &body).await {
                Ok(resp) => {
                    // Parse {"accepted": N, "rejected": M}
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&resp) {
                        let acc = v["accepted"].as_u64().unwrap_or(0);
                        let rej = v["rejected"].as_u64().unwrap_or(0);
                        accepted_c.fetch_add(acc, Ordering::Relaxed);
                        rejected_c.fetch_add(rej, Ordering::Relaxed);
                    } else {
                        // Fallback: /submit_batch nicht verfügbar → einzeln versuchen
                        errors_c.fetch_add(batch.len() as u64, Ordering::Relaxed);
                    }
                }
                Err(_) => {
                    errors_c.fetch_add(batch.len() as u64, Ordering::Relaxed);
                }
            }

            // Fortschritt drucken alle 500ms
            let mut last = t_last_c.lock().await;
            if last.elapsed() >= Duration::from_millis(500) {
                let total_acc   = accepted_c.load(Ordering::Relaxed);
                let prev_acc    = last_acc_c.swap(total_acc, Ordering::Relaxed);
                let delta       = total_acc.saturating_sub(prev_acc);
                let tps         = delta as f64 / 0.5;
                let errs        = errors_c.load(Ordering::Relaxed);
                let elapsed     = t_start.elapsed().as_secs_f64();
                let overall_tps = total_acc as f64 / elapsed;
                println!(
                    "  [{:.1}s] {:>7} TXs akzeptiert  {:>6} TPS aktuell  {:>6.0} TPS gesamt  {} Fehler",
                    elapsed, total_acc, tps as u64, overall_tps, errs
                );
                *last = Instant::now();
            }
        });
        handles.push(handle);
    }

    // Alle Tasks abwarten
    for h in handles {
        let _ = h.await;
    }

    // ── Ergebnis ──────────────────────────────────────────────────────────────
    let elapsed     = t_start.elapsed();
    let accepted    = accepted_total.load(Ordering::Relaxed);
    let rejected    = rejected_total.load(Ordering::Relaxed);
    let errors      = errors_total.load(Ordering::Relaxed);
    let submission_tps = accepted as f64 / elapsed.as_secs_f64();

    println!();
    println!("╔══════════════════════════════════════════════════════╗");
    println!("║                  ERGEBNIS                           ║");
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Laufzeit:        {:<38}║", format!("{:.2}s", elapsed.as_secs_f64()));
    println!("║  Signing TPS:     {:<38}║", format!("{:.0}/s", sign_tps));
    println!("║  Akzeptiert:      {:<38}║", accepted);
    println!("║  Abgelehnt:       {:<38}║", rejected);
    println!("║  HTTP-Fehler:     {:<38}║", errors);
    println!("║  Submission TPS:  {:<38}║", format!("{:.0}/s", submission_tps));
    println!("╠══════════════════════════════════════════════════════╣");
    println!("║  Signing:   rayon parallel auf allen CPU-Kernen     ║");
    println!("║  Transport: {} parallele TCP-Verbindungen{:<13}║",
        cfg.parallel,
        ""
    );
    println!("╚══════════════════════════════════════════════════════╝");

    if errors > 0 {
        eprintln!();
        eprintln!("Hinweis: {} HTTP-Fehler. Läuft atlas-aggregator?", errors);
        eprintln!("  → systemctl status atlas-aggregator");
    }

    Ok(())
}
