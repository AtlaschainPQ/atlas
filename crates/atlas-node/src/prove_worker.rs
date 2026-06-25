//! Isolierter ZK-Prover-Subprozess (struktureller Fix gegen den arkworks-RSS-Leak).
//!
//! Die Groth16-Proof-Erzeugung (arkworks/BN254) leakt pro Aufruf einige MB, die
//! glibc selbst mit Arena-Tuning nur dämpft, nicht zurückgibt. Statt den Prover im
//! langlebigen Node-Prozess zu halten, startet der Mining-Pfad für JEDEN Block-Proof
//! einen kurzlebigen Child-Prozess (`atlas-node prove-worker`). Sobald dieser sich
//! beendet, reklamiert das OS seinen gesamten Speicher — inklusive des Leaks. Der
//! gebündelte Proving-Key ist nur ~340 KB, das Laden kostet <50 ms, der Overhead pro
//! Block-Proof ist damit vernachlässigbar. Zusätzlicher Gewinn: vollständige
//! Crash-Isolation — ein Prover-OOM/Panic tötet nur den Child, nie den Node.
//!
//! Wire-Format (alle Mehrbyte-Werte little-endian):
//!   Job   (Node → Worker, stdin):
//!     magic[4]="PVJ1" | pre_root[32] | n[u32] | n × ( batch_id[32] | bid[u128/16] )
//!   Result (Worker → Node, stdout):
//!     Erfolg: tag[1]=1 | proof_len[u32] | proof[proof_len] | post[32]
//!     Fehler: tag[1]=0 | msg_len[u32]   | msg[utf8]

use std::io::{Read, Write};
use std::process::{Command, Stdio};

const JOB_MAGIC: &[u8; 4] = b"PVJ1";

// ── Serialisierung ───────────────────────────────────────────────────────────

/// Kodiert einen Proof-Job (Node-Seite, wird in stdin des Workers geschrieben).
fn encode_job(pre_root: &[u8; 32], batches: &[([u8; 32], u128)]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + 32 + 4 + batches.len() * 48);
    buf.extend_from_slice(JOB_MAGIC);
    buf.extend_from_slice(pre_root);
    buf.extend_from_slice(&(batches.len() as u32).to_le_bytes());
    for (id, bid) in batches {
        buf.extend_from_slice(id);
        buf.extend_from_slice(&bid.to_le_bytes());
    }
    buf
}

/// Dekodiert einen Proof-Job (Worker-Seite, aus stdin gelesen).
fn decode_job(buf: &[u8]) -> Result<([u8; 32], Vec<([u8; 32], u128)>), String> {
    let mut p = 0usize;
    let take = |p: &mut usize, n: usize| -> Result<&[u8], String> {
        if *p + n > buf.len() {
            return Err(format!("truncated job: need {} bytes at offset {}, have {}", n, *p, buf.len()));
        }
        let s = &buf[*p..*p + n];
        *p += n;
        Ok(s)
    };

    if take(&mut p, 4)? != JOB_MAGIC {
        return Err("bad job magic".to_string());
    }
    let mut pre_root = [0u8; 32];
    pre_root.copy_from_slice(take(&mut p, 32)?);
    let n = u32::from_le_bytes(take(&mut p, 4)?.try_into().unwrap()) as usize;

    let mut batches = Vec::with_capacity(n);
    for _ in 0..n {
        let mut id = [0u8; 32];
        id.copy_from_slice(take(&mut p, 32)?);
        let bid = u128::from_le_bytes(take(&mut p, 16)?.try_into().unwrap());
        batches.push((id, bid));
    }
    Ok((pre_root, batches))
}

/// Kodiert das Ergebnis (Worker-Seite, wird auf stdout geschrieben).
fn encode_result(res: &Result<(Vec<u8>, [u8; 32]), String>) -> Vec<u8> {
    let mut buf = Vec::new();
    match res {
        Ok((proof, post)) => {
            buf.push(1u8);
            buf.extend_from_slice(&(proof.len() as u32).to_le_bytes());
            buf.extend_from_slice(proof);
            buf.extend_from_slice(post);
        }
        Err(msg) => {
            buf.push(0u8);
            let m = msg.as_bytes();
            buf.extend_from_slice(&(m.len() as u32).to_le_bytes());
            buf.extend_from_slice(m);
        }
    }
    buf
}

/// Dekodiert das Ergebnis (Node-Seite, aus stdout des Workers gelesen).
fn decode_result(buf: &[u8]) -> Result<(Vec<u8>, [u8; 32]), String> {
    if buf.is_empty() {
        return Err("empty result from prove-worker".to_string());
    }
    match buf[0] {
        1 => {
            if buf.len() < 5 {
                return Err("truncated success result header".to_string());
            }
            let plen = u32::from_le_bytes(buf[1..5].try_into().unwrap()) as usize;
            let proof_end = 5 + plen;
            if buf.len() < proof_end + 32 {
                return Err("truncated success result body".to_string());
            }
            let proof = buf[5..proof_end].to_vec();
            let mut post = [0u8; 32];
            post.copy_from_slice(&buf[proof_end..proof_end + 32]);
            Ok((proof, post))
        }
        0 => {
            if buf.len() < 5 {
                return Err("truncated error result".to_string());
            }
            let mlen = u32::from_le_bytes(buf[1..5].try_into().unwrap()) as usize;
            let msg = String::from_utf8_lossy(&buf[5..(5 + mlen).min(buf.len())]).to_string();
            Err(format!("prove-worker error: {}", msg))
        }
        t => Err(format!("unknown result tag {}", t)),
    }
}

// ── Worker-Seite (Child-Prozess) ─────────────────────────────────────────────

/// Einstiegspunkt des `atlas-node prove-worker`-Subprozesses: liest einen Job von
/// stdin, erzeugt den Proof, schreibt das Ergebnis auf stdout und beendet sich.
/// Beendet den Prozess immer selbst (kehrt nie zurück).
pub fn run_stdio() -> ! {
    let mut input = Vec::new();
    if let Err(e) = std::io::stdin().read_to_end(&mut input) {
        eprintln!("prove-worker: stdin read failed: {}", e);
        std::process::exit(2);
    }

    let result: Result<(Vec<u8>, [u8; 32]), String> = (|| {
        let (pre_root, batches) = decode_job(&input)?;
        let prover = atlas_zk::ZkBatchProver::from_bundled()
            .map_err(|e| format!("load bundled PK: {}", e))?;
        prover
            .prove_block(&pre_root, &batches)
            .map_err(|e| format!("prove_block: {}", e))
    })();

    let frame = encode_result(&result);
    let mut stdout = std::io::stdout();
    if stdout.write_all(&frame).and_then(|_| stdout.flush()).is_err() {
        std::process::exit(3);
    }
    std::process::exit(0);
}

// ── Node-Seite (Eltern-Prozess) ──────────────────────────────────────────────

/// Erzeugt EINEN aggregierten Block-Proof in einem isolierten Subprozess.
/// Spawnt `current_exe() prove-worker`, übergibt den Job über stdin und liest das
/// Ergebnis von stdout. Bei jedem Fehler (Spawn, Exit-Code, Parsing, Prover) wird
/// `Err` zurückgegeben — der Aufrufer fällt dann auf einen Block ohne Groth16-Proof
/// zurück (die proof_root-Digest-Bindung bleibt erhalten).
pub fn prove_in_subprocess(
    pre_root: &[u8; 32],
    batches:  &[([u8; 32], u128)],
) -> Result<(Vec<u8>, [u8; 32]), String> {
    let exe = std::env::current_exe()
        .map_err(|e| format!("current_exe: {}", e))?;

    let mut child = Command::new(&exe)
        .arg("prove-worker")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn prove-worker: {}", e))?;

    let job = encode_job(pre_root, batches);
    {
        let mut stdin = child.stdin.take().ok_or("no stdin handle")?;
        stdin.write_all(&job).map_err(|e| format!("write job: {}", e))?;
        // stdin wird beim Verlassen des Blocks geschlossen → Worker sieht EOF.
    }

    let out = child
        .wait_with_output()
        .map_err(|e| format!("wait prove-worker: {}", e))?;

    if !out.status.success() {
        return Err(format!("prove-worker exited with {}", out.status));
    }
    decode_result(&out.stdout)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_job_roundtrip() {
        let pre_root = [7u8; 32];
        let batches = vec![([1u8; 32], 1_000u128), ([2u8; 32], u128::MAX), ([3u8; 32], 0)];
        let enc = encode_job(&pre_root, &batches);
        let (pr, bs) = decode_job(&enc).unwrap();
        assert_eq!(pr, pre_root);
        assert_eq!(bs, batches);
    }

    #[test]
    fn test_job_empty_batches() {
        let pre_root = [0u8; 32];
        let enc = encode_job(&pre_root, &[]);
        let (pr, bs) = decode_job(&enc).unwrap();
        assert_eq!(pr, pre_root);
        assert!(bs.is_empty());
    }

    #[test]
    fn test_decode_job_rejects_bad_magic() {
        let mut enc = encode_job(&[0u8; 32], &[]);
        enc[0] = b'X';
        assert!(decode_job(&enc).is_err());
    }

    #[test]
    fn test_decode_job_rejects_truncated() {
        let enc = encode_job(&[0u8; 32], &[([9u8; 32], 5u128)]);
        assert!(decode_job(&enc[..enc.len() - 1]).is_err());
    }

    #[test]
    fn test_result_success_roundtrip() {
        let res: Result<(Vec<u8>, [u8; 32]), String> = Ok((vec![0xAB; 224], [0xCD; 32]));
        let enc = encode_result(&res);
        let dec = decode_result(&enc).unwrap();
        assert_eq!(dec.0, vec![0xAB; 224]);
        assert_eq!(dec.1, [0xCD; 32]);
    }

    #[test]
    fn test_result_error_roundtrip() {
        let res: Result<(Vec<u8>, [u8; 32]), String> = Err("kaboom".to_string());
        let enc = encode_result(&res);
        let dec = decode_result(&enc);
        assert!(dec.is_err());
        assert!(dec.unwrap_err().contains("kaboom"));
    }

    #[test]
    fn test_decode_result_empty() {
        assert!(decode_result(&[]).is_err());
    }
}
