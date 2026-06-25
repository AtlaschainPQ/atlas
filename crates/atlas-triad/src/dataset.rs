//! TRIAD Memory-Hard Dataset
//!
//! ~4 GB RAM Dataset — deterministisch aus Epoch-Seed erzeugt.
//! RAM-Bandbreite ist das primäre Mining-Limit.
//! ASIC-Optimierung wird durch Epoch-Rotation alle 2 Wochen unattraktiv.
//!
//! Produktions-Konfiguration: 4 GB = 4 * 1024^3 / 64 = 67.108.864 Items
//! Test-Konfiguration (schnell): 16 MB = 262.144 Items

use sha2::{Sha256, Digest};
use sha3::{Sha3_256};
use rayon::prelude::*;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use crate::epoch::EpochSeed;

/// Größe eines Dataset-Items in Bytes
pub const ITEM_SIZE: usize = 64;

/// Magic + Versions-Header für die Disk-Cache-Datei.
/// Wird bei jedem Layout-Wechsel erhöht, damit alte Caches automatisch verworfen werden.
const CACHE_MAGIC: &[u8; 8] = b"ATRIAD01";
const CACHE_FORMAT_VERSION: u32 = 1;
/// Header-Größe in Bytes: magic(8) + fmt(4) + is_test(4) + epoch(4) + item_count(8) + seed_hash(32)
const CACHE_HEADER_LEN: usize = 8 + 4 + 4 + 4 + 8 + 32;

/// Produktions-Dataset: 4 GB
pub const DATASET_SIZE_PROD: usize = 4 * 1024 * 1024 * 1024;
pub const DATASET_ITEM_COUNT: usize = DATASET_SIZE_PROD / ITEM_SIZE;

/// Cache-Größe: 1/32 des Datasets (wie Ethash)
pub const CACHE_SIZE: usize = DATASET_SIZE_PROD / 32;
pub const CACHE_ITEM_COUNT: usize = CACHE_SIZE / ITEM_SIZE;

/// Für Tests / Entwicklung: 16 MB Dataset
pub const DATASET_ITEM_COUNT_TEST: usize = (16 * 1024 * 1024) / ITEM_SIZE;
pub const CACHE_ITEM_COUNT_TEST:   usize = DATASET_ITEM_COUNT_TEST / 32;

/// Anzahl Lookup-Accesses pro Hash (data-dependent, GPU-feindlich)
pub const ACCESSES: usize = 64;

pub struct DatasetConfig {
    pub item_count:  usize,
    pub cache_count: usize,
    pub is_test:     bool,
}

impl DatasetConfig {
    pub fn production() -> Self {
        DatasetConfig {
            item_count:  DATASET_ITEM_COUNT,
            cache_count: CACHE_ITEM_COUNT,
            is_test:     false,
        }
    }

    pub fn test() -> Self {
        DatasetConfig {
            item_count:  DATASET_ITEM_COUNT_TEST,
            cache_count: CACHE_ITEM_COUNT_TEST,
            is_test:     true,
        }
    }
}

/// TRIAD Dataset: im RAM geladen, epoch-spezifisch
pub struct Dataset {
    pub config: DatasetConfig,
    /// Cache (1/32 des Datasets, für Verifier)
    cache:      Vec<[u8; ITEM_SIZE]>,
    /// Volles Dataset (nur für Miner)
    data:       Option<Vec<[u8; ITEM_SIZE]>>,
    pub epoch:  u32,
}

impl Dataset {
    /// Generiert den Cache (schnell, ~128 MB)
    pub fn generate_cache(seed: &EpochSeed, config: &DatasetConfig) -> Vec<[u8; ITEM_SIZE]> {
        let n = config.cache_count;
        let mut cache = Vec::with_capacity(n);

        // Erstes Item: Hash des Seeds
        let first: [u8; ITEM_SIZE] = {
            let mut item = [0u8; ITEM_SIZE];
            let h = Sha256::digest(seed.cache_seed.as_bytes());
            item[..32].copy_from_slice(&h);
            let h2 = Sha3_256::digest(h);
            item[32..].copy_from_slice(&h2);
            item
        };
        cache.push(first);

        // Folge-Items: Hash des Vorgängers
        for i in 1..n {
            let prev = &cache[i - 1];
            let mut item = [0u8; ITEM_SIZE];
            let h1 = Sha256::digest(*prev);
            item[..32].copy_from_slice(&h1);
            let h2 = Sha3_256::digest(h1);
            item[32..].copy_from_slice(&h2);
            cache.push(item);
        }

        // Mehrere Durchläufe für Memory-Hardness (vereinfachtes Scrypt-ähnlich)
        for _ in 0..3 {
            for i in 0..n {
                let prev_idx = if i == 0 { n - 1 } else { i - 1 };
                let xor_idx  = u64::from_le_bytes(cache[i][..8].try_into().unwrap()) as usize % n;
                let mixed: [u8; ITEM_SIZE] = {
                    let mut m = [0u8; ITEM_SIZE];
                    for j in 0..ITEM_SIZE {
                        m[j] = cache[prev_idx][j] ^ cache[xor_idx][j];
                    }
                    let h = Sha256::digest(&m[..32]);
                    m[..32].copy_from_slice(&h);
                    m
                };
                cache[i] = mixed;
            }
        }

        cache
    }

    /// Generiert das volle Dataset aus dem Cache (parallel, RAM-intensiv)
    pub fn generate_full(
        cache:  &[[u8; ITEM_SIZE]],
        config: &DatasetConfig,
    ) -> Vec<[u8; ITEM_SIZE]> {
        let n      = config.item_count;
        let c_size = cache.len();

        (0..n).into_par_iter().map(|i| {
            Self::calc_dataset_item(cache, c_size, i)
        }).collect()
    }

    /// Berechnet ein einzelnes Dataset-Item aus dem Cache
    /// Data-dependent memory access: GPU-feindlich, CPU-Cache-stressend
    pub fn calc_dataset_item(
        cache:  &[[u8; ITEM_SIZE]],
        c_size: usize,
        index:  usize,
    ) -> [u8; ITEM_SIZE] {
        let mut mix = cache[index % c_size];

        // XOR mit index-basierter Modifikation
        let idx_bytes = (index as u64).to_le_bytes();
        for j in 0..8 { mix[j] ^= idx_bytes[j]; }

        // Data-dependent Lookups (cache-dependency, GPU-feindlich)
        for _ in 0..ACCESSES {
            // Nächster Index hängt vom aktuellen Datenwert ab
            let next_idx = u64::from_le_bytes(mix[..8].try_into().unwrap()) as usize % c_size;
            for j in 0..ITEM_SIZE {
                mix[j] ^= cache[next_idx][j];
            }
            // Sha3 Runde für Diffusion
            let hash = Sha3_256::digest(&mix[..32]);
            mix[..32].copy_from_slice(&hash);
        }

        mix
    }

    /// Initialisiert Dataset (Miner: mit vollem Dataset)
    pub fn new_for_mining(seed: &EpochSeed, config: DatasetConfig) -> Self {
        let cache = Self::generate_cache(seed, &config);
        let data  = Some(Self::generate_full(&cache, &config));
        let epoch = seed.epoch;
        Dataset { config, cache, data, epoch }
    }

    /// Initialisiert Dataset (Verifier: nur Cache nötig)
    pub fn new_for_verification(seed: &EpochSeed, config: DatasetConfig) -> Self {
        let cache = Self::generate_cache(seed, &config);
        let epoch = seed.epoch;
        Dataset { config, cache, data: None, epoch }
    }

    /// Liest ein Dataset-Item (Miner: direkt; Verifier: berechnet aus Cache)
    pub fn get_item(&self, index: usize) -> [u8; ITEM_SIZE] {
        let idx = index % self.config.item_count;
        if let Some(ref data) = self.data {
            data[idx]
        } else {
            Self::calc_dataset_item(&self.cache, self.cache.len(), idx)
        }
    }

    // ── Disk-Cache ──────────────────────────────────────────────────────────────
    //
    // Das volle Dataset ist pro Epoche DETERMINISTISCH (nur aus dem EpochSeed
    // abgeleitet) — Caching auf Disk ist daher konsensneutral: die geladenen
    // Bytes sind exakt dieselben, die `generate_full` erzeugt hätte. Der Cache
    // spart lediglich die teure Neuberechnung (~Minuten beim 4-GB-Dataset) bei
    // jedem Node-Neustart innerhalb derselben Epoche. Jeder Cache-Fehler ist
    // unkritisch und führt nur zum normalen Neuaufbau im RAM.

    fn cache_file_path(cache_dir: &Path, seed: &EpochSeed, config: &DatasetConfig) -> PathBuf {
        let tag = if config.is_test { "test" } else { "prod" };
        cache_dir.join(format!("triad-epoch{}-{}.bin", seed.epoch, tag))
    }

    /// Versucht, das volle Dataset aus dem Disk-Cache zu laden.
    /// Gibt None zurück bei fehlender Datei, Header-Mismatch, falscher Länge oder IO-Fehler.
    fn try_load_full_from_disk(
        path:   &Path,
        seed:   &EpochSeed,
        config: &DatasetConfig,
    ) -> Option<Vec<[u8; ITEM_SIZE]>> {
        let mut f = File::open(path).ok()?;

        let mut header = [0u8; CACHE_HEADER_LEN];
        f.read_exact(&mut header).ok()?;
        if &header[0..8] != CACHE_MAGIC {
            return None;
        }
        let fmt = u32::from_le_bytes(header[8..12].try_into().ok()?);
        if fmt != CACHE_FORMAT_VERSION {
            return None;
        }
        let is_test = u32::from_le_bytes(header[12..16].try_into().ok()?) != 0;
        if is_test != config.is_test {
            return None;
        }
        let epoch = u32::from_le_bytes(header[16..20].try_into().ok()?);
        if epoch != seed.epoch {
            return None;
        }
        let item_count = u64::from_le_bytes(header[20..28].try_into().ok()?) as usize;
        if item_count != config.item_count {
            return None;
        }
        if &header[28..60] != seed.seed_hash.as_bytes() {
            return None;
        }

        // Exakte Dateilänge prüfen → erkennt Truncation/Korruption.
        let expected_len = (CACHE_HEADER_LEN + item_count * ITEM_SIZE) as u64;
        if f.metadata().ok()?.len() != expected_len {
            return None;
        }

        // In einen zusammenhängenden Item-Vektor einlesen (kein zweiter 4-GB-Buffer).
        let mut data: Vec<[u8; ITEM_SIZE]> = vec![[0u8; ITEM_SIZE]; item_count];
        // SAFETY: `[u8; ITEM_SIZE]` ist Plain-Old-Data und der Vec-Speicher ist
        // zusammenhängend; die Byte-View hat exakt item_count*ITEM_SIZE Bytes.
        let byte_view: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut u8, item_count * ITEM_SIZE)
        };
        f.read_exact(byte_view).ok()?;
        Some(data)
    }

    /// Schreibt das volle Dataset atomar in den Disk-Cache (best effort).
    fn write_full_to_disk(
        path:   &Path,
        seed:   &EpochSeed,
        config: &DatasetConfig,
        data:   &[[u8; ITEM_SIZE]],
    ) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let tmp = path.with_extension("tmp");
        {
            let mut f = File::create(&tmp)?;
            let mut header = [0u8; CACHE_HEADER_LEN];
            header[0..8].copy_from_slice(CACHE_MAGIC);
            header[8..12].copy_from_slice(&CACHE_FORMAT_VERSION.to_le_bytes());
            header[12..16].copy_from_slice(&(config.is_test as u32).to_le_bytes());
            header[16..20].copy_from_slice(&seed.epoch.to_le_bytes());
            header[20..28].copy_from_slice(&(config.item_count as u64).to_le_bytes());
            header[28..60].copy_from_slice(seed.seed_hash.as_bytes());
            f.write_all(&header)?;
            // SAFETY: zusammenhängender POD-Speicher, exakt data.len()*ITEM_SIZE Bytes.
            let byte_view: &[u8] = unsafe {
                std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * ITEM_SIZE)
            };
            f.write_all(byte_view)?;
            f.sync_all()?;
        }
        // Atomar einsetzen — ein Leser sieht nie eine halb geschriebene Datei.
        fs::rename(&tmp, path)?;
        Ok(())
    }

    /// Entfernt Cache-Dateien anderer Epochen (verhindert unbegrenztes Disk-Wachstum).
    fn prune_old_caches(cache_dir: &Path, keep: &Path) {
        if let Ok(entries) = fs::read_dir(cache_dir) {
            for e in entries.flatten() {
                let p = e.path();
                let name = e.file_name();
                let name = name.to_string_lossy();
                if name.starts_with("triad-epoch")
                    && (name.ends_with(".bin") || name.ends_with(".tmp"))
                    && p != keep
                {
                    let _ = fs::remove_file(&p);
                }
            }
        }
    }

    /// Wie `new_for_mining`, nutzt aber einen Disk-Cache unter `cache_dir`.
    ///
    /// Lädt das Dataset von Disk, falls eine gültige Cache-Datei für diese Epoche
    /// existiert; andernfalls wird es generiert und (best effort) geschrieben.
    /// Gibt zusätzlich `from_disk` zurück (true = aus Cache geladen).
    ///
    /// Cache-Fehler sind niemals fatal — es wird immer ein gültiges Dataset geliefert.
    pub fn new_for_mining_cached(
        seed:      &EpochSeed,
        config:    DatasetConfig,
        cache_dir: &Path,
    ) -> (Self, bool) {
        let path = Self::cache_file_path(cache_dir, seed, &config);

        if let Some(data) = Self::try_load_full_from_disk(&path, seed, &config) {
            // Cache-Hit: Der Verifier-Cache wird beim Mining nicht gebraucht
            // (get_item nutzt `data`), daher leer lassen → spart Zeit + RAM.
            return (
                Dataset { config, cache: Vec::new(), data: Some(data), epoch: seed.epoch },
                true,
            );
        }

        // Cache-Miss: regulär generieren …
        let cache = Self::generate_cache(seed, &config);
        let data  = Self::generate_full(&cache, &config);
        let epoch = seed.epoch;

        // … und für künftige Neustarts persistieren (Fehler ignorieren).
        if Self::write_full_to_disk(&path, seed, &config, &data).is_ok() {
            Self::prune_old_caches(cache_dir, &path);
        }

        (Dataset { config, cache: Vec::new(), data: Some(data), epoch }, false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_cache_dir(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("atlas-triad-test-{}-{}", tag, nanos))
    }

    /// Der Disk-Cache muss EXAKT dasselbe Dataset liefern wie die RAM-Generierung
    /// (Konsensneutralität) und beim zweiten Aufruf aus der Datei laden.
    #[test]
    fn test_disk_cache_roundtrip_is_identical() {
        let seed = EpochSeed::for_epoch(7);
        let dir  = unique_cache_dir("roundtrip");

        // Referenz: rein im RAM generiert.
        let reference = Dataset::new_for_mining(&seed, DatasetConfig::test());

        // Erster Aufruf → Cache-Miss (generiert + schreibt).
        let (first, from_disk1) = Dataset::new_for_mining_cached(&seed, DatasetConfig::test(), &dir);
        assert!(!from_disk1, "erster Aufruf muss Cache-Miss sein");

        // Zweiter Aufruf → Cache-Hit (von Disk geladen).
        let (second, from_disk2) = Dataset::new_for_mining_cached(&seed, DatasetConfig::test(), &dir);
        assert!(from_disk2, "zweiter Aufruf muss aus dem Disk-Cache laden");

        // Alle drei müssen byte-identisch sein (Stichprobe über das ganze Dataset).
        let n = DatasetConfig::test().item_count;
        for i in (0..n).step_by(997) {
            let r = reference.get_item(i);
            assert_eq!(r, first.get_item(i),  "RAM vs. frischer Cache weicht ab @ {}", i);
            assert_eq!(r, second.get_item(i), "RAM vs. geladener Cache weicht ab @ {}", i);
        }

        let _ = fs::remove_dir_all(&dir);
    }

    /// Ein Header-Mismatch (falsche Epoche) darf NICHT geladen werden, sondern
    /// muss sauber zu einem Cache-Miss / Neuaufbau führen.
    #[test]
    fn test_disk_cache_rejects_wrong_epoch() {
        let dir = unique_cache_dir("epoch");

        // Cache für Epoche 1 schreiben.
        let seed1 = EpochSeed::for_epoch(1);
        let (_d, miss) = Dataset::new_for_mining_cached(&seed1, DatasetConfig::test(), &dir);
        assert!(!miss);

        // Für Epoche 2 darf die Datei von Epoche 1 nicht akzeptiert werden.
        let seed2 = EpochSeed::for_epoch(2);
        let path1 = Dataset::cache_file_path(&dir, &seed1, &DatasetConfig::test());
        assert!(Dataset::try_load_full_from_disk(&path1, &seed2, &DatasetConfig::test()).is_none());

        let _ = fs::remove_dir_all(&dir);
    }

    /// Eine abgeschnittene Datei (Korruption) muss erkannt und verworfen werden.
    #[test]
    fn test_disk_cache_rejects_truncated_file() {
        let seed = EpochSeed::for_epoch(3);
        let dir  = unique_cache_dir("trunc");

        let (_d, _miss) = Dataset::new_for_mining_cached(&seed, DatasetConfig::test(), &dir);
        let path = Dataset::cache_file_path(&dir, &seed, &DatasetConfig::test());

        // Datei künstlich kürzen.
        let f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
        f.set_len((CACHE_HEADER_LEN + 10) as u64).unwrap();
        drop(f);

        assert!(Dataset::try_load_full_from_disk(&path, &seed, &DatasetConfig::test()).is_none());

        let _ = fs::remove_dir_all(&dir);
    }
}
