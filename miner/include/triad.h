#pragma once
#include <cstdint>
#include <cstddef>
#include <vector>
#include <array>
#include <memory>
#include <atomic>
#include <functional>

namespace atlas::triad {

// ── Konstanten ──────────────────────────────────────────────────────────────

constexpr size_t ITEM_SIZE       = 64;
constexpr size_t ACCESSES        = 64;
constexpr size_t EPOCH_LENGTH    = 2016;

// Produktions-Dataset: 4 GB
constexpr size_t DATASET_SIZE    = 4ULL * 1024 * 1024 * 1024;
constexpr size_t DATASET_ITEMS   = DATASET_SIZE / ITEM_SIZE;

// Test-Dataset: 16 MB
constexpr size_t TEST_DATASET_SIZE  = 16 * 1024 * 1024;
constexpr size_t TEST_DATASET_ITEMS = TEST_DATASET_SIZE / ITEM_SIZE;

using Hash32 = std::array<uint8_t, 32>;
using Item64 = std::array<uint8_t, ITEM_SIZE>;

// ── Epoch-Seed ───────────────────────────────────────────────────────────────

struct EpochSeed {
    uint32_t epoch;
    Hash32   seed_hash;
    Hash32   permutation;
    Hash32   cache_seed;

    static EpochSeed for_epoch(uint32_t epoch);
};

// ── Mining-Ergebnis ──────────────────────────────────────────────────────────

struct MineResult {
    bool     found;
    uint64_t nonce;
    Hash32   block_hash;
    Hash32   mix_hash;
    double   hashrate;   // H/s
};

// ── Dataset ─────────────────────────────────────────────────────────────────

class Dataset {
public:
    explicit Dataset(const EpochSeed& seed, bool test_mode = false);

    // Gibt ein Dataset-Item zurück (aus RAM oder aus Cache berechnet)
    Item64 get_item(size_t index) const;

    size_t item_count() const { return item_count_; }
    bool   is_test()    const { return test_mode_;  }

    // Generiert Cache (schnell, für Verifier)
    static std::vector<Item64> generate_cache(const EpochSeed& seed, size_t count);

    // Generiert volles Dataset aus Cache (RAM-intensiv, parallel)
    static std::vector<Item64> generate_full(
        const std::vector<Item64>& cache,
        size_t                     item_count,
        int                        threads = 0
    );

    // Einzelnes Dataset-Item aus Cache berechnen (für Verifier)
    static Item64 calc_item(const std::vector<Item64>& cache, size_t index);

private:
    EpochSeed          seed_;
    bool               test_mode_;
    size_t             item_count_;
    std::vector<Item64> cache_;
    std::vector<Item64> data_;   // Leer bei Verifier-Only Mode
};

// ── TRIAD Hasher ─────────────────────────────────────────────────────────────

class TriadHasher {
public:
    explicit TriadHasher(const Dataset& dataset);

    // Berechnet TRIAD-Hash für einen Nonce
    // Gibt (block_hash, mix_hash) zurück
    std::pair<Hash32, Hash32> hash(
        const uint8_t* header_prefix,
        size_t         prefix_len,
        uint64_t       nonce
    ) const;

private:
    const Dataset& dataset_;

    static Hash32 sha256(const uint8_t* data, size_t len);
    static Hash32 sha256_double(const uint8_t* data, size_t len);
    static Hash32 keccak256(const uint8_t* data, size_t len);
};

// ── Miner ────────────────────────────────────────────────────────────────────

class Miner {
public:
    Miner(std::shared_ptr<Dataset> dataset, int threads = 0);

    // Mining-Loop: sucht Nonce die target erfüllt
    // stop: wird auf true gesetzt wenn Lösung gefunden
    MineResult mine(
        const uint8_t*          header_prefix,
        size_t                  prefix_len,
        const Hash32&           target,
        uint64_t                start_nonce,
        std::atomic<bool>&      stop
    );

    // Multi-Thread Mining
    MineResult mine_parallel(
        const uint8_t*     header_prefix,
        size_t             prefix_len,
        const Hash32&      target
    );

private:
    std::shared_ptr<Dataset> dataset_;
    int                      threads_;
    TriadHasher              hasher_;

    bool meets_target(const Hash32& hash, const Hash32& target) const;
};

// ── C FFI Interface (für Rust via FFI) ───────────────────────────────────────

extern "C" {

// Erstellt ein Dataset
void* triad_dataset_create(const uint8_t* seed_bytes, bool test_mode);
void  triad_dataset_destroy(void* dataset);

// Mining
int triad_mine(
    void*          dataset,
    const uint8_t* header_prefix,
    size_t         prefix_len,
    const uint8_t* target,      // 32 Bytes
    uint64_t       start_nonce,
    uint64_t*      out_nonce,
    uint8_t*       out_block_hash,  // 32 Bytes
    uint8_t*       out_mix_hash     // 32 Bytes
);

// Hash-Berechnung
void triad_hash(
    void*          dataset,
    const uint8_t* header_prefix,
    size_t         prefix_len,
    uint64_t       nonce,
    uint8_t*       out_block_hash,
    uint8_t*       out_mix_hash
);

} // extern "C"

} // namespace atlas::triad
