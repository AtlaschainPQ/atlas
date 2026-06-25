//! TRIAD Mining Engine — C++ Hochleistungs-Implementierung
//!
//! WICHTIG: Rust verifiziert immer das Ergebnis (Determinism Firewall).
//! C++ liefert nur Mining-Kandidaten.

#include "triad.h"
#include <cstring>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <algorithm>

// Forward declarations
namespace atlas::triad {
    Hash32 sha256_compute(const uint8_t*, size_t);
}

namespace atlas::triad {

// ── TriadHasher ──────────────────────────────────────────────────────────────

TriadHasher::TriadHasher(const Dataset& dataset) : dataset_(dataset) {}

Hash32 TriadHasher::sha256(const uint8_t* data, size_t len) {
    return sha256_compute(data, len);
}

Hash32 TriadHasher::sha256_double(const uint8_t* data, size_t len) {
    Hash32 first  = sha256_compute(data, len);
    Hash32 second = sha256_compute(first.data(), 32);
    return second;
}

std::pair<Hash32, Hash32> TriadHasher::hash(
    const uint8_t* prefix,
    size_t         prefix_len,
    uint64_t       nonce
) const {
    // Schritt 1: Seed-Hash = SHA256(prefix || nonce)
    std::vector<uint8_t> seed_input(prefix_len + 8);
    memcpy(seed_input.data(), prefix, prefix_len);
    memcpy(seed_input.data() + prefix_len, &nonce, 8);
    Hash32 seed_hash = sha256(seed_input.data(), seed_input.size());

    // Schritt 2: Initialer Mix
    Item64 mix = {};
    memcpy(mix.data(),      seed_hash.data(), 32);
    Hash32 seed_h2 = sha256(seed_hash.data(), 32);
    memcpy(mix.data() + 32, seed_h2.data(), 32);

    const size_t item_count = dataset_.item_count();

    // Schritt 3: Memory-Hard Dataset-Lookups (data-dependent)
    for (size_t i = 0; i < ACCESSES; i++) {
        uint64_t idx_raw;
        memcpy(&idx_raw, mix.data(), 8);

        // Permutation (verhindert Vorausberechnung)
        size_t idx = (idx_raw ^ (i * 0x9e3779b9ULL)) % item_count;

        Item64 item = dataset_.get_item(idx);

        // FNV-ähnlicher Mix
        for (size_t j = 0; j < ITEM_SIZE; j++) {
            mix[j] = static_cast<uint8_t>(
                static_cast<uint32_t>(mix[j]) * 0xfeu + item[j]
            );
        }

        // Periodische SHA-Runde
        if ((i & 7) == 7) {
            Hash32 h = sha256(mix.data(), 32);
            memcpy(mix.data(), h.data(), 32);
        }
    }

    // Schritt 4: Mix-Hash
    Hash32 mix_hash = sha256(mix.data(), ITEM_SIZE);

    // Schritt 5: Final Block-Hash = SHA256(SHA256(seed || mix_hash))
    uint8_t final_input[64];
    memcpy(final_input,      seed_hash.data(), 32);
    memcpy(final_input + 32, mix_hash.data(),  32);
    Hash32 block_hash = sha256_double(final_input, 64);

    return { block_hash, mix_hash };
}

// ── Miner ────────────────────────────────────────────────────────────────────

Miner::Miner(std::shared_ptr<Dataset> dataset, int threads)
    : dataset_(std::move(dataset))
    , threads_(threads <= 0 ? static_cast<int>(std::thread::hardware_concurrency()) : threads)
    , hasher_(*dataset_)
{}

bool Miner::meets_target(const Hash32& hash, const Hash32& target) const {
    // Vergleich: hash <= target (big-endian)
    return hash <= target;
}

MineResult Miner::mine(
    const uint8_t*     prefix,
    size_t             prefix_len,
    const Hash32&      target,
    uint64_t           start_nonce,
    std::atomic<bool>& stop
) {
    using Clock = std::chrono::high_resolution_clock;
    auto   t0   = Clock::now();
    uint64_t hashes = 0;

    uint64_t nonce = start_nonce;
    while (!stop.load(std::memory_order_relaxed)) {
        auto [block_hash, mix_hash] = hasher_.hash(prefix, prefix_len, nonce);

        if (meets_target(block_hash, target)) {
            auto  t1      = Clock::now();
            double elapsed = std::chrono::duration<double>(t1 - t0).count();
            double rate    = elapsed > 0 ? hashes / elapsed : 0;
            stop.store(true, std::memory_order_relaxed);
            return MineResult{true, nonce, block_hash, mix_hash, rate};
        }

        ++hashes;
        ++nonce;
        if (nonce == start_nonce) break; // Overflow
    }

    return MineResult{false, 0, {}, {}, 0.0};
}

MineResult Miner::mine_parallel(
    const uint8_t* prefix,
    size_t         prefix_len,
    const Hash32&  target
) {
    std::atomic<bool> stop{false};
    MineResult        winner{false, 0, {}, {}, 0.0};
    std::vector<std::thread> pool;

    uint64_t range = UINT64_MAX / threads_;

    for (int t = 0; t < threads_; t++) {
        uint64_t start = static_cast<uint64_t>(t) * range;
        pool.emplace_back([&, start]() {
            auto result = mine(prefix, prefix_len, target, start, stop);
            if (result.found) {
                winner = result;
            }
        });
    }

    for (auto& th : pool) { th.join(); }
    return winner;
}

// ── C FFI ────────────────────────────────────────────────────────────────────

extern "C" {

int triad_mine(
    void*          dataset_ptr,
    const uint8_t* prefix,
    size_t         prefix_len,
    const uint8_t* target,
    uint64_t       start_nonce,
    uint64_t*      out_nonce,
    uint8_t*       out_block_hash,
    uint8_t*       out_mix_hash
) {
    auto* dataset = static_cast<Dataset*>(dataset_ptr);
    auto  shared  = std::shared_ptr<Dataset>(dataset, [](Dataset*){});  // non-owning
    Miner miner(shared);

    Hash32 target_arr;
    memcpy(target_arr.data(), target, 32);

    std::atomic<bool> stop{false};
    MineResult result = miner.mine(prefix, prefix_len, target_arr, start_nonce, stop);

    if (!result.found) return 0;

    *out_nonce = result.nonce;
    memcpy(out_block_hash, result.block_hash.data(), 32);
    memcpy(out_mix_hash,   result.mix_hash.data(),   32);
    return 1;
}

void triad_hash(
    void*          dataset_ptr,
    const uint8_t* prefix,
    size_t         prefix_len,
    uint64_t       nonce,
    uint8_t*       out_block_hash,
    uint8_t*       out_mix_hash
) {
    auto* dataset = static_cast<Dataset*>(dataset_ptr);
    TriadHasher hasher(*dataset);
    auto [block_hash, mix_hash] = hasher.hash(prefix, prefix_len, nonce);
    memcpy(out_block_hash, block_hash.data(), 32);
    memcpy(out_mix_hash,   mix_hash.data(),   32);
}

} // extern "C"

} // namespace atlas::triad
