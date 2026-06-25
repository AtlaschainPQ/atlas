#include "triad.h"
#include <cstring>
#include <thread>
#include <vector>
#include <algorithm>

// Forward declaration
namespace atlas::triad { Hash32 sha256_compute(const uint8_t*, size_t); }

namespace atlas::triad {

// ── EpochSeed ────────────────────────────────────────────────────────────────

EpochSeed EpochSeed::for_epoch(uint32_t epoch) {
    EpochSeed seed;
    seed.epoch = epoch;

    // seed_hash: SHA256("ATLAS-TRIAD-v1:epoch:" || epoch_bytes)
    {
        uint8_t buf[25];
        memcpy(buf, "ATLAS-TRIAD-v1:epoch:", 21);
        memcpy(buf + 21, &epoch, 4);
        seed.seed_hash = sha256_compute(buf, 25);
    }

    // permutation: SHA256("ATLAS-TRIAD-v1:perm:" || seed_hash)
    {
        uint8_t buf[52];
        memcpy(buf, "ATLAS-TRIAD-v1:perm:", 20);
        memcpy(buf + 20, seed.seed_hash.data(), 32);
        seed.permutation = sha256_compute(buf, 52);
    }

    // cache_seed: SHA256(seed_hash || permutation)
    {
        uint8_t buf[64];
        memcpy(buf,      seed.seed_hash.data(),  32);
        memcpy(buf + 32, seed.permutation.data(), 32);
        seed.cache_seed = sha256_compute(buf, 64);
    }

    return seed;
}

// ── Cache-Generierung ────────────────────────────────────────────────────────

std::vector<Item64> Dataset::generate_cache(const EpochSeed& seed, size_t count) {
    std::vector<Item64> cache(count);

    // Erstes Item: SHA256(cache_seed) || SHA256(SHA256(cache_seed))
    {
        Item64 item = {};
        Hash32 h1   = sha256_compute(seed.cache_seed.data(), 32);
        Hash32 h2   = sha256_compute(h1.data(), 32);
        memcpy(item.data(),      h1.data(), 32);
        memcpy(item.data() + 32, h2.data(), 32);
        cache[0] = item;
    }

    // Folgeelemente
    for (size_t i = 1; i < count; i++) {
        Item64 item = {};
        Hash32 h1   = sha256_compute(cache[i-1].data(), 32);
        Hash32 h2   = sha256_compute(h1.data(), 32);
        memcpy(item.data(),      h1.data(), 32);
        memcpy(item.data() + 32, h2.data(), 32);
        cache[i] = item;
    }

    // Memory-Hardness: 3 Durchläufe (Scrypt-ähnlich)
    for (int round = 0; round < 3; round++) {
        for (size_t i = 0; i < count; i++) {
            size_t prev_idx = (i == 0) ? count - 1 : i - 1;
            uint64_t xor_idx_raw;
            memcpy(&xor_idx_raw, cache[i].data(), 8);
            size_t xor_idx = xor_idx_raw % count;

            Item64 mixed = {};
            for (size_t j = 0; j < ITEM_SIZE; j++) {
                mixed[j] = cache[prev_idx][j] ^ cache[xor_idx][j];
            }
            Hash32 h = sha256_compute(mixed.data(), 32);
            memcpy(mixed.data(), h.data(), 32);
            cache[i] = mixed;
        }
    }

    return cache;
}

// ── Dataset-Item Berechnung ───────────────────────────────────────────────────

Item64 Dataset::calc_item(const std::vector<Item64>& cache, size_t index) {
    size_t c_size = cache.size();
    Item64 mix    = cache[index % c_size];

    // Index-Modifikation (XOR)
    uint64_t idx_u64 = static_cast<uint64_t>(index);
    for (size_t j = 0; j < 8; j++) {
        mix[j] ^= static_cast<uint8_t>(idx_u64 >> (j * 8));
    }

    // Data-dependent Lookups — GPU-feindlich
    for (size_t i = 0; i < ACCESSES; i++) {
        uint64_t next_raw;
        memcpy(&next_raw, mix.data(), 8);
        size_t next_idx = next_raw % c_size;

        // FNV-ähnlicher Mix
        for (size_t j = 0; j < ITEM_SIZE; j++) {
            mix[j] = static_cast<uint8_t>(
                static_cast<uint32_t>(mix[j]) * 0xfeu + cache[next_idx][j]
            );
        }

        // SHA-256 Runde alle 8 Accesses
        if ((i & 7) == 7) {
            Hash32 h = sha256_compute(mix.data(), 32);
            memcpy(mix.data(), h.data(), 32);
        }
    }

    return mix;
}

// ── Volles Dataset generieren (parallel) ─────────────────────────────────────

std::vector<Item64> Dataset::generate_full(
    const std::vector<Item64>& cache,
    size_t                      item_count,
    int                         threads
) {
    if (threads <= 0) {
        threads = static_cast<int>(std::thread::hardware_concurrency());
    }
    threads = std::max(1, threads);

    std::vector<Item64> data(item_count);

    auto worker = [&](size_t start, size_t end) {
        for (size_t i = start; i < end; i++) {
            data[i] = calc_item(cache, i);
        }
    };

    std::vector<std::thread> pool;
    size_t chunk = item_count / threads;
    for (int t = 0; t < threads; t++) {
        size_t from = t * chunk;
        size_t to   = (t == threads - 1) ? item_count : from + chunk;
        pool.emplace_back(worker, from, to);
    }
    for (auto& th : pool) { th.join(); }

    return data;
}

// ── Dataset Konstruktor ───────────────────────────────────────────────────────

Dataset::Dataset(const EpochSeed& seed, bool test_mode)
    : seed_(seed)
    , test_mode_(test_mode)
    , item_count_(test_mode ? TEST_DATASET_ITEMS : DATASET_ITEMS)
{
    size_t cache_count = item_count_ / 32;
    cache_ = generate_cache(seed, cache_count);

    // Nur für Mining: volles Dataset laden
    // Für Verifier: nur Cache
    // (Hier: immer nur Cache für Memory-Effizienz im Stub)
}

Item64 Dataset::get_item(size_t index) const {
    size_t idx = index % item_count_;
    if (!data_.empty()) {
        return data_[idx];
    }
    return calc_item(cache_, idx % cache_.size());
}

// ── C FFI ────────────────────────────────────────────────────────────────────

extern "C" {

void* triad_dataset_create(const uint8_t* seed_bytes, bool test_mode) {
    EpochSeed seed;
    seed.epoch = 0;
    memcpy(seed.seed_hash.data(), seed_bytes, 32);
    seed = EpochSeed::for_epoch(0);
    return new Dataset(seed, test_mode);
}

void triad_dataset_destroy(void* dataset) {
    delete static_cast<Dataset*>(dataset);
}

} // extern "C"

} // namespace atlas::triad
