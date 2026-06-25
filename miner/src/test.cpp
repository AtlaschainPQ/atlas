#include "triad.h"
#include <cassert>
#include <iostream>
#include <atomic>

using namespace atlas::triad;

void test_epoch_seed_deterministic() {
    auto s1 = EpochSeed::for_epoch(7);
    auto s2 = EpochSeed::for_epoch(7);
    assert(s1.seed_hash == s2.seed_hash && "EpochSeed must be deterministic");
    assert(s1.seed_hash != EpochSeed::for_epoch(8).seed_hash && "Different epochs different seeds");
    std::cout << "PASS: epoch_seed_deterministic" << std::endl;
}

void test_hash_deterministic() {
    auto seed = EpochSeed::for_epoch(0);
    Dataset ds(seed, true);
    TriadHasher hasher(ds);

    uint8_t prefix[8] = {1,2,3,4,5,6,7,8};
    auto [h1, m1] = hasher.hash(prefix, 8, 42);
    auto [h2, m2] = hasher.hash(prefix, 8, 42);
    assert(h1 == h2 && "Hash must be deterministic");
    assert(m1 == m2 && "Mix hash must be deterministic");
    std::cout << "PASS: hash_deterministic" << std::endl;
}

void test_hash_nonce_sensitive() {
    auto seed = EpochSeed::for_epoch(0);
    Dataset ds(seed, true);
    TriadHasher hasher(ds);

    uint8_t prefix[8] = {1,2,3,4,5,6,7,8};
    auto [h1, _m1] = hasher.hash(prefix, 8, 1);
    auto [h2, _m2] = hasher.hash(prefix, 8, 2);
    assert(h1 != h2 && "Different nonces must produce different hashes");
    std::cout << "PASS: hash_nonce_sensitive" << std::endl;
}

void test_mine_easy_target() {
    auto seed = EpochSeed::for_epoch(0);
    auto shared_ds = std::make_shared<Dataset>(seed, true);
    Miner miner(shared_ds, 1);

    Hash32 target;
    target.fill(0xff);
    target[0] = 0x0f; // 4 führende Nullbits

    uint8_t prefix[4] = {0xde, 0xad, 0xbe, 0xef};
    std::atomic<bool> stop{false};
    auto result = miner.mine(prefix, 4, target, 0, stop);

    assert(result.found && "Should find solution with easy target");
    assert(result.block_hash <= target && "Hash must meet target");
    std::cout << "PASS: mine_easy_target (nonce=" << result.nonce << ")" << std::endl;
}

int main() {
    std::cout << "=== ATLAS TRIAD Tests ===" << std::endl;
    test_epoch_seed_deterministic();
    test_hash_deterministic();
    test_hash_nonce_sensitive();
    test_mine_easy_target();
    std::cout << "All tests passed!" << std::endl;
    return 0;
}
