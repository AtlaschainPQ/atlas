//! TRIAD Mining Benchmark

#include "triad.h"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <atomic>

using namespace atlas::triad;
using Clock = std::chrono::high_resolution_clock;

int main() {
    std::cout << "=== ATLAS TRIAD Mining Benchmark ===" << std::endl;

    // Test-Dataset (16 MB, schnell zu generieren)
    std::cout << "Generating test dataset (16 MB)..." << std::flush;
    auto t0      = Clock::now();
    auto seed    = EpochSeed::for_epoch(0);
    Dataset ds(seed, /*test_mode=*/true);
    auto   t1    = Clock::now();
    double gen_s = std::chrono::duration<double>(t1 - t0).count();
    std::cout << " done in " << std::fixed << std::setprecision(2) << gen_s << "s" << std::endl;

    // Hash-Rate messen
    std::cout << "Measuring hash rate (5 seconds)..." << std::flush;
    TriadHasher  hasher(ds);
    uint8_t      prefix[32] = {0x01, 0x02, 0x03};
    uint64_t     count = 0;
    auto         bench_start = Clock::now();
    double       bench_secs  = 5.0;

    uint64_t nonce = 0;
    while (true) {
        auto [bh, mh] = hasher.hash(prefix, 32, nonce++);
        ++count;
        auto now = Clock::now();
        if (std::chrono::duration<double>(now - bench_start).count() >= bench_secs) break;
    }

    double elapsed = std::chrono::duration<double>(Clock::now() - bench_start).count();
    double rate    = count / elapsed;

    std::cout << " done." << std::endl;
    std::cout << std::endl;
    std::cout << "Results:" << std::endl;
    std::cout << "  Hashes: " << count << std::endl;
    std::cout << "  Time:   " << std::fixed << std::setprecision(2) << elapsed << "s" << std::endl;
    std::cout << "  Rate:   " << std::fixed << std::setprecision(0) << rate << " H/s" << std::endl;
    std::cout << "  Rate:   " << std::fixed << std::setprecision(2) << rate/1000.0 << " kH/s" << std::endl;

    // Easy-Target Mining
    std::cout << std::endl << "Mining with easy target (8 leading zero bits)..." << std::flush;
    Hash32 easy_target;
    easy_target.fill(0xff);
    easy_target[0] = 0x00;
    easy_target[1] = 0xff;

    auto shared_ds = std::shared_ptr<Dataset>(&ds, [](Dataset*){});
    Miner miner(shared_ds, 1);
    std::atomic<bool> stop{false};
    auto mine_start  = Clock::now();
    auto result      = miner.mine(prefix, 32, easy_target, 0, stop);
    double mine_time = std::chrono::duration<double>(Clock::now() - mine_start).count();

    if (result.found) {
        std::cout << " found!" << std::endl;
        std::cout << "  Nonce:    " << result.nonce << std::endl;
        std::cout << "  Time:     " << std::fixed << std::setprecision(3) << mine_time << "s" << std::endl;
        std::cout << "  Hashrate: " << std::fixed << std::setprecision(0) << result.hashrate << " H/s" << std::endl;
    } else {
        std::cout << " not found." << std::endl;
    }

    return 0;
}
