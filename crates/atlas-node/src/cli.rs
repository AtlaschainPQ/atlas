//! ATLAS CLI — Kommandozeilen-Interface

use atlas_consensus::params::ConsensusParams;
use atlas_consensus::reward::RewardSchedule;
use atlas_core::amount::Amount;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "emission" => print_emission_table(),
        "supply"   => print_supply_info(),
        "fees"     => print_fee_info(),
        _ => print_help(),
    }
}

fn print_emission_table() {
    let params   = ConsensusParams::mainnet();
    let schedule = RewardSchedule::new(&params);
    let table    = schedule.emission_table();

    println!("\n=== ATLAS Emissionstabelle ===");
    println!("{:>4} | {:>12} | {:>12} | {:>16}", "Era", "Startblock", "ATL/Block", "Era-Gesamtmenge");
    println!("{}", "-".repeat(55));

    let mut cumulative = Amount::ZERO;
    for (era, start, subsidy) in &table {
        let era_total = *subsidy * params.halving_interval as u128;
        cumulative   += era_total;
        println!(
            "{:>4} | {:>12} | {:>12} | {:>14} ATL",
            era,
            start,
            subsidy.as_atl_floor(),
            era_total.as_atl_floor(),
        );
    }
    println!("{}", "-".repeat(55));
    println!("Max Supply: {} ATL", cumulative.as_atl_floor());
    println!("(ca. 100.000.000 ATL)\n");
}

fn print_supply_info() {
    let params = ConsensusParams::mainnet();
    println!("\n=== ATLAS Geldpolitik ===");
    println!("Start-Subsidy:     {} ATL/Block", params.initial_subsidy.as_atl_floor());
    println!("Halving-Intervall: {} Blöcke (~4.75 Jahre)", params.halving_interval);
    println!("Max Supply:        ~100.000.000 ATL");
    println!("Blockzeit:         ~10 Minuten");
    println!();
    println!("Einheitensystem:");
    println!("  1 ATL  = 100.000.000 UNIT");
    println!("  1 UNIT = 10.000 ATOM");
    println!("  1 ATL  = 1.000.000.000.000 ATOM");
    println!();
    println!("Reward-Verteilung:");
    println!("  Miner:  70% von (Subsidy + Fees)");
    println!("  Prover: 30% von (Subsidy + Fees)");
}

fn print_fee_info() {
    println!("\n=== ATLAS Gebührenmodell ===");
    println!("Minimale Fee:  10 ATOM");
    println!("Maximale Fee: 100 ATOM  (Fee-Cap)");
    println!();
    println!("ATL-Preis | 100 ATOM in €");
    println!("{}", "-".repeat(30));
    for price_eur in [1_000u128, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000] {
        // 100 ATOM / 1e12 * price
        // In Cent: 100 * price / 1e12 * 100
        let cent_times_million = 100u128 * price_eur * 100 / 1_000_000_000_000u128;
        let euros = cent_times_million / 100_000_000;
        let cents = (cent_times_million % 100_000_000) / 1_000_000;
        let milli  = (cent_times_million % 1_000_000) / 1_000;
        println!("{:>12} € | {:}.{:02}.{:03} €", price_eur, euros, cents, milli);
    }
    println!();
    println!("TX-Stamp (Spam-Schutz): ~20-50ms CPU-Arbeit pro TX");
}

fn print_help() {
    println!("\n=== ATLAS CLI ===");
    println!("Befehle:");
    println!("  emission  — Emissionstabelle anzeigen");
    println!("  supply    — Geldpolitik-Übersicht");
    println!("  fees      — Gebührenmodell-Übersicht");
    println!("  help      — Diese Hilfe");
    println!();
    println!("Node starten: atlas-node");
}
