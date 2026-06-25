//! Genesis-Werkzeug für ATLAS.
//!
//!   cargo run -p atlas-zk --release --bin genesis_root
//!       → gibt die GENESIS_L2_ROOT-Konstante (aus genesis/alloc.json) für
//!         atlas-core/src/block.rs aus.
//!
//!   cargo run -p atlas-zk --release --bin genesis_root -- dump-dev
//!       → gibt die seed-basierte Dev-Allokation als JSON aus (zum Erzeugen
//!         der genesis/alloc.json für Dev/Testnet).
//!
//!   cargo run -p atlas-zk --release --bin genesis_root -- root-of <datei.json>
//!       → liest eine beliebige Allokationsdatei und gibt deren Root + Konstante
//!         aus (Mainnet-Workflow: echte Allokation schreiben → Root generieren).

use atlas_zk::l2_state::{
    dev_genesis_allocation, genesis_alloc_to_json, parse_genesis_alloc_json, L2State,
};
use atlas_zk::{genesis_allocation, GenesisAlloc};

fn print_const(allocs: &[GenesisAlloc]) {
    let root = L2State::from_genesis(allocs).root_bytes();
    println!("// {} geförderte Konten, Root (hex): {}", allocs.len(), hex::encode(root));
    print!("pub const GENESIS_L2_ROOT: [u8; 32] = [");
    for (i, b) in root.iter().enumerate() {
        if i % 12 == 0 { print!("\n    "); }
        print!("0x{:02x}, ", b);
    }
    println!("\n];");
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(|s| s.as_str()) {
        Some("dump-dev") => {
            // Seed-basierte Dev-Allokation als JSON (für genesis/alloc.json).
            println!("{}", genesis_alloc_to_json(&dev_genesis_allocation()));
        }
        Some("root-of") => {
            let path = args.get(2)
                .ok_or_else(|| anyhow::anyhow!("Usage: genesis_root root-of <datei.json>"))?;
            let s = std::fs::read_to_string(path)?;
            let allocs = parse_genesis_alloc_json(&s)?;
            print_const(&allocs);
        }
        _ => {
            // Default: Root der eingebetteten genesis/alloc.json.
            print_const(&genesis_allocation());
        }
    }
    Ok(())
}
