//! Erzeugt ein frisches L2-Konto (Baby-Jubjub-EdDSA).
//!
//! Ausgabe: `secret_hex` (32 Byte — der private Schlüssel, GEHEIM halten/sichern)
//! und `address_hex` (20 Byte — die öffentliche L2-Adresse). Der Secret kann in
//! die Web-Wallet (`account_from_secret`) importiert werden, um über das Konto zu
//! verfügen.
//!
//!   cargo run -p atlas-zk --release --bin gen_account

use atlas_zk::eddsa::EddsaKeypair;
use rand::RngCore;

fn main() {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let kp = EddsaKeypair::from_secret_bytes(&secret);
    println!("secret_hex={}", hex::encode(secret));
    println!("address_hex={}", hex::encode(kp.public().address20()));
}
