//! Hochrangiger L2-State-Manager für Aggregatoren — kapselt ALLE `ark`-Typen.
//!
//! Der Aggregator hält genau eine Instanz dieses Zustands (den belegten
//! `AccountTree`) und arbeitet ausschließlich mit 20-Byte-Adressen und
//! `u128`-Salden. Die Abbildung 20-Byte-Adresse → `Fr` geschieht hier injektiv
//! (160 Bit ⊂ 254 Bit ⇒ keine modulare Reduktion), sodass weder der Aggregator
//! noch der Node jemals direkt mit `Fr` hantieren müssen.
//!
//! Soundness-Bezug: `root_bytes()` liefert exakt die `pre_root`/`post_root`, die
//! als Public Inputs in den State-Transition-Beweis eingehen. Der vom
//! `apply()` zurückgegebene `BatchWitness` ist genau die Eingabe für
//! `ZkBatchProver::prove_state`.

use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::account::{Account, AccountTree};
use crate::eddsa::{EddsaPublicKey, EddsaSignature};
use crate::poseidon::hash_many;
use crate::proof::fr_to_bytes32;
use crate::transition::{apply_batch, BatchWitness, L2Tx, TransitionError};

/// Serialisierte Größe einer L2-TX in der On-Chain-Calldata:
/// from(20) + to(20) + amount(16) + fee(16) + nonce(8) = 80 Byte.
pub const CALLDATA_TX_SIZE: usize = 20 + 20 + 16 + 16 + 8;

/// Snapshot-Format (Aggregator-Persistenz): Versions-Tag + Record-Größe.
/// Bei Layout-Änderung Version erhöhen → alte Snapshots werden verworfen.
const L2_SNAPSHOT_VERSION: u32 = 1;
/// index(8) + address(20) + balance(16) + nonce(8) = 52 Byte pro Konto.
const SNAPSHOT_REC: usize = 8 + 20 + 16 + 8;

/// Kodiert L2-TXs als kompakte On-Chain-Calldata (Data Availability).
/// Reihenfolge MUSS der Batch-Reihenfolge entsprechen (für deterministisches Replay).
pub fn encode_calldata(txs: &[L2Input]) -> Vec<u8> {
    let mut out = Vec::with_capacity(txs.len() * CALLDATA_TX_SIZE);
    for t in txs {
        out.extend_from_slice(&t.from);
        out.extend_from_slice(&t.to);
        out.extend_from_slice(&t.amount.to_le_bytes());
        out.extend_from_slice(&t.fee.to_le_bytes());
        out.extend_from_slice(&t.nonce.to_le_bytes());
    }
    out
}

/// Dekodiert On-Chain-Calldata zurück in L2-TXs.
pub fn decode_calldata(bytes: &[u8]) -> Result<Vec<L2Input>, DaError> {
    if bytes.len() % CALLDATA_TX_SIZE != 0 {
        return Err(DaError::BadLength { len: bytes.len() });
    }
    let mut txs = Vec::with_capacity(bytes.len() / CALLDATA_TX_SIZE);
    for chunk in bytes.chunks_exact(CALLDATA_TX_SIZE) {
        let mut from = [0u8; 20];
        let mut to   = [0u8; 20];
        from.copy_from_slice(&chunk[0..20]);
        to.copy_from_slice(&chunk[20..40]);
        let amount = u128::from_le_bytes(chunk[40..56].try_into().unwrap());
        let fee    = u128::from_le_bytes(chunk[56..72].try_into().unwrap());
        let nonce  = u64::from_le_bytes(chunk[72..80].try_into().unwrap());
        txs.push(L2Input { from, to, amount, fee, nonce });
    }
    Ok(txs)
}

/// Berechnet das Batch-Commitment (Poseidon) AUS den Calldata-TXs — bit-genau
/// identisch zu `state_circuit::compute_batch_commitment` über die zugehörigen
/// Witness-Slots (reale TXs + Null-Padding auf `batch_size`).
///
/// So kann der Node das im Beweis gebundene `batch_commitment` unabhängig aus der
/// On-Chain-Calldata nachrechnen und damit beweisen, dass die veröffentlichten
/// Daten exakt der bewiesenen Zustandsänderung entsprechen (Data Availability).
pub fn batch_commitment_from_inputs(txs: &[L2Input], batch_size: usize) -> [u8; 32] {
    debug_assert!(txs.len() <= batch_size);
    let mut inputs: Vec<Fr> = Vec::with_capacity(batch_size * 5);
    for t in txs {
        inputs.push(address_to_fr(&t.from));
        inputs.push(address_to_fr(&t.to));
        inputs.push(Fr::from(t.amount));
        inputs.push(Fr::from(t.fee));
        inputs.push(Fr::from(t.nonce));
    }
    // Padding-Slots: from=to=amount=fee=nonce=0 ⇒ fünf Null-Felder je Slot.
    for _ in txs.len()..batch_size {
        for _ in 0..5 {
            inputs.push(Fr::from(0u64));
        }
    }
    fr_to_bytes32(hash_many(&inputs))
}

/// Fehler bei der Data-Availability-Dekodierung.
#[derive(thiserror::Error, Debug, PartialEq, Eq)]
pub enum DaError {
    #[error("Calldata-Länge {len} ist kein Vielfaches der TX-Größe")]
    BadLength { len: usize },
}

/// Bildet eine 20-Byte-L2-Adresse injektiv auf ein Feldelement ab.
/// 20 Byte = 160 Bit < 254 Bit (BN254-Skalarfeld) ⇒ keine Kollisionen.
pub fn address_to_fr(addr: &[u8; 20]) -> Fr {
    Fr::from_le_bytes_mod_order(addr)
}

/// Leitet die L2-Adresse (20 Byte) aus einem komprimierten EdDSA-Pubkey ab.
/// `None`, falls der Pubkey nicht dekodierbar ist.
pub fn eddsa_pubkey_to_address(pubkey: &[u8; 32]) -> Option<[u8; 20]> {
    EddsaPublicKey::from_bytes(pubkey).map(|p| p.address20())
}

/// Signiert eine L2-TX mit Baby-Jubjub EdDSA. Liefert (pubkey32, sig64).
/// `from` MUSS `kp.public().address20()` sein (wird hier nicht erzwungen).
pub fn sign_l2_eddsa(
    kp:     &crate::eddsa::EddsaKeypair,
    from:   &[u8; 20],
    to:     &[u8; 20],
    amount: u128,
    fee:    u128,
    nonce:  u64,
) -> ([u8; 32], [u8; 64]) {
    let m = crate::transition::tx_message(
        address_to_fr(from), address_to_fr(to), amount, fee, nonce);
    let sig = kp.sign(m);
    (kp.public().to_bytes(), sig.to_bytes())
}

/// One-shot für Wallet/Sender: liefert (from20, pubkey32, sig64) einer
/// EdDSA-signierten L2-TX. `from` = `kp.public().address20()`.
pub fn build_l2_eddsa(
    kp:     &crate::eddsa::EddsaKeypair,
    to:     &[u8; 20],
    amount: u128,
    fee:    u128,
    nonce:  u64,
) -> ([u8; 20], [u8; 32], [u8; 64]) {
    let from = kp.public().address20();
    let (pubkey, sig) = sign_l2_eddsa(kp, &from, to, amount, fee, nonce);
    (from, pubkey, sig)
}

/// Verifiziert eine L2-TX-Signatur byte-level inklusive Adressbindung
/// `from == lower160(Poseidon(pubkey.x, pubkey.y))`.
///
/// Dies ist die kryptographische Prüfung, die `atlas-core` NICHT leisten kann.
/// Der Aggregator ruft sie beim Annehmen jeder TX auf.
pub fn verify_l2_eddsa(
    from:   &[u8; 20],
    to:     &[u8; 20],
    amount: u128,
    fee:    u128,
    nonce:  u64,
    pubkey: &[u8; 32],
    sig:    &[u8; 64],
) -> bool {
    let pk = match EddsaPublicKey::from_bytes(pubkey) {
        Some(p) => p,
        None => return false,
    };
    let sg = match EddsaSignature::from_bytes(sig) {
        Some(s) => s,
        None => return false,
    };
    if &pk.address20() != from {
        return false;
    }
    let m = crate::transition::tx_message(
        address_to_fr(from), address_to_fr(to), amount, fee, nonce);
    crate::eddsa::verify(&pk, m, &sg)
}

/// Eine an der Byte-Grenze definierte L2-Transaktion (entkoppelt von `ark`).
/// Enthält NUR die On-Chain-Calldata-Felder — Signatur/Pubkey liegen separat in
/// [`SignedL2Input`] (Witness-only, nicht on-chain).
#[derive(Clone, Copy, Debug)]
pub struct L2Input {
    pub from:   [u8; 20],
    pub to:     [u8; 20],
    pub amount: u128,
    pub fee:    u128,
    pub nonce:  u64,
}

/// L2-Transaktion samt EdDSA-Authentifizierung (Aggregator-Eingabe für `apply`).
///
/// `pubkey` (32 B, komprimiert) und `sig` (64 B) sind **Witness-only**: sie gehen
/// als private Eingaben in den State-Transition-Beweis ein, NICHT in die On-Chain-
/// Calldata. Die Adresse `input.from` muss `pubkey.address20()` entsprechen — der
/// Circuit erzwingt die Bindung `from == lower160(Poseidon(A))`.
#[derive(Clone, Copy, Debug)]
pub struct SignedL2Input {
    pub input:  L2Input,
    pub pubkey: [u8; 32],
    pub sig:    [u8; 64],
}

/// Eine Genesis-Allokation: vorab gefördertes L2-Konto.
#[derive(Clone, Copy, Debug)]
pub struct GenesisAlloc {
    pub address: [u8; 20],
    pub balance: u128,
}

/// Belegter L2-Zustand: kapselt den `AccountTree`.
#[derive(Clone)]
pub struct L2State {
    tree: AccountTree,
}

impl L2State {
    /// Leerer Zustand — Wurzel == `empty_l2_state_root()`.
    pub fn new() -> Self {
        L2State { tree: AccountTree::new() }
    }

    /// Zustand aus einer deterministischen Genesis-Allokation.
    /// Node und Aggregator MÜSSEN dieselbe (sortierte) Allokation verwenden,
    /// damit ihre Genesis-L2-Wurzeln übereinstimmen.
    pub fn from_genesis(allocs: &[GenesisAlloc]) -> Self {
        let mut state = L2State::new();
        for a in allocs {
            state.credit(&a.address, a.balance);
        }
        state
    }

    /// Aktuelle State-Wurzel als 32 Byte (Big-Endian-kanonisch via `fr_to_bytes32`).
    pub fn root_bytes(&self) -> [u8; 32] {
        fr_to_bytes32(self.tree.root())
    }

    /// Aktuelles Guthaben einer Adresse (0 falls unbekannt).
    pub fn balance(&self, addr: &[u8; 20]) -> u128 {
        self.tree.account_of(address_to_fr(addr)).map(|a| a.balance).unwrap_or(0)
    }

    /// Aktuelle Nonce einer Adresse (0 falls unbekannt).
    pub fn nonce(&self, addr: &[u8; 20]) -> u64 {
        self.tree.account_of(address_to_fr(addr)).map(|a| a.nonce).unwrap_or(0)
    }

    /// Schreibt Guthaben gut (Bridge-Deposit / Genesis-Förderung).
    /// Legt das Konto bei Bedarf mit Nonce 0 an.
    pub fn credit(&mut self, addr: &[u8; 20], amount: u128) {
        let a = address_to_fr(addr);
        let idx = self.tree.ensure(a);
        let acct = self.tree.account_at(idx).expect("ensure liefert Index");
        let new_balance = acct.balance.saturating_add(amount);
        self.tree.write(idx, Account::new(a, new_balance, acct.nonce));
    }

    /// Wendet einen Batch an und liefert den `BatchWitness` für `prove_state`.
    ///
    /// All-or-nothing: bei einem Fehler bleibt der Zustand UNVERÄNDERT (die
    /// Anwendung läuft auf einer Kopie; erst bei Erfolg wird committet).
    pub fn apply(&mut self, txs: &[SignedL2Input]) -> Result<BatchWitness, TransitionError> {
        let mut l2: Vec<L2Tx> = Vec::with_capacity(txs.len());
        for t in txs {
            let pubkey = EddsaPublicKey::from_bytes(&t.pubkey)
                .ok_or(TransitionError::SignatureInvalid)?;
            let sig = EddsaSignature::from_bytes(&t.sig)
                .ok_or(TransitionError::SignatureInvalid)?;
            l2.push(L2Tx {
                from:   address_to_fr(&t.input.from),
                to:     address_to_fr(&t.input.to),
                amount: t.input.amount,
                fee:    t.input.fee,
                nonce:  t.input.nonce,
                pubkey,
                sig,
            });
        }

        let mut trial = self.tree.clone();
        let witness = apply_batch(&mut trial, &l2)?;
        self.tree = trial; // commit erst nach erfolgreichem Übergang
        Ok(witness)
    }

    /// Spielt dekodierte On-Chain-Calldata (Data Availability) OHNE Signatur-
    /// prüfung ab — für den Aggregator-Resync beim Start. Die Calldata stammt aus
    /// bereits gesettelten, bewiesenen Batches; der reine Zustandsübergang ist
    /// deterministisch aus `from/to/amount/fee/nonce` reproduzierbar.
    ///
    /// All-or-nothing: läuft auf einer Kopie, committet erst bei Erfolg.
    pub fn apply_calldata(&mut self, inputs: &[L2Input]) -> Result<(), TransitionError> {
        let txs: Vec<(Fr, Fr, u128, u128, u64)> = inputs
            .iter()
            .map(|t| (address_to_fr(&t.from), address_to_fr(&t.to), t.amount, t.fee, t.nonce))
            .collect();
        // Schneller Bulk-Replay (Merkle nur einmal am Ende) auf einer Kopie;
        // committet erst bei Erfolg.
        let mut trial = self.tree.clone();
        trial.apply_replay_fast(&txs)?;
        self.tree = trial;
        Ok(())
    }

    /// Serialisiert den L2-Zustand kompakt (NUR belegte Konten) für die
    /// Aggregator-Persistenz. Format (alles LE):
    ///   version(u32) | next_index(u64) | count(u64) |
    ///   count × [ index(u64) | address(20) | balance(u128) | nonce(u64) ]
    /// Der Merkle-Baum wird beim Laden aus den Blättern rekonstruiert.
    pub fn to_snapshot_bytes(&self) -> Vec<u8> {
        let (next_index, accounts) = self.tree.snapshot_accounts();
        let mut out = Vec::with_capacity(20 + accounts.len() * SNAPSHOT_REC);
        out.extend_from_slice(&L2_SNAPSHOT_VERSION.to_le_bytes());
        out.extend_from_slice(&next_index.to_le_bytes());
        out.extend_from_slice(&(accounts.len() as u64).to_le_bytes());
        for (index, acct) in accounts {
            out.extend_from_slice(&index.to_le_bytes());
            out.extend_from_slice(&fr_to_bytes32(acct.address)[..20]);
            out.extend_from_slice(&acct.balance.to_le_bytes());
            out.extend_from_slice(&acct.nonce.to_le_bytes());
        }
        out
    }

    /// Lädt einen Snapshot zurück. `None`, wenn Version/Layout nicht passt
    /// (Aufrufer fällt dann auf den Full-Replay aus der Calldata zurück).
    pub fn from_snapshot_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 20 {
            return None;
        }
        let ver = u32::from_le_bytes(bytes[0..4].try_into().ok()?);
        if ver != L2_SNAPSHOT_VERSION {
            return None;
        }
        let next_index = u64::from_le_bytes(bytes[4..12].try_into().ok()?);
        let count = u64::from_le_bytes(bytes[12..20].try_into().ok()?) as usize;
        if bytes.len() != 20 + count.checked_mul(SNAPSHOT_REC)? {
            return None;
        }
        let mut accounts = Vec::with_capacity(count);
        for i in 0..count {
            let o = 20 + i * SNAPSHOT_REC;
            let index = u64::from_le_bytes(bytes[o..o + 8].try_into().ok()?);
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&bytes[o + 8..o + 28]);
            let balance = u128::from_le_bytes(bytes[o + 28..o + 44].try_into().ok()?);
            let nonce = u64::from_le_bytes(bytes[o + 44..o + 52].try_into().ok()?);
            accounts.push((index, Account::new(address_to_fr(&addr), balance, nonce)));
        }
        Some(L2State { tree: AccountTree::restore(next_index, accounts) })
    }
}

impl Default for L2State {
    fn default() -> Self {
        Self::new()
    }
}

// ── Forced Inclusion: native Rejection-Zeugen ─────────────────────────────────
//
// Eine Forced-TX (on-chain via L1) muss vom Aggregator aufgenommen werden ODER
// per Zeuge nachweislich abgelehnt: ein Merkle-Pfad gegen den `pre_root` des
// Settlements zeigt, dass die TX am angegebenen `sender_index` nicht anwendbar
// ist. Der Node verifiziert den Zeugen NATIV (Poseidon + Pfad) — kein Circuit.

/// Zeugen-Daten einer Forced-Rejection (byte-level, `ark`-frei nach außen).
#[derive(Clone, Debug)]
pub struct RejectionWitness {
    /// Slot am Index ist leer (kein Konto registriert).
    pub leaf_vacant:  bool,
    pub leaf_address: [u8; 20],
    pub leaf_balance: u128,
    pub leaf_nonce:   u64,
    /// Geschwister-Hashes (LSB-first, `DEPTH` Einträge à 32 B).
    pub siblings:     Vec<[u8; 32]>,
}

impl L2State {
    /// Erzeugt den Rejection-Zeugen für `sender_index` gegen den AKTUELLEN Root
    /// (== `pre_root` des nächsten Batches). Aggregator-Seite.
    pub fn rejection_witness(&self, sender_index: u64) -> RejectionWitness {
        let path = self.tree.path(sender_index);
        let siblings = path.siblings.iter().map(|s| fr_to_bytes32(*s)).collect();
        match self.tree.account_at(sender_index) {
            Some(acct) => RejectionWitness {
                leaf_vacant:  false,
                leaf_address: fr_to_address20(acct.address),
                leaf_balance: acct.balance,
                leaf_nonce:   acct.nonce,
                siblings,
            },
            None => RejectionWitness {
                leaf_vacant:  true,
                leaf_address: [0u8; 20],
                leaf_balance: 0,
                leaf_nonce:   0,
                siblings,
            },
        }
    }

    /// Index des Kontos einer Adresse (None falls nicht registriert).
    pub fn index_of(&self, addr: &[u8; 20]) -> Option<u64> {
        self.tree.index_of(address_to_fr(addr))
    }
}

/// Rückabbildung `Fr` → 20-Byte-Adresse (Inverse von [`address_to_fr`];
/// nur für Werte < 2^160 wohldefiniert — genau die, die `address_to_fr` erzeugt).
pub fn fr_to_address20(f: Fr) -> [u8; 20] {
    use ark_ff::BigInteger;
    let le = f.into_bigint().to_bytes_le();
    let mut out = [0u8; 20];
    out.copy_from_slice(&le[..20]);
    out
}

/// Verifiziert einen Forced-Rejection-Zeugen NATIV gegen `pre_root`. Node-Seite.
///
/// `Ok(())` ⇔ der Zeuge belegt, dass die Forced-TX (`tx_*`) am `sender_index`
/// gegen den Zustand `pre_root` NICHT anwendbar ist. Gründe (einer genügt):
/// leerer Slot, fremde Leaf-Adresse (falscher Index), Nonce-Mismatch oder
/// unzureichendes Guthaben. Ist die TX in Wahrheit anwendbar, schlägt die
/// Verifikation fehl — ein Aggregator kann gültige TXs also NICHT abweisen.
#[allow(clippy::too_many_arguments)]
pub fn verify_forced_rejection(
    pre_root:     &[u8; 32],
    sender_index: u64,
    leaf_vacant:  bool,
    leaf_address: &[u8; 20],
    leaf_balance: u128,
    leaf_nonce:   u64,
    siblings:     &[[u8; 32]],
    tx_from:      &[u8; 20],
    tx_amount:    u128,
    tx_fee:       u128,
    tx_nonce:     u64,
) -> Result<(), String> {
    use crate::merkle::{root_from_path, MerklePath, DEPTH};

    if siblings.len() != DEPTH {
        return Err(format!("Pfadlänge {} ≠ Baumtiefe {}", siblings.len(), DEPTH));
    }
    if sender_index >= (1u64 << DEPTH) {
        return Err(format!("sender_index {} außerhalb des Baums", sender_index));
    }
    // Leaf rekonstruieren: leer ⇒ 0, sonst Poseidon(addr, balance, nonce).
    let leaf = if leaf_vacant {
        Fr::from(0u64)
    } else {
        Account::new(address_to_fr(leaf_address), leaf_balance, leaf_nonce).leaf_hash()
    };
    let path = MerklePath {
        index:    sender_index,
        siblings: siblings.iter().map(|b| Fr::from_le_bytes_mod_order(b)).collect(),
    };
    if fr_to_bytes32(root_from_path(leaf, &path)) != *pre_root {
        return Err("Merkle-Pfad hasht nicht zum pre_root".to_string());
    }

    // Nachweis der Nicht-Anwendbarkeit.
    if leaf_vacant {
        return Ok(()); // kein Konto an diesem Index
    }
    if leaf_address != tx_from {
        return Ok(()); // Index gehört einem anderen Konto (User-Fehler)
    }
    if leaf_nonce != tx_nonce {
        return Ok(()); // Nonce verbraucht oder noch nicht erreicht
    }
    let debit = tx_amount.checked_add(tx_fee)
        .ok_or_else(|| "amount+fee Überlauf".to_string())?;
    if leaf_balance < debit {
        return Ok(()); // unzureichendes Guthaben
    }
    Err("Forced-TX ist gegen pre_root anwendbar — Ablehnung unberechtigt".to_string())
}

// ── Kanonische Dev-/Testnet-Genesis-Allokation ────────────────────────────────
//
// Da ATLAS keine Bridge und kein Mint/Burn besitzt, ist die Genesis-Allokation
// der EINZIGE Förderpfad für L2-Konten. Node und Aggregator MÜSSEN exakt diese
// (deterministische, nach Adresse sortierte) Allokation verwenden, damit ihre
// Genesis-L2-State-Roots übereinstimmen und der erste SettlementBid anschließt.

/// Seed-Basis der vorab geförderten Dev-Konten — identisch zu den
/// `atlas-sender`-Keypairs (`EddsaKeypair::from_seed(GENESIS_SEED_BASE + i)`).
pub const GENESIS_SEED_BASE: u64 = 0xA71A_5000;

/// Anzahl vorab geförderter Dev-Konten (deckt den `atlas-sender`-Default von 50
/// Sendern plus Reserve ab).
pub const GENESIS_ACCOUNT_COUNT: u64 = 64;

/// Startguthaben je gefördertem Dev-Konto (ATOM).
pub const GENESIS_BALANCE_PER_ACCOUNT: u128 = 1_000_000_000_000;

/// JSON-DTO einer Allokationszeile: {"address":"<40 Hex>","balance":<u128>}.
#[derive(serde::Deserialize, serde::Serialize)]
struct AllocEntry { address: String, balance: u128 }

/// Parst eine Genesis-Allokation aus JSON. Validiert 20-Byte-Hex-Adressen,
/// lehnt Duplikate ab und sortiert deterministisch nach Adresse (reproduzierbare
/// Root, unabhängig von der Dateireihenfolge). EINZIGE erlaubte Parse-Routine —
/// Node und Aggregator MÜSSEN dieselbe Allokation erhalten.
pub fn parse_genesis_alloc_json(s: &str) -> anyhow::Result<Vec<GenesisAlloc>> {
    let entries: Vec<AllocEntry> = serde_json::from_str(s)
        .map_err(|e| anyhow::anyhow!("Genesis-Alloc-JSON ungültig: {}", e))?;
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(entries.len());
    for e in &entries {
        let raw = hex::decode(e.address.trim_start_matches("0x"))
            .map_err(|err| anyhow::anyhow!("Adresse '{}' kein Hex: {}", e.address, err))?;
        let address: [u8; 20] = raw.as_slice().try_into()
            .map_err(|_| anyhow::anyhow!("Adresse '{}' ist nicht 20 Byte", e.address))?;
        if !seen.insert(address) {
            anyhow::bail!("Doppelte Genesis-Adresse: {}", e.address);
        }
        out.push(GenesisAlloc { address, balance: e.balance });
    }
    out.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(out)
}

/// Serialisiert eine Allokation als hübsches JSON (für Tooling/Export).
pub fn genesis_alloc_to_json(allocs: &[GenesisAlloc]) -> String {
    let entries: Vec<AllocEntry> = allocs.iter().map(|a| AllocEntry {
        address: hex::encode(a.address), balance: a.balance,
    }).collect();
    serde_json::to_string_pretty(&entries).expect("alloc JSON serialisierbar")
}

/// Kanonische, nach Adresse sortierte Genesis-Allokation — EINZIGE Quelle der
/// Wahrheit für Node (treibt `GENESIS_L2_ROOT`) UND Aggregator. Eingebettet aus
/// `genesis/alloc.json`, sodass alle Binaries byte-identisch dieselbe Geldmenge
/// verankern.
///
/// MAINNET: `genesis/alloc.json` mit der echten Allokation ersetzen, dann
/// `cargo run -p atlas-zk --release --bin genesis_root` ausführen und die
/// ausgegebene `GENESIS_L2_ROOT`-Konstante in `atlas-core/src/block.rs`
/// einsetzen, danach Workspace neu bauen. Der Cross-Check-Test in atlas-node
/// erzwingt, dass Konstante und Datei übereinstimmen.
pub fn genesis_allocation() -> Vec<GenesisAlloc> {
    parse_genesis_alloc_json(include_str!("../genesis/alloc.json"))
        .expect("eingebettete genesis/alloc.json muss gültig sein")
}

/// Seed-basierte Dev-/Testnet-Allokation: `GENESIS_ACCOUNT_COUNT` deterministische
/// EdDSA-Konten (Seeds `GENESIS_SEED_BASE..`). Wird zum GENERIEREN der
/// `genesis/alloc.json` genutzt und stimmt mit den `atlas-sender`-Keypairs überein.
pub fn dev_genesis_allocation() -> Vec<GenesisAlloc> {
    use crate::eddsa::EddsaKeypair;
    let mut allocs: Vec<GenesisAlloc> = (0..GENESIS_ACCOUNT_COUNT)
        .map(|i| GenesisAlloc {
            address: EddsaKeypair::from_seed(GENESIS_SEED_BASE + i).public().address20(),
            balance: GENESIS_BALANCE_PER_ACCOUNT,
        })
        .collect();
    allocs.sort_by(|a, b| a.address.cmp(&b.address));
    allocs
}

/// Die kanonische L2-State-Root des geförderten Genesis-Zustands (32 Byte).
/// Muss in `atlas-core` als Konstante gespiegelt werden (Block::genesis).
pub fn genesis_l2_state_root() -> [u8; 32] {
    L2State::from_genesis(&genesis_allocation()).root_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eddsa::EddsaKeypair;

    fn kp(seed: u64) -> EddsaKeypair {
        EddsaKeypair::from_secret(ark_ed_on_bn254::Fr::from(seed))
    }

    /// Baut einen signierten Input (Adresse = `kp.address20()`, Nachricht =
    /// `Poseidon(from,to,amount,fee,nonce)`).
    fn signed(kp: &EddsaKeypair, to: [u8; 20], amount: u128, fee: u128, nonce: u64) -> SignedL2Input {
        let from = kp.public().address20();
        let m = crate::transition::tx_message(
            address_to_fr(&from), address_to_fr(&to), amount, fee, nonce);
        let sig = kp.sign(m);
        SignedL2Input {
            input: L2Input { from, to, amount, fee, nonce },
            pubkey: kp.public().to_bytes(),
            sig: sig.to_bytes(),
        }
    }

    #[test]
    fn empty_root_matches_helper() {
        let s = L2State::new();
        assert_eq!(s.root_bytes(), crate::empty_l2_state_root());
    }

    /// REPRODUKTION/GUARD (Incident 2026-06-27): Es gibt ZWEI Baum-Mutationspfade —
    /// `apply()`/`apply_batch` (vom Aggregator zum Beweisen + Bid-Bauen) und
    /// `apply_calldata()`/`apply_replay_fast` (vom Node in `apply_block` UND vom
    /// Aggregator-Follower/Resync). Beide MÜSSEN für denselben Transfer EXAKT
    /// dieselbe L2-Root liefern — besonders wenn der Transfer ein NEUES Empfänger-
    /// konto anlegt (Index-Zuweisung!). Sonst divergieren Node- und Aggregator-Root
    /// nach dem ersten echten Transfer (leere Heartbeats berühren keine Konten →
    /// nie getriggert) und jeder Folge-Bid fällt als `pre_root does not chain` raus.
    #[test]
    fn apply_paths_agree_on_transfer_to_new_account() {
        let alice_kp = kp(1);
        let alice    = alice_kp.public().address20();
        let bob      = [9u8; 20]; // existiert noch NICHT → wird neu angelegt

        // Gemeinsamer Ausgangszustand.
        let mut base = L2State::new();
        base.credit(&alice, 1_000_000);
        let snap = base.to_snapshot_bytes();

        // Pfad A: apply() / apply_batch (signiert, wie der Aggregator-Bid).
        let mut sa = L2State::from_snapshot_bytes(&snap).expect("snapshot A");
        let tx = signed(&alice_kp, bob, 1000, 10, 0);
        sa.apply(std::slice::from_ref(&tx)).expect("apply_batch ok");

        // Pfad B: apply_calldata() / apply_replay_fast (unsigniert, wie Node+Follower).
        let mut sb = L2State::from_snapshot_bytes(&snap).expect("snapshot B");
        sb.apply_calldata(std::slice::from_ref(&tx.input)).expect("apply_calldata ok");

        assert_eq!(
            sa.root_bytes(), sb.root_bytes(),
            "apply_batch und apply_replay_fast divergieren bei Transfer auf NEUES Konto \
             → Node↔Aggregator-Root-Desync (Incident 2026-06-27)"
        );
        assert_eq!(sa.balance(&bob), 1000);
        assert_eq!(sb.balance(&bob), 1000);
        assert_eq!(sa.balance(&alice), 1_000_000 - 1010);
    }

    #[test]
    fn credit_then_transfer() {
        let alice_kp = kp(1);
        let alice = alice_kp.public().address20();
        let bob   = [2u8; 20];
        let mut s = L2State::new();
        s.credit(&alice, 1_000_000);
        assert_eq!(s.balance(&alice), 1_000_000);

        let pre = s.root_bytes();
        let w = s.apply(&[signed(&alice_kp, bob, 1000, 10, 0)])
            .expect("gültiger Transfer");
        assert_eq!(w.total_fees, 10);
        assert_eq!(s.balance(&alice), 1_000_000 - 1010);
        assert_eq!(s.balance(&bob), 1000);
        assert_eq!(s.nonce(&alice), 1);
        // Wurzel hat sich verändert und entspricht dem post_root des Witness.
        assert_ne!(s.root_bytes(), pre);
        assert_eq!(s.root_bytes(), fr_to_bytes32(w.post_root));
    }

    #[test]
    fn failed_batch_leaves_state_unchanged() {
        let alice_kp = kp(1);
        let alice = alice_kp.public().address20();
        let bob   = [2u8; 20];
        let mut s = L2State::new();
        s.credit(&alice, 100);
        let before = s.root_bytes();
        // Überweisung > Guthaben ⇒ Fehler, Zustand unverändert.
        let r = s.apply(&[signed(&alice_kp, bob, 1000, 0, 0)]);
        assert!(r.is_err());
        assert_eq!(s.root_bytes(), before);
        assert_eq!(s.balance(&alice), 100);
    }

    /// KERN-Garantie für den Aggregator-Resync: das signatur-lose Calldata-Replay
    /// (`apply_calldata`) erzeugt bit-genau dieselbe L2-Root wie das signierte
    /// `apply` — inklusive des echten encode/decode-Calldata-Pfads (DA).
    #[test]
    fn replay_calldata_matches_signed_apply() {
        let a_kp = kp(1);
        let b_kp = kp(2);
        let a = a_kp.public().address20();
        let b = b_kp.public().address20();
        let c = [9u8; 20]; // neuer Empfänger (wird angelegt)

        // 1) Signiert anwenden.
        let mut signed_state = L2State::new();
        signed_state.credit(&a, 1_000_000);
        signed_state.credit(&b, 500_000);
        let batch = [
            signed(&a_kp, b, 1000, 10, 0),
            signed(&b_kp, c, 2000, 20, 0),
            signed(&a_kp, c,  500,  5, 1),
        ];
        signed_state.apply(&batch).expect("gültiger Batch");
        let root_signed = signed_state.root_bytes();

        // 2) Dieselbe Sequenz als reine Calldata über encode→decode→replay.
        let inputs: Vec<L2Input> = batch.iter().map(|s| s.input).collect();
        let decoded = decode_calldata(&encode_calldata(&inputs)).expect("decode");
        let mut replay_state = L2State::new();
        replay_state.credit(&a, 1_000_000);
        replay_state.credit(&b, 500_000);
        replay_state.apply_calldata(&decoded).expect("Replay");

        assert_eq!(
            replay_state.root_bytes(), root_signed,
            "Calldata-Replay muss bit-genau dieselbe L2-Root erzeugen wie signiertes apply"
        );
    }

    /// Persistenz-Garantie: Snapshot→Restore erhält Root, Salden, Nonces und
    /// bleibt voll weiter-anwendbar (Nonce-Kette intakt).
    #[test]
    fn snapshot_roundtrip_preserves_root_and_state() {
        let a_kp = kp(1);
        let b_kp = kp(2);
        let a = a_kp.public().address20();
        let b = b_kp.public().address20();

        let mut s = L2State::new();
        s.credit(&a, 1_000_000);
        s.credit(&b, 500_000);
        s.apply(&[
            signed(&a_kp, b, 1000, 10, 0),
            signed(&b_kp, [9u8; 20], 2000, 20, 0),
        ]).expect("Batch");
        let root = s.root_bytes();

        // Serialisieren → laden.
        let bytes = s.to_snapshot_bytes();
        let restored = L2State::from_snapshot_bytes(&bytes).expect("Snapshot ladbar");

        assert_eq!(restored.root_bytes(), root, "Restore muss dieselbe Root liefern");
        assert_eq!(restored.balance(&a), s.balance(&a));
        assert_eq!(restored.nonce(&a),   s.nonce(&a));
        assert_eq!(restored.balance(&b), s.balance(&b));

        // Nach Restore weiter anwendbar (Nonce-Kette intakt).
        let mut r2 = restored;
        r2.apply(&[signed(&a_kp, b, 500, 5, 1)]).expect("nach Restore weiter anwendbar");

        // Defekte/fremde Version → None (Fallback auf Full-Replay).
        assert!(L2State::from_snapshot_bytes(&[]).is_none());
        let mut bad = bytes.clone();
        bad[0] ^= 0xFF;
        assert!(L2State::from_snapshot_bytes(&bad).is_none());
    }

    #[test]
    fn calldata_roundtrip() {
        let txs = vec![
            L2Input { from: [1u8; 20], to: [2u8; 20], amount: 1234, fee: 7, nonce: 0 },
            L2Input { from: [2u8; 20], to: [3u8; 20], amount: 99,   fee: 1, nonce: 5 },
        ];
        let bytes = encode_calldata(&txs);
        assert_eq!(bytes.len(), 2 * CALLDATA_TX_SIZE);
        let back = decode_calldata(&bytes).expect("decode");
        assert_eq!(back.len(), 2);
        assert_eq!(back[0].amount, 1234);
        assert_eq!(back[1].nonce, 5);
        assert_eq!(back[0].from, [1u8; 20]);
        assert!(decode_calldata(&bytes[..bytes.len() - 1]).is_err());
    }

    /// Das aus Calldata berechnete Commitment MUSS bit-genau dem kanonischen
    /// Circuit-Commitment (über die gepaddeten Witness-Slots) entsprechen —
    /// sonst kann der Node die On-Chain-Daten nicht gegen den Beweis binden.
    #[test]
    fn calldata_commitment_matches_circuit() {
        let alice_kp = kp(1);
        let alice = alice_kp.public().address20();
        let bob   = [2u8; 20];
        let mut s = L2State::from_genesis(&[GenesisAlloc { address: alice, balance: 1_000_000 }]);
        let si = signed(&alice_kp, bob, 500, 3, 0);
        let inputs = vec![si.input];
        let bw = s.apply(&[si]).expect("apply");

        let batch_size = crate::L2_BATCH_SIZE;
        let from_calldata = batch_commitment_from_inputs(&inputs, batch_size);
        let canonical = fr_to_bytes32(
            crate::state_circuit::StateTransitionCircuit::from_witness(&bw, batch_size).batch_commitment
        );
        assert_eq!(from_calldata, canonical, "Calldata-Commitment != Circuit-Commitment");
    }

    #[test]
    fn genesis_alloc_deterministic() {
        let allocs = [
            GenesisAlloc { address: [1u8; 20], balance: 500 },
            GenesisAlloc { address: [2u8; 20], balance: 700 },
        ];
        let a = L2State::from_genesis(&allocs);
        let b = L2State::from_genesis(&allocs);
        assert_eq!(a.root_bytes(), b.root_bytes());
        assert_eq!(a.balance(&[1u8; 20]), 500);
    }

    /// Voller Aggregator-Krypto-Pfad (echter Groth16, ~Minuten in debug):
    /// Genesis-gefördertes Konto → `L2State.apply` → `prove_state` → `verify_state`.
    /// Bindet das byte-orientierte L2State-API an Prover & Verifier und prüft, dass
    /// die vom L2State gelieferten pre/post-Roots exakt die Public Inputs des
    /// Beweises sind. Manipulierte Public Inputs werden abgelehnt.
    ///
    /// Benötigt `keys/state_pk.bin` (nur auf dem Aggregator-Server):
    ///   cargo test -p atlas-zk --release l2_state_full_prove_verify_roundtrip -- --ignored --nocapture
    #[test]
    #[ignore]
    fn l2_state_full_prove_verify_roundtrip() {
        use crate::{ZkBatchProver, ZkBatchVerifier};

        let alice_kp = kp(1);
        let alice = alice_kp.public().address20();
        let bob   = [2u8; 20];

        // Genesis: Alice mit Startguthaben fördern.
        let mut state = L2State::from_genesis(&[GenesisAlloc { address: alice, balance: 1_000_000 }]);
        let pre_root = state.root_bytes();

        // Einen Batch (1 Transfer) anwenden → Witness + post_root.
        let witness = state.apply(&[signed(&alice_kp, bob, 1234, 7, 0)])
            .expect("gültiger Transfer");
        let post_root = state.root_bytes();
        let total_fees = witness.total_fees;
        assert_eq!(total_fees, 7);

        // Echten State-Transition-Beweis erzeugen.
        let pk_path = concat!(env!("CARGO_MANIFEST_DIR"), "/keys/state_pk.bin");
        let prover = ZkBatchProver::from_state_file(pk_path).expect("state_pk.bin laden");
        let (proof, proof_post_root, batch_commitment) =
            prover.prove_state(&witness).expect("prove_state");

        // Der Beweis-post_root muss exakt der L2State-Wurzel entsprechen.
        assert_eq!(proof_post_root, post_root, "post_root aus Beweis != L2State-Root");

        // Verifikation mit den On-Chain-ableitbaren Public Inputs.
        let verifier = ZkBatchVerifier::from_hardcoded_state_vk().expect("VK");
        verifier.verify_state(&proof, &pre_root, &post_root, total_fees, &batch_commitment)
            .expect("gültiger State-Beweis muss verifizieren");

        // Manipulationen müssen abgelehnt werden.
        let mut bad_post = post_root;
        bad_post[0] ^= 0x01;
        assert!(
            verifier.verify_state(&proof, &pre_root, &bad_post, total_fees, &batch_commitment).is_err(),
            "manipulierter post_root muss abgelehnt werden"
        );
        assert!(
            verifier.verify_state(&proof, &pre_root, &post_root, total_fees + 1, &batch_commitment).is_err(),
            "manipulierte total_fees müssen abgelehnt werden"
        );
    }
}
