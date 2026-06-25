//! L2-Account-Modell und der zustandstragende Account-Baum.
//!
//! Ein Konto ist `{ address, balance, nonce }`. Das Merkle-Blatt eines Kontos ist
//!   leaf = Poseidon(address, balance, nonce)
//! — dadurch bindet die Wurzel Adresse **und** Index (der Index ist die Position
//! im Baum, die Adresse steht im Blatt; der Circuit erzwingt beides gemeinsam).
//!
//! Adressen werden auf der ZK-Ebene als `Fr` geführt (der Aufrufer bildet seine
//! 20-Byte-Adresse via `from_le_bytes_mod_order` injektiv ab). So bleibt
//! `atlas-zk` von `atlas-core` entkoppelt.

use ark_bn254::Fr;
use std::collections::HashMap;

use crate::merkle::{MerklePath, MerkleTree};
use crate::poseidon::hash_many;

/// Ein L2-Konto.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Account {
    pub address: Fr,
    pub balance: u128,
    pub nonce:   u64,
}

impl Account {
    pub fn new(address: Fr, balance: u128, nonce: u64) -> Self {
        Account { address, balance, nonce }
    }

    /// Blatt-Hash dieses Kontos: Poseidon(address, balance, nonce).
    pub fn leaf_hash(&self) -> Fr {
        hash_many(&[self.address, Fr::from(self.balance), Fr::from(self.nonce)])
    }
}

/// Belegter Account-Baum: Merkle-Baum + Adress→Index-Registry.
///
/// Index 0 bleibt reserviert (sentinel „kein Konto"), damit ein nicht belegtes
/// Blatt (leerer Hash 0) eindeutig von jedem echten Konto unterscheidbar ist.
#[derive(Clone)]
pub struct AccountTree {
    tree:       MerkleTree,
    by_address: HashMap<[u8; 32], u64>, // address-Fr (LE-Bytes) → Blattindex
    accounts:   HashMap<u64, Account>,  // Index → Konto
    next_index: u64,
}

fn addr_key(address: Fr) -> [u8; 32] {
    crate::proof::fr_to_bytes32(address)
}

impl AccountTree {
    pub fn new() -> Self {
        AccountTree {
            tree:       MerkleTree::new(),
            by_address: HashMap::new(),
            accounts:   HashMap::new(),
            next_index: 1, // 0 reserviert
        }
    }

    /// Aktuelle State-Wurzel.
    pub fn root(&self) -> Fr {
        self.tree.root()
    }

    /// Blattindex einer Adresse, falls registriert.
    pub fn index_of(&self, address: Fr) -> Option<u64> {
        self.by_address.get(&addr_key(address)).copied()
    }

    /// Konto an einem Index (None = unbelegt).
    pub fn account_at(&self, index: u64) -> Option<Account> {
        self.accounts.get(&index).copied()
    }

    /// Konto per Adresse.
    pub fn account_of(&self, address: Fr) -> Option<Account> {
        self.index_of(address).and_then(|i| self.account_at(i))
    }

    /// Authentifizierungspfad für einen Index.
    pub fn path(&self, index: u64) -> MerklePath {
        self.tree.path(index)
    }

    pub fn leaf_at(&self, index: u64) -> Fr {
        self.tree.leaf(index)
    }

    /// Registriert ein neues Konto und gibt seinen Index zurück.
    /// Panikt, wenn die Adresse bereits existiert (Aufrufer muss `index_of` prüfen).
    pub fn register(&mut self, account: Account) -> u64 {
        let key = addr_key(account.address);
        assert!(!self.by_address.contains_key(&key), "Adresse bereits registriert");
        let index = self.next_index;
        self.next_index += 1;
        self.by_address.insert(key, index);
        self.write(index, account);
        index
    }

    /// Stellt sicher, dass ein Konto für `address` existiert (legt es bei Bedarf
    /// mit Saldo/Nonce 0 an) und gibt seinen Index zurück.
    pub fn ensure(&mut self, address: Fr) -> u64 {
        if let Some(i) = self.index_of(address) {
            i
        } else {
            self.register(Account::new(address, 0, 0))
        }
    }

    /// Überschreibt das Konto an `index` und aktualisiert das Merkle-Blatt.
    pub fn write(&mut self, index: u64, account: Account) {
        self.tree.set_leaf(index, account.leaf_hash());
        self.accounts.insert(index, account);
    }

    /// Exportiert den Minimal-Zustand `(next_index, [(index, Konto)])` für
    /// Persistenz — nach Index sortiert (deterministisch). Enthält NUR die
    /// belegten Konten, NICHT die Merkle-Knoten; der Baum wird beim Laden aus
    /// den Blättern rekonstruiert (siehe `restore`).
    pub fn snapshot_accounts(&self) -> (u64, Vec<(u64, Account)>) {
        let mut v: Vec<(u64, Account)> =
            self.accounts.iter().map(|(i, a)| (*i, *a)).collect();
        v.sort_by_key(|(i, _)| *i);
        (self.next_index, v)
    }

    /// Schneller Bulk-Replay aus Calldata-Feldern `(from,to,amount,fee,nonce)`:
    /// aktualisiert je TX NUR die Konten-Map (keine Merkle-Hashing pro TX) und
    /// baut den Merkle-Baum EINMAL am Ende aus den finalen Konten neu auf.
    ///
    /// Die Ergebnis-Root ist identisch zum tx-weisen `replay_batch` — die Root
    /// hängt nur vom End-Zustand + den Indizes ab, und die Index-Vergabe
    /// (Empfänger = `next_index` bei Erstauftritt) ist reihenfolge-deterministisch.
    /// Kosten: O(TXs) Map-Ops + O(Konten) Hashing statt O(TXs × Tiefe) Hashing —
    /// macht selbst einen Full-Replay über die ganze Historie zu Sekunden.
    pub fn apply_replay_fast(
        &mut self,
        txs: &[(Fr, Fr, u128, u128, u64)],
    ) -> Result<(), crate::transition::TransitionError> {
        use crate::transition::TransitionError;
        for &(from, to, amount, fee, nonce) in txs {
            if from == to {
                return Err(TransitionError::SelfTransfer);
            }
            let si = *self.by_address.get(&addr_key(from)).ok_or(TransitionError::UnknownSender)?;
            let sender = *self.accounts.get(&si).expect("Index ohne Konto");
            let debit = amount.checked_add(fee).ok_or(TransitionError::Overflow)?;
            if sender.balance < debit {
                return Err(TransitionError::InsufficientBalance { needed: debit, have: sender.balance });
            }
            if sender.nonce != nonce {
                return Err(TransitionError::BadNonce { expected: sender.nonce, got: nonce });
            }
            self.accounts.insert(si, Account::new(from, sender.balance - debit, sender.nonce + 1));

            // Empfänger laden / bei Erstauftritt anlegen — NUR Map, kein Merkle.
            let ri = match self.by_address.get(&addr_key(to)).copied() {
                Some(i) => i,
                None => {
                    let i = self.next_index;
                    self.next_index += 1;
                    self.by_address.insert(addr_key(to), i);
                    self.accounts.insert(i, Account::new(to, 0, 0));
                    i
                }
            };
            let recv = *self.accounts.get(&ri).expect("Empfänger-Index ohne Konto");
            let new_bal = recv.balance.checked_add(amount).ok_or(TransitionError::Overflow)?;
            self.accounts.insert(ri, Account::new(to, new_bal, recv.nonce));
        }
        // Merkle-Baum EINMALIG aus den finalen Konten neu aufbauen.
        self.tree = MerkleTree::new();
        for (index, acct) in self.accounts.iter() {
            self.tree.set_leaf(*index, acct.leaf_hash());
        }
        Ok(())
    }

    /// Baut den Baum aus dem Minimal-Zustand neu auf. Re-hasht NUR die wenigen
    /// belegten Blätter (O(Konten), nicht O(TX-Historie)) — daher schnell,
    /// während ein Calldata-Replay alle je angewandten TXs neu rechnet.
    pub fn restore(next_index: u64, accounts: Vec<(u64, Account)>) -> Self {
        let mut t = AccountTree {
            tree:       MerkleTree::new(),
            by_address: HashMap::new(),
            accounts:   HashMap::new(),
            next_index,
        };
        for (index, account) in accounts {
            t.by_address.insert(addr_key(account.address), index);
            t.tree.set_leaf(index, account.leaf_hash());
            t.accounts.insert(index, account);
        }
        t
    }
}

impl Default for AccountTree {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::root_from_path;
    use ark_ff::Zero;

    #[test]
    fn empty_account_leaf_distinct_from_unoccupied() {
        // Ein echtes Null-Konto (addr=0,bal=0,nonce=0) hasht NICHT auf 0,
        // ist also vom leeren Blatt (0) unterscheidbar.
        let zero_acct = Account::new(Fr::zero(), 0, 0);
        assert_ne!(zero_acct.leaf_hash(), Fr::zero());
    }

    #[test]
    fn register_and_lookup() {
        let mut t = AccountTree::new();
        let addr = Fr::from(0xABCDu64);
        let idx = t.register(Account::new(addr, 1000, 0));
        assert_eq!(t.index_of(addr), Some(idx));
        assert_eq!(t.account_at(idx).unwrap().balance, 1000);

        // Pfad rekonstruiert die Wurzel.
        let path = t.path(idx);
        let leaf = t.account_at(idx).unwrap().leaf_hash();
        assert_eq!(root_from_path(leaf, &path), t.root());
    }

    #[test]
    fn write_updates_root_and_path() {
        let mut t = AccountTree::new();
        let addr = Fr::from(7u64);
        let idx = t.register(Account::new(addr, 500, 0));
        let r0 = t.root();
        t.write(idx, Account::new(addr, 400, 1));
        assert_ne!(t.root(), r0);

        let path = t.path(idx);
        let leaf = Account::new(addr, 400, 1).leaf_hash();
        assert_eq!(root_from_path(leaf, &path), t.root());
    }

    #[test]
    fn ensure_is_idempotent() {
        let mut t = AccountTree::new();
        let addr = Fr::from(99u64);
        let i1 = t.ensure(addr);
        let i2 = t.ensure(addr);
        assert_eq!(i1, i2);
    }

    /// Der schnelle Bulk-Replay (`apply_replay_fast`, Merkle nur am Ende) muss
    /// bit-genau dieselbe Root liefern wie der tx-weise `replay_batch`.
    #[test]
    fn fast_replay_matches_per_tx_replay() {
        let build = || {
            let mut t = AccountTree::new();
            t.register(Account::new(Fr::from(1u64), 1_000_000, 0));
            t.register(Account::new(Fr::from(2u64), 1_000_000, 0));
            t
        };
        // inkl. neuem Empfänger (9) + Folge-Nonce.
        let txs = [
            (Fr::from(1u64), Fr::from(9u64), 100u128, 5u128, 0u64),
            (Fr::from(2u64), Fr::from(9u64), 200, 5, 0),
            (Fr::from(1u64), Fr::from(2u64),  50, 5, 1),
        ];
        let mut a = build();
        crate::transition::replay_batch(&mut a, &txs).expect("per-tx replay");
        let mut b = build();
        b.apply_replay_fast(&txs).expect("fast replay");
        assert_eq!(a.root(), b.root(), "fast == per-tx Replay");
    }
}
