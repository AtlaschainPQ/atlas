//! Batch-Erstellung aus gesammelten L2-Transaktionen

use atlas_core::hash::Hash;
use crate::l2_tx::L2Transaction;

/// Fertiger Batch — bereit zum Beweisen und Einreichen
#[derive(Debug)]
pub struct Batch {
    /// Merkle-Root aller TX-Hashes (= batch_id für den Verifier)
    pub batch_merkle: Hash,
    /// Alle L2-TXs in diesem Batch
    pub transactions: Vec<L2Transaction>,
    /// Summe aller Aggregator-Gebühren (ATOM)
    pub total_fees:   u128,
}

/// Sammelt L2-TXs und baut Batches
pub struct BatchBuilder {
    pending:  Vec<L2Transaction>,
    max_size: usize,
}

impl BatchBuilder {
    pub fn new(max_size: usize) -> Self {
        BatchBuilder {
            pending: Vec::new(),
            max_size,
        }
    }

    /// TX hinzufügen — gibt true zurück wenn Batch jetzt voll ist
    pub fn push(&mut self, tx: L2Transaction) -> bool {
        self.pending.push(tx);
        self.pending.len() >= self.max_size
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    #[allow(dead_code)] // Teil der BatchBuilder-API
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    /// Batch finalisieren und zurückgeben (pending wird geleert)
    pub fn take(&mut self) -> Option<Batch> {
        if self.pending.is_empty() {
            return None;
        }
        let txs: Vec<L2Transaction> = std::mem::take(&mut self.pending);
        let total_fees: u128 = txs.iter().map(|tx| tx.fee).sum();
        let batch_merkle = compute_batch_merkle(&txs);

        Some(Batch {
            batch_merkle,
            transactions: txs,
            total_fees,
        })
    }
}

/// Berechnet den Batch-Merkle-Root: double-SHA256 über alle TX-Hashes verkettet
pub fn compute_batch_merkle(txs: &[L2Transaction]) -> Hash {
    // Alle TX-Hashes hintereinander
    let mut data: Vec<u8> = Vec::with_capacity(txs.len() * 32);
    for tx in txs {
        data.extend_from_slice(tx.hash().as_bytes());
    }
    Hash::double_sha256(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::crypto::Address;
    use atlas_zk::eddsa::EddsaKeypair;
    use atlas_zk::l2_state::build_l2_eddsa;

    fn signed(kp: &EddsaKeypair, to: Address, amount: u128, fee: u128, nonce: u64) -> L2Transaction {
        let (from, pubkey, sig) = build_l2_eddsa(kp, &to.0, amount, fee, nonce);
        L2Transaction::from_parts(Address(from), to, amount, fee, nonce, pubkey, sig)
    }

    #[test]
    fn test_batch_merkle_deterministic() {
        let kp  = EddsaKeypair::from_seed(1);
        let to  = Address([9u8; 20]);
        let tx1 = signed(&kp, to, 1000, 10, 1);
        let tx2 = signed(&kp, to, 2000, 10, 2);

        let txs = vec![tx1.clone(), tx2.clone()];
        let m1  = compute_batch_merkle(&txs);
        let m2  = compute_batch_merkle(&txs);
        assert_eq!(m1, m2, "Merkle-Root muss deterministisch sein");
    }

    #[test]
    fn test_batch_builder_take() {
        let kp = EddsaKeypair::from_seed(2);
        let to = Address([9u8; 20]);
        let mut builder = BatchBuilder::new(3);

        builder.push(signed(&kp, to, 500,  10, 1));
        builder.push(signed(&kp, to, 1000, 20, 2));

        let batch = builder.take().unwrap();
        assert_eq!(batch.transactions.len(), 2);
        assert_eq!(batch.total_fees, 30);
        assert!(builder.is_empty());
    }
}
