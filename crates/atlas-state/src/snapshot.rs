//! State-Snapshots für Reorg-Unterstützung und Rolling Pruning

use std::collections::HashMap;
use atlas_core::block::BlockHeight;
use atlas_core::hash::Hash;
use atlas_core::amount::Amount;
use atlas_core::transaction::OutPoint;
use crate::utxo::Utxo;

/// Vollständiger Snapshot des Chain-Zustands vor Anwendung eines Blocks.
/// Ermöglicht Rollback auf beliebige Tiefe innerhalb des Snapshot-Fensters.
pub struct StateSnapshot {
    /// Höhe des Blocks der diesen Snapshot ausgelöst hat
    pub height:          BlockHeight,
    /// Hash dieses Blocks
    pub block_hash:      Hash,
    /// UTXO-Set NACH diesem Block (= Zustand vor dem nächsten Block)
    pub utxos:           HashMap<OutPoint, Utxo>,
    // Chain-State-Felder für korrekten Rollback
    pub total_supply:    Amount,
    pub total_txs:       u64,
    pub total_fees:      Amount,
    pub avg_fees:        Amount,
    pub security_delay:  u32,
    pub current_bits:    u32,
    /// L2-State-Root NACH diesem Block (für Reorg-Rollback der L2-Kette)
    pub l2_state_root:   Hash,
    /// Forced-Inclusion-Queue NACH diesem Block (für Reorg-Rollback)
    pub forced_queue:    Vec<atlas_core::transaction::ForcedQueueEntry>,
}

impl StateSnapshot {
    pub fn utxo_count(&self) -> usize {
        self.utxos.len()
    }
}

/// Verwaltet mehrere Snapshots für Reorganisationen
pub struct SnapshotManager {
    snapshots: std::collections::VecDeque<StateSnapshot>,
    max_depth: usize,
}

impl SnapshotManager {
    pub fn new(max_reorg_depth: usize) -> Self {
        SnapshotManager {
            snapshots: std::collections::VecDeque::new(),
            max_depth: max_reorg_depth,
        }
    }

    pub fn push(&mut self, snapshot: StateSnapshot) {
        self.snapshots.push_back(snapshot);
        if self.snapshots.len() > self.max_depth {
            self.snapshots.pop_front();
        }
    }

    /// Snapshot bei gegebener Höhe (nach diesem Block = vor dem nächsten)
    pub fn get_at_height(&self, height: BlockHeight) -> Option<&StateSnapshot> {
        self.snapshots.iter().find(|s| s.height == height)
    }

    pub fn latest(&self) -> Option<&StateSnapshot> {
        self.snapshots.back()
    }

    pub fn len(&self) -> usize {
        self.snapshots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.snapshots.is_empty()
    }

    /// Entfernt alle Snapshots die nach `count` eingefügt wurden (für Reorg-Rollback)
    pub fn truncate(&mut self, count: usize) {
        while self.snapshots.len() > count {
            self.snapshots.pop_back();
        }
    }
}
