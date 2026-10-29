//! PostgreSQL store: every block is one transaction appending its leaves,
//! events, rejections, nullifiers and root; rollback deletes above a height.
//! Tables are shared by deployments and keyed by deployment name.

use std::collections::{BTreeMap, HashSet};

use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use postgres::{Client, NoTls};

use sb_core::envelope::{Envelope, parse_envelope};
use sb_core::event::{AcceptedEvent, EventKind};
use sb_core::tree::NoteTree;
use sb_primitives::Fr;
use sb_primitives::encoding::{fr_from_bytes, fr_to_bytes};

use super::{StateStore, StoreError};
use crate::state::{BlockCheckpoint, Rejection, ReplayState};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sb_blocks (
    deployment text NOT NULL, height int NOT NULL, hash bytea NOT NULL,
    leaf_count_before bigint NOT NULL, events_before int NOT NULL, rejections_before int NOT NULL,
    nullifiers_added bytea[] NOT NULL, root bytea NOT NULL,
    PRIMARY KEY (deployment, height));
CREATE TABLE IF NOT EXISTS sb_leaves (
    deployment text NOT NULL, pos bigint NOT NULL, leaf bytea NOT NULL, height int NOT NULL,
    PRIMARY KEY (deployment, pos));
CREATE TABLE IF NOT EXISTS sb_events (
    deployment text NOT NULL, idx int NOT NULL, kind smallint NOT NULL, height int NOT NULL,
    tx_index int NOT NULL, txid bytea NOT NULL, raw bytea NOT NULL, h_body bytea NOT NULL,
    first_position bigint NOT NULL, leaves bytea[] NOT NULL, memo bytea,
    PRIMARY KEY (deployment, idx));
CREATE TABLE IF NOT EXISTS sb_nullifiers (
    deployment text NOT NULL, nf bytea NOT NULL, height int NOT NULL,
    PRIMARY KEY (deployment, nf));
CREATE INDEX IF NOT EXISTS sb_nullifiers_height ON sb_nullifiers (deployment, height);
CREATE TABLE IF NOT EXISTS sb_rejections (
    deployment text NOT NULL, idx int NOT NULL, height int NOT NULL, tx_index int NOT NULL,
    txid bytea NOT NULL, reason text NOT NULL,
    PRIMARY KEY (deployment, idx));
";

pub struct PgStore {
    client: Client,
    deployment: String,
}

fn fr_bytes(f: &Fr) -> Vec<u8> {
    fr_to_bytes(f).to_vec()
}

fn fr_of(b: &[u8]) -> Result<Fr, StoreError> {
    fr_from_bytes(b).map_err(|e| StoreError::Corrupt(e.to_string()))
}

fn arr32(b: &[u8], what: &str) -> Result<[u8; 32], StoreError> {
    b.try_into()
        .map_err(|_| StoreError::Corrupt(format!("{what}: expected 32 bytes")))
}

impl PgStore {
    /// `conn` is a libpq-style string or URL, e.g.
    /// `host=/var/run/postgresql dbname=shielded_bitcoin` (peer auth) or
    /// `postgresql://user:pass@127.0.0.1/shielded_bitcoin`.
    pub fn connect(conn: &str, deployment: &str) -> Result<Self, StoreError> {
        let mut client = Client::connect(conn, NoTls)?;
        client.batch_execute(SCHEMA)?;
        Ok(PgStore {
            client,
            deployment: deployment.to_string(),
        })
    }
}

impl StateStore for PgStore {
    fn load(&mut self) -> Result<ReplayState, StoreError> {
        let d = &self.deployment;
        let mut leaves = Vec::new();
        for row in self.client.query(
            "SELECT leaf FROM sb_leaves WHERE deployment = $1 ORDER BY pos",
            &[d],
        )? {
            leaves.push(fr_of(row.get::<_, &[u8]>(0))?);
        }
        let mut nullifiers = HashSet::new();
        for row in self
            .client
            .query("SELECT nf FROM sb_nullifiers WHERE deployment = $1", &[d])?
        {
            nullifiers.insert(fr_of(row.get::<_, &[u8]>(0))?);
        }
        let mut roots = BTreeMap::new();
        let mut blocks = Vec::new();
        for row in self.client.query(
            "SELECT height, hash, leaf_count_before, events_before, rejections_before, nullifiers_added, root \
             FROM sb_blocks WHERE deployment = $1 ORDER BY height",
            &[d],
        )? {
            let height = row.get::<_, i32>(0) as u32;
            let hash = BlockHash::from_byte_array(arr32(row.get::<_, &[u8]>(1), "block hash")?);
            let added: Vec<Vec<u8>> = row.get(5);
            blocks.push(BlockCheckpoint {
                height,
                hash,
                leaf_count_before: row.get::<_, i64>(2) as u64,
                events_before: row.get::<_, i32>(3) as usize,
                rejections_before: row.get::<_, i32>(4) as usize,
                nullifiers_added: added.iter().map(|b| fr_of(b)).collect::<Result<_, _>>()?,
            });
            roots.insert(height, fr_of(row.get::<_, &[u8]>(6))?);
        }
        let mut events = Vec::new();
        for row in self.client.query(
            "SELECT height, tx_index, txid, raw, h_body, first_position, leaves, memo \
             FROM sb_events WHERE deployment = $1 ORDER BY idx",
            &[d],
        )? {
            let height = row.get::<_, i32>(0) as u32;
            let tx_index = row.get::<_, i32>(1) as u32;
            let txid = arr32(row.get::<_, &[u8]>(2), "txid")?;
            let raw: Vec<u8> = row.get(3);
            let h_body = fr_of(row.get::<_, &[u8]>(4))?;
            let first_position = row.get::<_, i64>(5) as u64;
            let leaf_bytes: Vec<Vec<u8>> = row.get(6);
            let leaves: Vec<Fr> = leaf_bytes
                .iter()
                .map(|b| fr_of(b))
                .collect::<Result<_, _>>()?;
            let memo: Option<Vec<u8>> = row.get(7);
            let mut ev =
                match parse_envelope(&raw).map_err(|e| StoreError::Corrupt(e.to_string()))? {
                    Envelope::Transfer(t) => AcceptedEvent::from_transfer(
                        height,
                        tx_index,
                        txid,
                        &t,
                        h_body,
                        first_position,
                        leaves,
                    ),
                    Envelope::Swap(sw) => AcceptedEvent::from_swap(
                        height,
                        tx_index,
                        txid,
                        &sw,
                        h_body,
                        first_position,
                        leaves,
                    ),
                    Envelope::Mint(m) => {
                        let derived = m
                            .derive()
                            .ok_or_else(|| StoreError::Corrupt("mint diversifier".into()))?;
                        let leaf = *leaves
                            .first()
                            .ok_or_else(|| StoreError::Corrupt("mint leaf".into()))?;
                        AcceptedEvent::from_mint(
                            height,
                            tx_index,
                            txid,
                            &m,
                            h_body,
                            derived,
                            first_position,
                            leaf,
                        )
                    }
                };
            ev.memo = memo;
            debug_assert!(matches!(
                ev.kind,
                EventKind::Transfer | EventKind::Mint | EventKind::Swap
            ));
            events.push(ev);
        }
        let mut rejections = Vec::new();
        for row in self.client.query(
            "SELECT height, tx_index, txid, reason FROM sb_rejections WHERE deployment = $1 ORDER BY idx",
            &[d],
        )? {
            rejections.push(Rejection {
                height: row.get::<_, i32>(0) as u32,
                tx_index: row.get::<_, i32>(1) as u32,
                txid: arr32(row.get::<_, &[u8]>(2), "txid")?,
                reason: row.get(3),
            });
        }
        let mut state = ReplayState {
            tree: NoteTree::from_leaves(&leaves),
            nullifiers,
            roots,
            blocks,
            events,
            rejections,
            nullifier_tree: Default::default(),
            root_tree: Default::default(),
        };
        state.rebuild_commitments();
        Ok(state)
    }

    fn commit_block(&mut self, state: &ReplayState, index: usize) -> Result<(), StoreError> {
        let cp = &state.blocks[index];
        let leaf_end = state
            .blocks
            .get(index + 1)
            .map(|n| n.leaf_count_before)
            .unwrap_or(state.tree.size());
        let events_end = state
            .blocks
            .get(index + 1)
            .map(|n| n.events_before)
            .unwrap_or(state.events.len());
        let rejections_end = state
            .blocks
            .get(index + 1)
            .map(|n| n.rejections_before)
            .unwrap_or(state.rejections.len());
        let root = state
            .roots
            .get(&cp.height)
            .ok_or_else(|| StoreError::Corrupt(format!("no root for {}", cp.height)))?;
        let d = self.deployment.clone();
        let mut tx = self.client.transaction()?;
        tx.execute(
            "INSERT INTO sb_blocks (deployment, height, hash, leaf_count_before, events_before, rejections_before, nullifiers_added, root) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            &[
                &d,
                &(cp.height as i32),
                &cp.hash.to_byte_array().as_slice(),
                &(cp.leaf_count_before as i64),
                &(cp.events_before as i32),
                &(cp.rejections_before as i32),
                &cp.nullifiers_added.iter().map(fr_bytes).collect::<Vec<_>>(),
                &fr_bytes(root).as_slice(),
            ],
        )?;
        for pos in cp.leaf_count_before..leaf_end {
            tx.execute(
                "INSERT INTO sb_leaves (deployment, pos, leaf, height) VALUES ($1, $2, $3, $4)",
                &[
                    &d,
                    &(pos as i64),
                    &fr_bytes(&state.tree.leaves()[pos as usize]).as_slice(),
                    &(cp.height as i32),
                ],
            )?;
        }
        for (idx, ev) in state
            .events
            .iter()
            .enumerate()
            .take(events_end)
            .skip(cp.events_before)
        {
            tx.execute(
                "INSERT INTO sb_events (deployment, idx, kind, height, tx_index, txid, raw, h_body, first_position, leaves, memo) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
                &[
                    &d,
                    &(idx as i32),
                    &(match ev.kind {
                        EventKind::Transfer => 1i16,
                        EventKind::Mint => 2i16,
                        EventKind::Swap => 3i16,
                    }),
                    &(ev.height as i32),
                    &(ev.tx_index as i32),
                    &ev.txid.as_slice(),
                    &ev.raw,
                    &fr_bytes(&ev.h_body).as_slice(),
                    &(ev.first_position as i64),
                    &ev.leaves.iter().map(fr_bytes).collect::<Vec<_>>(),
                    &ev.memo,
                ],
            )?;
        }
        for nf in &cp.nullifiers_added {
            tx.execute(
                "INSERT INTO sb_nullifiers (deployment, nf, height) VALUES ($1, $2, $3)",
                &[&d, &fr_bytes(nf).as_slice(), &(cp.height as i32)],
            )?;
        }
        for (idx, r) in state
            .rejections
            .iter()
            .enumerate()
            .take(rejections_end)
            .skip(cp.rejections_before)
        {
            tx.execute(
                "INSERT INTO sb_rejections (deployment, idx, height, tx_index, txid, reason) VALUES ($1, $2, $3, $4, $5, $6)",
                &[&d, &(idx as i32), &(r.height as i32), &(r.tx_index as i32), &r.txid.as_slice(), &r.reason],
            )?;
        }
        tx.commit()?;
        Ok(())
    }

    fn rollback_to(&mut self, _state: &ReplayState, height: u32) -> Result<(), StoreError> {
        let d = self.deployment.clone();
        let h = height as i32;
        let mut tx = self.client.transaction()?;
        tx.execute(
            "DELETE FROM sb_leaves WHERE deployment = $1 AND height > $2",
            &[&d, &h],
        )?;
        tx.execute(
            "DELETE FROM sb_events WHERE deployment = $1 AND height > $2",
            &[&d, &h],
        )?;
        tx.execute(
            "DELETE FROM sb_nullifiers WHERE deployment = $1 AND height > $2",
            &[&d, &h],
        )?;
        tx.execute(
            "DELETE FROM sb_rejections WHERE deployment = $1 AND height > $2",
            &[&d, &h],
        )?;
        tx.execute(
            "DELETE FROM sb_blocks WHERE deployment = $1 AND height > $2",
            &[&d, &h],
        )?;
        tx.commit()?;
        Ok(())
    }

    fn flush(&mut self, _state: &ReplayState) -> Result<(), StoreError> {
        Ok(())
    }
}
