//! What the structure-aware targets share: a grammar of chains for either
//! indexer — blocks of carrier transactions around one valid transfer and
//! one valid mint prepared once, reorganisations, syncs — and the way a
//! grammar is played against a mock chain. The targets supply the family:
//! how a mint and a transfer are made, and the indexer that replays them.

use arbitrary::Arbitrary;

/// One carrier transaction, by kind.
#[derive(Arbitrary, Debug, Clone)]
pub enum Tx {
    /// A valid mint of `value` to one of the harness's addresses, the
    /// carrier paying the vault exactly.
    Mint { to: u8, value: u64 },
    /// A mint whose carrier pays the vault `paid` instead of its value.
    MintPaid { to: u8, value: u64, paid: u64 },
    /// The prepared valid transfer (valid once, within its anchor window).
    Transfer,
    /// The prepared transfer with one byte changed.
    TransferFlipped { at: u16, xor: u8 },
    /// The prepared mint's envelope with one byte changed, the vault paid.
    MintFlipped { at: u16, xor: u8 },
    /// A candidate payload of arbitrary bytes behind the family's prefix.
    Raw(Vec<u8>),
    /// A payload without the prefix (someone else's OP_RETURN).
    Foreign(Vec<u8>),
    /// The prepared transfer carried twice in one transaction.
    TwoCarriers,
    /// The prepared transfer with a memo beside it (the memo magic, then
    /// these bytes).
    WithMemo(Vec<u8>),
    /// The prepared transfer with a second `OP_RETURN` of arbitrary bytes
    /// beside it (neither a memo nor an envelope, unless the bytes say so).
    SecondOpReturn(Vec<u8>),
}

#[derive(Arbitrary, Debug, Clone)]
pub enum Op {
    /// A block of up to a few transactions, then a sync.
    Block(Vec<Tx>),
    /// Drop the last `depth` blocks (at most to the activation), push a
    /// block of the given transactions in their place, then sync.
    Reorg { depth: u8, txs: Vec<Tx> },
    /// A sync with nothing new.
    Sync,
}

/// A chain to play: the operations, bounded so one input stays cheap.
#[derive(Arbitrary, Debug)]
pub struct Script {
    pub ops: Vec<Op>,
}

impl Script {
    /// At most this many operations and transactions a block are played.
    pub const MAX_OPS: usize = 12;
    pub const MAX_TXS: usize = 4;
}

/// Flip one byte of `bytes` at `at` (modulo the length).
pub fn flipped(bytes: &[u8], at: u16, xor: u8) -> Vec<u8> {
    let mut v = bytes.to_vec();
    if !v.is_empty() {
        let i = at as usize % v.len();
        v[i] ^= xor | 1; // never the identity
    }
    v
}
