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

/// How one output of a scanned event is made (the wallet targets).
#[derive(Arbitrary, Debug, Clone)]
pub enum NoteSrc {
    /// Arbitrary ephemeral-key and ciphertext bytes: no key of ours opens them.
    Random {
        pk_eph: [u8; 32],
        c0: [u8; 32],
        c1: [u8; 32],
        tag: [u8; 32],
    },
    /// A note of these parts encrypted honestly to our address `to`.
    ToUs { to: u8, value: u64, rseed: [u8; 32] },
    /// Honestly encrypted to us, then one byte of the ciphertext flipped.
    ToUsFlipped {
        to: u8,
        value: u64,
        rseed: [u8; 32],
        at: u8,
        xor: u8,
    },
    /// Our diversifier in the plaintext, but encrypted to a stranger's key
    /// for it.
    OurDiversifierForeignKey { to: u8, value: u64, rseed: [u8; 32] },
    /// Encrypted to a stranger's address.
    Stranger { value: u64, rseed: [u8; 32] },
}

/// The recovery field of a scanned event.
#[derive(Arbitrary, Debug, Clone)]
pub enum Recovery {
    None,
    /// Arbitrary bytes, padded or cut to the field's length.
    Random(Vec<u8>),
    /// Made honestly from the outputs' ephemeral secrets with our outgoing
    /// key (when the event has two outputs the harness made).
    Honest,
    /// Honest, then one byte flipped.
    HonestFlipped {
        at: u8,
        xor: u8,
    },
}

/// One accepted event as the wallet sees it, shaped by the fuzzer.
#[derive(Arbitrary, Debug, Clone)]
pub struct EventSpec {
    pub mint: bool,
    pub outputs: Vec<NoteSrc>,
    pub recovery: Recovery,
    /// Bit `j`: the leaf of output `j` is computed honestly over it; the
    /// other leaves are arbitrary.
    pub honest_leaves: u8,
    pub leaf_salt: [u8; 32],
    pub h_body: [u8; 32],
    pub first_position: u64,
    pub height: u32,
    pub txid: [u8; 32],
    pub aux: Vec<[u8; 32]>,
    pub nullifiers: Vec<[u8; 32]>,
}

/// A wallet's history: events, and where to cut it for the incremental scan.
#[derive(Arbitrary, Debug, Clone)]
pub struct WalletScript {
    pub events: Vec<EventSpec>,
    pub split: u8,
}

pub const MAX_EVENTS: usize = 6;
pub const MAX_OUTPUTS: usize = 4;
/// Values stay under the supply (the circuit binds a note's value; a forged
/// one is outside the model, and the wallet sums what it finds).
pub const MAX_VALUE: u64 = 1 << 51;
