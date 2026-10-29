//! Transfer construction (paper §13.1, Appendix C; profile §7, §8).

use ark_ff::UniformRand;
use rand::{CryptoRng, RngCore};

use sb_circuit::{
    InputWitness, OutputWitness, SwapInputWitness, SwapParams, SwapStatement, SwapWitness,
    TransferParams, TransferStatement, TransferWitness,
};
use sb_core::address::PaymentAddress;
use sb_core::envelope::{N_IN, SwapBody, SwapEnvelope, TransferBody, TransferEnvelope};
use sb_core::keys::WalletKeys;
use sb_core::lock::{LockOpening, Secret};
use sb_core::note::{
    NotePlaintext, encrypt_note, note_leaf, note_leaf_aux, nullifier, nullifier_locked,
};
use sb_core::recovery::{N_OUT, RecoveryEntry, binding_digest, encrypt_recovery};
use sb_core::tree::NoteTree;
use sb_primitives::Fr;
use sb_primitives::JubjubAffine;

/// A note the wallet can spend: plaintext plus the creation data needed to
/// rebuild its leaf (paper §C.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpendableNote {
    pub note: NotePlaintext,
    pub h_body_create: Fr,
    pub output_index: u64,
    pub pos: u64,
}

impl SpendableNote {
    /// Rebuild the leaf from the stored plaintext and creation fields (§C.4).
    pub fn leaf(&self, const_salt: &Fr, pk_d: &sb_primitives::JubjubAffine) -> Option<Fr> {
        let (pk_eph, ct) = encrypt_note(&self.note, pk_d)?;
        Some(note_leaf(
            const_salt,
            &self.h_body_create,
            self.output_index,
            &pk_eph,
            &ct,
        ))
    }

    /// The leaf with an explicit slot (`docs/SWAP.md` §3).
    pub fn leaf_aux(
        &self,
        const_salt: &Fr,
        pk_d: &sb_primitives::JubjubAffine,
        h_aux: &Fr,
    ) -> Option<Fr> {
        let (pk_eph, ct) = encrypt_note(&self.note, pk_d)?;
        Some(note_leaf_aux(
            const_salt,
            &self.h_body_create,
            self.output_index,
            &pk_eph,
            &ct,
            h_aux,
        ))
    }
}

/// An input of a swap transfer (`docs/SWAP.md` §6, §9).
#[derive(Clone, Debug)]
pub enum SwapInput {
    /// One of our plain notes.
    Plain(SpendableNote),
    /// A locked note we own, spent with the preimage.
    Claim {
        note: SpendableNote,
        opening: LockOpening,
        secret: Secret,
    },
    /// A locked note we created for `owner`, taken back after `t_refund`
    /// with our refund key (the note's `d` is the owner's); `d_refund` is
    /// the diversifier of our address whose `pk_d` is the lock's
    /// `pk_refund` (the wallet looks it up in its address book).
    Refund {
        note: SpendableNote,
        opening: LockOpening,
        owner: JubjubAffine,
        d_refund: [u8; 11],
    },
}

impl SwapInput {
    pub fn note(&self) -> &SpendableNote {
        match self {
            SwapInput::Plain(n)
            | SwapInput::Claim { note: n, .. }
            | SwapInput::Refund { note: n, .. } => n,
        }
    }
}

/// An output of a swap transfer: a recipient, locked or plain.
#[derive(Clone, Debug)]
pub struct SwapOutput {
    pub recipient: Recipient,
    pub lock: Option<LockOpening>,
}

/// Everything a wallet needs to remember about a swap transfer it built.
#[derive(Clone, Debug)]
pub struct BuiltSwap {
    pub envelope: SwapEnvelope,
    pub statement: SwapStatement,
    pub output_notes: [NotePlaintext; N_OUT],
    pub output_addresses: [PaymentAddress; N_OUT],
    pub h_aux: [Fr; N_OUT],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Recipient {
    pub address: PaymentAddress,
    pub value: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error("at most {N_IN} inputs allowed")]
    InputCount,
    #[error("between 1 and {N_OUT} outputs required")]
    OutputCount,
    #[error("inputs sum to {inputs} but outputs sum to {outputs}")]
    Imbalance { inputs: u64, outputs: u64 },
    #[error("input at position {0} is not the note described by the wallet record")]
    LeafMismatch(u64),
    #[error("input at position {0} does not belong to this wallet")]
    NotOwned(u64),
    #[error("input at position {0} is not under the anchor")]
    NotUnderAnchor(u64),
    #[error("value overflow")]
    Overflow,
    #[error("proving: {0}")]
    Proof(#[from] sb_circuit::ProofError),
}

/// Everything a wallet needs to remember about a transfer it built.
#[derive(Clone, Debug)]
pub struct BuiltTransfer {
    pub envelope: TransferEnvelope,
    pub statement: TransferStatement,
    pub output_notes: [NotePlaintext; N_OUT],
    pub output_addresses: [PaymentAddress; N_OUT],
}

/// Build and prove a transfer.
///
/// * `tree` is the replayed note tree; `anchor_size` is its leaf count after
///   block `h_anchor`, so paths are taken under `R[h_anchor]`.
/// * Fewer than two inputs/outputs are padded with dummies (profile §8.2);
///   with no real inputs every output must be zero-valued.
#[allow(clippy::too_many_arguments)]
pub fn build_transfer<R: RngCore + CryptoRng>(
    params: &TransferParams,
    keys: &WalletKeys,
    const_salt: &[u8; 32],
    tree: &NoteTree,
    h_anchor: u32,
    anchor_size: u64,
    inputs: &[SpendableNote],
    outputs: &[Recipient],
    rng: &mut R,
) -> Result<BuiltTransfer, BuildError> {
    if inputs.len() > N_IN {
        return Err(BuildError::InputCount);
    }
    if outputs.is_empty() || outputs.len() > N_OUT {
        return Err(BuildError::OutputCount);
    }
    let salt_fe = sb_core::envelope::bytes_to_fr_253(const_salt);
    let sum_in = inputs
        .iter()
        .try_fold(0u64, |a, i| a.checked_add(i.note.value))
        .ok_or(BuildError::Overflow)?;
    let sum_out = outputs
        .iter()
        .try_fold(0u64, |a, o| a.checked_add(o.value))
        .ok_or(BuildError::Overflow)?;
    if sum_in != sum_out {
        return Err(BuildError::Imbalance {
            inputs: sum_in,
            outputs: sum_out,
        });
    }
    let (_, own_addr) = keys.ivk.find_address(0);

    // 1. input preparation (§13.1)
    let r_anchor = tree.root_at(anchor_size);
    let mut input_witnesses = Vec::with_capacity(N_IN);
    let mut nullifiers = Vec::with_capacity(N_IN);
    for i in inputs {
        let pk_d = keys.pk_d(i.note.d).ok_or(BuildError::NotOwned(i.pos))?;
        let leaf = i.leaf(&salt_fe, &pk_d).ok_or(BuildError::NotOwned(i.pos))?;
        if tree.leaves().get(i.pos as usize) != Some(&leaf) {
            return Err(BuildError::LeafMismatch(i.pos));
        }
        let path = tree
            .path_at(i.pos, anchor_size)
            .ok_or(BuildError::NotUnderAnchor(i.pos))?;
        debug_assert_eq!(path.root(&leaf), r_anchor);
        input_witnesses.push(InputWitness {
            note: i.note,
            h_body_create: i.h_body_create,
            output_index: i.output_index,
            pos: i.pos,
            siblings: path.siblings,
        });
        nullifiers.push(nullifier(&keys.sk_nf, &i.note.rho(), i.pos));
    }
    while input_witnesses.len() < N_IN {
        let dummy = InputWitness::dummy(own_addr.d, Fr::rand(rng));
        nullifiers.push(nullifier(&keys.sk_nf, &dummy.note.rho(), dummy.pos));
        input_witnesses.push(dummy);
    }
    debug_assert_ne!(nullifiers[0], nullifiers[1], "distinct rseed/pos");

    // 2. output construction
    let mut output_witnesses = Vec::with_capacity(N_OUT);
    let mut addresses = Vec::with_capacity(N_OUT);
    for o in outputs {
        output_witnesses.push(OutputWitness {
            note: NotePlaintext {
                value: o.value,
                d: o.address.d,
                rseed: Fr::rand(rng),
            },
            pk_d: o.address.pk_d,
        });
        addresses.push(o.address);
    }
    while output_witnesses.len() < N_OUT {
        output_witnesses.push(OutputWitness {
            note: NotePlaintext {
                value: 0,
                d: own_addr.d,
                rseed: Fr::rand(rng),
            },
            pk_d: own_addr.pk_d,
        });
        addresses.push(own_addr);
    }
    let mut pk_eph = Vec::with_capacity(N_OUT);
    let mut ct_note = Vec::with_capacity(N_OUT);
    let mut entries = Vec::with_capacity(N_OUT);
    for o in &output_witnesses {
        let (p, c) = encrypt_note(&o.note, &o.pk_d).expect("recipient diversifier was validated");
        pk_eph.push(p);
        ct_note.push(c);
        entries.push(RecoveryEntry {
            pk_d: o.pk_d,
            sk_eph: o.note.sk_eph(),
        });
    }
    let pk_eph: [_; N_OUT] = pk_eph.try_into().unwrap();
    let ct_note: [_; N_OUT] = ct_note.try_into().unwrap();
    let entries: [_; N_OUT] = entries.try_into().unwrap();

    // 3. recovery ciphertext
    let digest = binding_digest(&pk_eph, &ct_note);
    let ct_out = encrypt_recovery(&keys.ovk, &digest, &entries);

    // 4. body and binding
    let nullifiers: [Fr; N_IN] = nullifiers.try_into().unwrap();
    let body = TransferBody {
        h_anchor,
        nullifiers,
        pk_eph,
        ct_note,
        ct_out,
    };
    let h_body = body.h_body(const_salt);

    // 5. prove
    let statement = TransferStatement {
        const_salt: salt_fe,
        r_anchor,
        nullifiers,
        pk_eph,
        ct_note,
        h_body,
    };
    let witness = TransferWitness {
        sk_spend: keys.sk_spend,
        inputs: input_witnesses.try_into().unwrap(),
        outputs: output_witnesses.clone().try_into().unwrap(),
    };
    let proof = params.prove(&statement, &witness, rng)?;
    Ok(BuiltTransfer {
        envelope: TransferEnvelope { body, proof },
        statement,
        output_notes: [output_witnesses[0].note, output_witnesses[1].note],
        output_addresses: addresses.try_into().unwrap(),
    })
}

/// Build and prove a swap transfer (`docs/SWAP.md`): any mix of plain,
/// claim and refund inputs, outputs with or without a lock.
#[allow(clippy::too_many_arguments)]
pub fn build_swap_transfer<R: RngCore + CryptoRng>(
    params: &SwapParams,
    keys: &WalletKeys,
    const_salt: &[u8; 32],
    tree: &NoteTree,
    h_anchor: u32,
    anchor_size: u64,
    inputs: &[SwapInput],
    outputs: &[SwapOutput],
    rng: &mut R,
) -> Result<BuiltSwap, BuildError> {
    if inputs.len() > N_IN {
        return Err(BuildError::InputCount);
    }
    if outputs.is_empty() || outputs.len() > N_OUT {
        return Err(BuildError::OutputCount);
    }
    let salt_fe = sb_core::envelope::bytes_to_fr_253(const_salt);
    let note_of = SwapInput::note;
    let sum_in = inputs
        .iter()
        .try_fold(0u64, |a, i| a.checked_add(note_of(i).note.value))
        .ok_or(BuildError::Overflow)?;
    let sum_out = outputs
        .iter()
        .try_fold(0u64, |a, o| a.checked_add(o.recipient.value))
        .ok_or(BuildError::Overflow)?;
    if sum_in != sum_out {
        return Err(BuildError::Imbalance {
            inputs: sum_in,
            outputs: sum_out,
        });
    }
    let (_, own_addr) = keys.ivk.find_address(0);
    let r_anchor = tree.root_at(anchor_size);

    // 1. inputs: leaf under the right slot and owner, path, nullifier of the path
    let mut input_witnesses = Vec::with_capacity(N_IN);
    let mut nullifiers = Vec::with_capacity(N_IN);
    for i in inputs {
        let n = note_of(i);
        let (pk_owner, h_aux, opening, secret, d_refund, refund) = match i {
            SwapInput::Plain(_) => {
                let pk = keys.pk_d(n.note.d).ok_or(BuildError::NotOwned(n.pos))?;
                (
                    pk,
                    Fr::from(0u64),
                    LockOpening {
                        hash: [0u8; 32],
                        pk_refund: JubjubAffine::zero(),
                        t_refund: 0,
                    },
                    Secret([0u8; 32]),
                    own_addr.d,
                    false,
                )
            }
            SwapInput::Claim {
                opening, secret, ..
            } => {
                let pk = keys.pk_d(n.note.d).ok_or(BuildError::NotOwned(n.pos))?;
                (
                    pk,
                    opening.commitment(),
                    *opening,
                    *secret,
                    own_addr.d,
                    false,
                )
            }
            SwapInput::Refund {
                opening,
                owner,
                d_refund,
                ..
            } => {
                // the refund key must be ours: d_refund must name the
                // address whose pk_d the lock commits to
                let ours = keys
                    .ivk
                    .address_for(*d_refund)
                    .filter(|a| a.pk_d == opening.pk_refund)
                    .ok_or(BuildError::NotOwned(n.pos))?;
                (
                    *owner,
                    opening.commitment(),
                    *opening,
                    Secret([0u8; 32]),
                    ours.d,
                    true,
                )
            }
        };
        let leaf = n
            .leaf_aux(&salt_fe, &pk_owner, &h_aux)
            .ok_or(BuildError::NotOwned(n.pos))?;
        if tree.leaves().get(n.pos as usize) != Some(&leaf) {
            return Err(BuildError::LeafMismatch(n.pos));
        }
        let path = tree
            .path_at(n.pos, anchor_size)
            .ok_or(BuildError::NotUnderAnchor(n.pos))?;
        debug_assert_eq!(path.root(&leaf), r_anchor);
        let locked = h_aux != Fr::from(0u64);
        nullifiers.push(if locked {
            nullifier_locked(&n.note.rho(), n.pos)
        } else {
            nullifier(&keys.sk_nf, &n.note.rho(), n.pos)
        });
        input_witnesses.push(SwapInputWitness {
            base: InputWitness {
                note: n.note,
                h_body_create: n.h_body_create,
                output_index: n.output_index,
                pos: n.pos,
                siblings: path.siblings,
            },
            h_aux,
            opening,
            secret,
            d_refund,
            pk_owner,
            refund,
        });
    }
    while input_witnesses.len() < N_IN {
        let dummy = InputWitness::dummy(own_addr.d, Fr::rand(rng));
        nullifiers.push(nullifier(&keys.sk_nf, &dummy.note.rho(), dummy.pos));
        input_witnesses.push(SwapInputWitness::plain(dummy, own_addr.pk_d, own_addr.d));
    }
    debug_assert_ne!(nullifiers[0], nullifiers[1], "distinct rseed/pos");

    // 2. outputs, with their slots
    let mut output_witnesses = Vec::with_capacity(N_OUT);
    let mut addresses = Vec::with_capacity(N_OUT);
    let mut h_aux = Vec::with_capacity(N_OUT);
    for o in outputs {
        output_witnesses.push(OutputWitness {
            note: NotePlaintext {
                value: o.recipient.value,
                d: o.recipient.address.d,
                rseed: Fr::rand(rng),
            },
            pk_d: o.recipient.address.pk_d,
        });
        addresses.push(o.recipient.address);
        h_aux.push(o.lock.map(|l| l.commitment()).unwrap_or(Fr::from(0u64)));
    }
    while output_witnesses.len() < N_OUT {
        output_witnesses.push(OutputWitness {
            note: NotePlaintext {
                value: 0,
                d: own_addr.d,
                rseed: Fr::rand(rng),
            },
            pk_d: own_addr.pk_d,
        });
        addresses.push(own_addr);
        h_aux.push(Fr::from(0u64));
    }
    let mut pk_eph = Vec::with_capacity(N_OUT);
    let mut ct_note = Vec::with_capacity(N_OUT);
    let mut entries = Vec::with_capacity(N_OUT);
    for o in &output_witnesses {
        let (p, c) = encrypt_note(&o.note, &o.pk_d).expect("recipient diversifier was validated");
        pk_eph.push(p);
        ct_note.push(c);
        entries.push(RecoveryEntry {
            pk_d: o.pk_d,
            sk_eph: o.note.sk_eph(),
        });
    }
    let pk_eph: [_; N_OUT] = pk_eph.try_into().unwrap();
    let ct_note: [_; N_OUT] = ct_note.try_into().unwrap();
    let entries: [_; N_OUT] = entries.try_into().unwrap();
    let h_aux: [Fr; N_OUT] = h_aux.try_into().unwrap();

    // 3. recovery ciphertext, 4. body and binding over the swap body
    let digest = binding_digest(&pk_eph, &ct_note);
    let ct_out = encrypt_recovery(&keys.ovk, &digest, &entries);
    let nullifiers: [Fr; N_IN] = nullifiers.try_into().unwrap();
    let body = SwapBody {
        base: TransferBody {
            h_anchor,
            nullifiers,
            pk_eph,
            ct_note,
            ct_out,
        },
        h_aux,
    };
    let h_body = body.h_body(const_salt);

    // 5. prove
    let statement = SwapStatement {
        base: TransferStatement {
            const_salt: salt_fe,
            r_anchor,
            nullifiers,
            pk_eph,
            ct_note,
            h_body,
        },
        h_anchor,
    };
    let witness = SwapWitness {
        sk_spend: keys.sk_spend,
        inputs: input_witnesses.try_into().unwrap(),
        outputs: output_witnesses.clone().try_into().unwrap(),
    };
    let proof = params.prove(&statement, &witness, rng)?;
    Ok(BuiltSwap {
        envelope: SwapEnvelope { body, proof },
        statement,
        output_notes: [output_witnesses[0].note, output_witnesses[1].note],
        output_addresses: addresses.try_into().unwrap(),
        h_aux,
    })
}

#[cfg(test)]
mod coverage_tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng as StdRng;
    use sb_core::keys::Seed;

    fn setup() -> (WalletKeys, PaymentAddress, NoteTree, [u8; 32]) {
        let k = WalletKeys::from_seed(&Seed([3u8; 32]));
        let (_, a) = k.ivk.find_address(0);
        (k, a, NoteTree::new(), [1u8; 32])
    }

    fn note(a: &PaymentAddress, value: u64, pos: u64) -> SpendableNote {
        SpendableNote {
            note: NotePlaintext {
                value,
                d: a.d,
                rseed: Fr::from(pos + 1),
            },
            h_body_create: Fr::from(0u64),
            output_index: 0,
            pos,
        }
    }

    #[test]
    fn builder_argument_errors() {
        let (k, a, tree, salt) = setup();
        let mut rng = StdRng::seed_from_u64(1);
        let params = sb_circuit::TransferParams::insecure_setup(&[0u8; 32]).unwrap();
        let r = |v| Recipient {
            address: a,
            value: v,
        };
        let three_in = [note(&a, 1, 0), note(&a, 1, 1), note(&a, 1, 2)];
        assert!(matches!(
            build_transfer(
                &params,
                &k,
                &salt,
                &tree,
                0,
                0,
                &three_in,
                &[r(3)],
                &mut rng
            ),
            Err(BuildError::InputCount)
        ));
        assert!(matches!(
            build_transfer(&params, &k, &salt, &tree, 0, 0, &[], &[], &mut rng),
            Err(BuildError::OutputCount)
        ));
        assert!(matches!(
            build_transfer(
                &params,
                &k,
                &salt,
                &tree,
                0,
                0,
                &[],
                &[r(1), r(1), r(1)],
                &mut rng
            ),
            Err(BuildError::OutputCount)
        ));
        assert!(matches!(
            build_transfer(
                &params,
                &k,
                &salt,
                &tree,
                0,
                0,
                &[note(&a, 5, 0)],
                &[r(4)],
                &mut rng
            ),
            Err(BuildError::Imbalance {
                inputs: 5,
                outputs: 4
            })
        ));
        let big = [note(&a, u64::MAX, 0), note(&a, 1, 1)];
        assert!(matches!(
            build_transfer(&params, &k, &salt, &tree, 0, 0, &big, &[r(1)], &mut rng),
            Err(BuildError::Overflow)
        ));
        // a note whose leaf is not in the tree
        assert!(matches!(
            build_transfer(
                &params,
                &k,
                &salt,
                &tree,
                0,
                0,
                &[note(&a, 5, 0)],
                &[r(5)],
                &mut rng
            ),
            Err(BuildError::LeafMismatch(0))
        ));
        // a note under a diversifier with no curve point cannot be owned
        let mut bad = a;
        let mut i = 0u64;
        bad.d = loop {
            let d = k.ivk.diversifier(i);
            if sb_primitives::diversify::diversify_hash(&d).is_none() {
                break d;
            }
            i += 1;
        };
        assert!(matches!(
            build_transfer(
                &params,
                &k,
                &salt,
                &tree,
                0,
                0,
                &[note(&bad, 5, 0)],
                &[r(5)],
                &mut rng
            ),
            Err(BuildError::NotOwned(0))
        ));
        assert!(format!("{}", BuildError::InputCount).contains("inputs"));
    }
}
