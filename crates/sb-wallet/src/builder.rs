//! Transfer construction (paper §13.1, Appendix C; profile §7, §8).

use ark_ff::UniformRand;
use rand::{CryptoRng, RngCore};

use sb_circuit::{InputWitness, OutputWitness, TransferParams, TransferStatement, TransferWitness};
use sb_core::address::PaymentAddress;
use sb_core::envelope::{N_IN, TransferBody, TransferEnvelope};
use sb_core::keys::WalletKeys;
use sb_core::note::{NotePlaintext, encrypt_note, note_leaf, nullifier};
use sb_core::recovery::{N_OUT, RecoveryEntry, binding_digest, encrypt_recovery};
use sb_core::tree::NoteTree;
use sb_primitives::Fr;

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
    if nullifiers[0] == nullifiers[1] {
        unreachable!("distinct rseed/pos give distinct nullifiers");
    }

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
