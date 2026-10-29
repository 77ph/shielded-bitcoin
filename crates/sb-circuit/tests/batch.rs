//! The batch circuit (`docs/REPLAY-PROOF.md` §4.2) against a native
//! simulation of replay's three trees: a two-slot block proves and
//! verifies, fragments chain to the same state, an empty block appends
//! only its root, and tampered witnesses leave the constraints unsatisfied.

use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem, SynthesisMode};
use ark_std::rand::{SeedableRng, rngs::StdRng};

use sb_circuit::groth16::{BatchShape, verify_batch};
use sb_circuit::{BatchCircuit, BatchParams};
use sb_core::batch::{
    BatchStatement, BatchWitness, N_OUT, NullifierInsert, SlotStatement, SlotWitness, StateOpening,
    batch_digest,
};
use sb_core::imt::IndexedMerkleTree;
use sb_core::note::{NoteCiphertext, note_leaf_aux};
use sb_core::tree::{MerklePath, NoteTree};
use sb_primitives::poseidon::hash;
use sb_primitives::tags::t_batch;
use sb_primitives::{Fr, JubjubAffine};

const ACT: u32 = 100;
const W: u32 = 100;
const K_MIN: u32 = 1;

fn salt() -> Fr {
    Fr::from(7u64)
}

fn shape(n: usize) -> BatchShape {
    BatchShape {
        n,
        activation: ACT,
        window_w: W,
        k_min: K_MIN,
        const_salt: salt(),
    }
}

/// Replay's trees, driven the way the circuit expects.
struct Sim {
    tree: NoteTree,
    nf: IndexedMerkleTree,
    roots: NoteTree,
    height: u32,
    applied: u32,
}

impl Sim {
    /// Three empty blocks replayed: leaf 0 the root before activation, then
    /// roots for `ACT..ACT+3`; next block `ACT+3`.
    fn new() -> Self {
        let tree = NoteTree::new();
        let mut roots = NoteTree::new();
        roots.append(sb_core::tree::EMPTY_ROOTS[sb_core::tree::DEPTH]);
        for _ in 0..3 {
            roots.append(tree.root());
        }
        Sim {
            tree,
            nf: IndexedMerkleTree::new(),
            roots,
            height: ACT + 3,
            applied: 0,
        }
    }

    fn opening(&self) -> StateOpening {
        StateOpening {
            root: self.tree.root(),
            size: self.tree.size(),
            nf_root: self.nf.root(),
            nf_size: self.nf.size(),
            h_root: self.roots.root(),
            height: self.height,
            applied: self.applied,
        }
    }

    /// Apply one synthetic accepted transfer anchored at `h_anchor`.
    fn slot(&mut self, h_anchor: u32, seed: u64) -> SlotWitness {
        let f = |k: u64| hash(t_batch(), &[Fr::from(seed), Fr::from(k)]);
        // an anchor below ACT is the initial root by definition
        let pre = h_anchor < ACT;
        let pos = if pre { 0 } else { (h_anchor - ACT + 1) as u64 };
        let statement = SlotStatement {
            h_anchor,
            r_anchor: self.roots.leaves()[pos as usize],
            nullifiers: [f(1), f(2)],
            pk_eph: [JubjubAffine::default(); N_OUT],
            ct: [
                NoteCiphertext {
                    c0: f(3),
                    c1: f(4),
                    tag: f(5),
                },
                NoteCiphertext {
                    c0: f(6),
                    c1: f(7),
                    tag: f(8),
                },
            ],
            h_body: f(9),
            h_aux: [Fr::from(0u64); N_OUT],
            mint: false,
        };
        let anchor_siblings = if pre {
            [Fr::from(0u64); sb_core::tree::DEPTH]
        } else {
            self.roots.path_at(pos, self.roots.size()).unwrap().siblings
        };
        let nullifiers = [
            NullifierInsert::from(&self.nf.insert(statement.nullifiers[0]).unwrap()),
            NullifierInsert::from(&self.nf.insert(statement.nullifiers[1]).unwrap()),
        ];
        let mut leaves: Vec<MerklePath> = Vec::new();
        for j in 0..N_OUT {
            let leaf = note_leaf_aux(
                &salt(),
                &statement.h_body,
                j as u64,
                &statement.pk_eph[j],
                &statement.ct[j],
                &statement.h_aux[j],
            );
            leaves.push(self.tree.append_path());
            self.tree.append(leaf);
        }
        self.applied += 1;
        SlotWitness {
            statement,
            anchor_siblings,
            nullifiers,
            leaves: leaves.try_into().unwrap(),
        }
    }

    /// Apply a mint: one leaf, no anchor, no nullifiers.
    fn mint_slot(&mut self, seed: u64) -> SlotWitness {
        let f = |k: u64| hash(t_batch(), &[Fr::from(seed), Fr::from(k)]);
        let statement = SlotStatement {
            h_anchor: 0,
            r_anchor: Fr::from(0u64),
            nullifiers: [Fr::from(0u64); 2],
            pk_eph: [JubjubAffine::default(); N_OUT],
            ct: [
                NoteCiphertext {
                    c0: f(3),
                    c1: f(4),
                    tag: f(5),
                },
                NoteCiphertext {
                    c0: Fr::from(0u64),
                    c1: Fr::from(0u64),
                    tag: Fr::from(0u64),
                },
            ],
            h_body: f(9),
            h_aux: [Fr::from(0u64); N_OUT],
            mint: true,
        };
        let leaf = note_leaf_aux(
            &salt(),
            &statement.h_body,
            0,
            &statement.pk_eph[0],
            &statement.ct[0],
            &statement.h_aux[0],
        );
        let path = self.tree.append_path();
        self.tree.append(leaf);
        self.applied += 1;
        let unused = MerklePath {
            position: 0,
            siblings: [Fr::from(0u64); sb_core::tree::DEPTH],
        };
        let unused_nf = NullifierInsert {
            low: sb_core::imt::Leaf {
                value: Fr::from(0u64),
                next: Fr::from(0u64),
            },
            low_path: unused.clone(),
            new_path: unused.clone(),
        };
        SlotWitness {
            statement,
            anchor_siblings: [Fr::from(0u64); sb_core::tree::DEPTH],
            nullifiers: [unused_nf.clone(), unused_nf],
            leaves: [path, unused],
        }
    }

    fn finish_block(&mut self) -> MerklePath {
        let path = self.roots.append_path();
        self.roots.append(self.tree.root());
        self.height += 1;
        self.applied = 0;
        path
    }
}

fn satisfied(circuit: BatchCircuit) -> (bool, usize) {
    let cs = ConstraintSystem::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    (cs.is_satisfied().unwrap(), cs.num_constraints())
}

fn circuit(n: usize, st: &BatchStatement, w: &BatchWitness) -> BatchCircuit {
    BatchCircuit {
        n,
        activation: ACT,
        window_w: W,
        k_min: K_MIN,
        const_salt: salt(),
        statement: Some(*st),
        witness: Some(w.clone()),
    }
}

#[test]
fn a_block_of_two_proves_fragments_chain_and_tampering_fails() {
    let mut sim = Sim::new();
    let prev = sim.opening();
    let s1 = sim.slot(ACT + 1, 1);
    let s2 = sim.slot(ACT + 2, 2);
    let ra = sim.finish_block();
    let next = sim.opening();
    let witness = BatchWitness {
        prev,
        slots: vec![Some(s1.clone()), Some(s2.clone())],
        final_block: true,
        root_append: Some(ra.clone()),
    };
    let statement = BatchStatement {
        s_prev: prev.digest(),
        s_next: next.digest(),
        d: batch_digest(&[Some(s1.statement), Some(s2.statement)]),
    };
    let (ok, n_constraints) = satisfied(circuit(2, &statement, &witness));
    assert!(ok);
    println!("batch constraints n=2: {n_constraints}");

    // prove and verify; a wrong public input fails
    let params = BatchParams::insecure_setup(shape(2), &[1u8; 32]).unwrap();
    let mut rng = StdRng::seed_from_u64(1);
    let proof = params.prove(&statement, &witness, &mut rng).unwrap();
    assert!(params.verify(&statement, &proof));
    // batched verification (REPLAY-PROOF.md §4.3 option 2): two proofs
    // under one key in one multi-pairing; a wrong one spoils the batch
    let proof2 = params.prove(&statement, &witness, &mut rng).unwrap();
    assert_ne!(proof, proof2, "re-randomised");
    let items = vec![
        (statement.to_field_elements(), proof),
        (statement.to_field_elements(), proof2),
    ];
    assert!(verify_batch(params.vk(), &items, &mut rng));
    let mut tampered = items.clone();
    tampered[1].0[2] += Fr::from(1u64);
    assert!(!verify_batch(params.vk(), &tampered, &mut rng));
    let mut tampered = items.clone();
    tampered[0].1[0] ^= 1;
    assert!(!verify_batch(params.vk(), &tampered, &mut rng));
    assert!(verify_batch(params.vk(), &[], &mut rng));
    let mut bad = statement;
    bad.s_next += Fr::from(1u64);
    assert!(!params.verify(&bad, &proof));
    let mut bad = statement;
    bad.d = batch_digest(&[Some(s2.statement), Some(s1.statement)]);
    assert!(!params.verify(&bad, &proof), "the order is part of D");

    // the same block as two fragments: slot 1 open, then slot 2 final
    let mut sim2 = Sim::new();
    let p0 = sim2.opening();
    let f1 = sim2.slot(ACT + 1, 1);
    let p1 = sim2.opening();
    assert_eq!(p1.applied, 1);
    assert_eq!(p1.height, p0.height);
    let w1 = BatchWitness {
        prev: p0,
        slots: vec![Some(f1.clone()), None],
        final_block: false,
        root_append: None,
    };
    let st1 = BatchStatement {
        s_prev: p0.digest(),
        s_next: p1.digest(),
        d: batch_digest(&[Some(f1.statement), None]),
    };
    assert!(satisfied(circuit(2, &st1, &w1)).0);
    let f2 = sim2.slot(ACT + 2, 2);
    let ra2 = sim2.finish_block();
    let p2 = sim2.opening();
    assert_eq!(p2, next, "two fragments end where one batch ends");
    let w2 = BatchWitness {
        prev: p1,
        slots: vec![Some(f2.clone()), None],
        final_block: true,
        root_append: Some(ra2),
    };
    let st2 = BatchStatement {
        s_prev: p1.digest(),
        s_next: p2.digest(),
        d: batch_digest(&[Some(f2.statement), None]),
    };
    assert!(satisfied(circuit(2, &st2, &w2)).0);

    // an empty block: no slots, the root appended
    let mut sim3 = Sim::new();
    let e0 = sim3.opening();
    let ra3 = sim3.finish_block();
    let e1 = sim3.opening();
    assert_eq!(e1.height, e0.height + 1);
    let w3 = BatchWitness {
        prev: e0,
        slots: vec![None, None],
        final_block: true,
        root_append: Some(ra3),
    };
    let st3 = BatchStatement {
        s_prev: e0.digest(),
        s_next: e1.digest(),
        d: batch_digest(&[None, None]),
    };
    assert!(satisfied(circuit(2, &st3, &w3)).0);

    // a block with a mint and a transfer anchored before activation (the
    // initial root, no tree membership): the mint appends one leaf and
    // touches neither the anchor nor the nullifier tree
    let mut sim4 = Sim::new();
    let m0 = sim4.opening();
    let mint = sim4.mint_slot(5);
    let tx = sim4.slot(ACT - 1, 6);
    let ra4 = sim4.finish_block();
    let m1 = sim4.opening();
    assert_eq!(m1.size, m0.size + 3);
    assert_eq!(m1.nf_size, m0.nf_size + 2);
    let w4 = BatchWitness {
        prev: m0,
        slots: vec![Some(mint.clone()), Some(tx.clone())],
        final_block: true,
        root_append: Some(ra4),
    };
    let st4 = BatchStatement {
        s_prev: m0.digest(),
        s_next: m1.digest(),
        d: batch_digest(&[Some(mint.statement), Some(tx.statement)]),
    };
    assert!(satisfied(circuit(2, &st4, &w4)).0);
    // a mint that claims a second leaf or a nullifier is not a mint
    let mut w = w4.clone();
    w.slots[0].as_mut().unwrap().statement.mint = false;
    let st = BatchStatement {
        d: batch_digest(&[
            Some(w.slots[0].as_ref().unwrap().statement),
            Some(tx.statement),
        ]),
        ..st4
    };
    assert!(
        !satisfied(circuit(2, &st, &w)).0,
        "a mint presented as a transfer"
    );
    // a pre-activation anchor must open to the initial root, nothing else
    let mut w = w4.clone();
    w.slots[1].as_mut().unwrap().statement.r_anchor += Fr::from(1u64);
    let st = BatchStatement {
        d: batch_digest(&[
            Some(mint.statement),
            Some(w.slots[1].as_ref().unwrap().statement),
        ]),
        ..st4
    };
    assert!(
        !satisfied(circuit(2, &st, &w)).0,
        "pre-activation anchor root"
    );

    // ---- tampering: each leaves the constraints unsatisfied ----
    // a double spend inside the batch: slot 2 reusing slot 1's nullifier
    // and its insertion witness
    let mut w = witness.clone();
    let s2d = w.slots[1].as_mut().unwrap();
    s2d.statement.nullifiers[0] = s1.statement.nullifiers[0];
    s2d.nullifiers[0] = s1.nullifiers[0].clone();
    let st = BatchStatement {
        d: batch_digest(&[Some(s1.statement), Some(s2d.statement)]),
        ..statement
    };
    assert!(!satisfied(circuit(2, &st, &w)).0, "double spend");
    // an anchor root that is not in the root tree
    let mut w = witness.clone();
    w.slots[0].as_mut().unwrap().statement.r_anchor += Fr::from(1u64);
    let st = BatchStatement {
        d: batch_digest(&[
            Some(w.slots[0].as_ref().unwrap().statement),
            Some(s2.statement),
        ]),
        ..statement
    };
    assert!(!satisfied(circuit(2, &st, &w)).0, "anchor");
    // an anchor at the block in progress itself (below K_min)
    let mut w = witness.clone();
    w.slots[0].as_mut().unwrap().statement.h_anchor = ACT + 3;
    let st = BatchStatement {
        d: batch_digest(&[
            Some(w.slots[0].as_ref().unwrap().statement),
            Some(s2.statement),
        ]),
        ..statement
    };
    assert!(!satisfied(circuit(2, &st, &w)).0, "window");
    // a leaf appended at the wrong position
    let mut w = witness.clone();
    w.slots[1].as_mut().unwrap().leaves[0].position += 1;
    assert!(!satisfied(circuit(2, &statement, &w)).0, "leaf position");
    // the block closed without the root appended
    let mut w = witness.clone();
    w.final_block = false;
    assert!(!satisfied(circuit(2, &statement, &w)).0, "final");

    // constraint counts for the document (in the same test, so that the
    // setup above and the 2^22 system below never share the memory)
    for n in [1usize, 4, 16] {
        let cs = ConstraintSystem::new_ref();
        cs.set_mode(SynthesisMode::Setup);
        BatchCircuit {
            n,
            activation: ACT,
            window_w: W,
            k_min: K_MIN,
            const_salt: salt(),
            statement: None,
            witness: None,
        }
        .generate_constraints(cs.clone())
        .unwrap();
        println!("batch constraints n={n}: {}", cs.num_constraints());
    }
}
