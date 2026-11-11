//! A key written and read back proves and verifies as the original.

use pasta_curves::{EqAffine, Fp};
use rand_core::OsRng;

use crate::plonk::claims_test::Mul;
use crate::plonk::{create_proof, keygen_pk, keygen_vk, verify_proof, ProvingKey, VerifyingKey};
use crate::poly::commitment::Params;
use crate::transcript::{Blake2bRead, Blake2bWrite, Challenge255};

#[test]
fn keys_round_trip_through_bytes() {
    let params: Params<EqAffine> = Params::new(5);
    let vk = keygen_vk(&params, &Mul::default()).unwrap();
    let pk = keygen_pk(&params, vk.clone(), &Mul::default()).unwrap();
    let mut vk_bytes = Vec::new();
    vk.write(&mut vk_bytes).unwrap();
    let mut pk_bytes = Vec::new();
    pk.write(&mut pk_bytes).unwrap();
    let vk2 = VerifyingKey::<EqAffine>::read::<_, Mul>(&mut &vk_bytes[..], &params).unwrap();
    let pk2 = ProvingKey::<EqAffine>::read::<_, Mul>(&mut &pk_bytes[..], &params).unwrap();
    // the same key: written again, the same bytes
    let mut again = Vec::new();
    pk2.write(&mut again).unwrap();
    assert_eq!(again, pk_bytes);
    // a proof with the read key verifies with the original, and the other way round
    let (circuit, out) = Mul::new(3, 4);
    let instance = [out];
    for (prover_key, verifier_key) in [(&pk2, &vk), (&pk, &vk2)] {
        let mut t = Blake2bWrite::<_, EqAffine, Challenge255<_>>::init(vec![]);
        create_proof(
            &params,
            prover_key,
            &[circuit.clone()],
            &[&[&instance[..]]],
            OsRng,
            &mut t,
        )
        .unwrap();
        let proof = t.finalize();
        let mut t = Blake2bRead::<_, EqAffine, Challenge255<_>>::init(&proof[..]);
        verify_proof(
            &params,
            verifier_key,
            crate::plonk::SingleVerifier::new(&params),
            &[&[&instance[..]]],
            &mut t,
        )
        .unwrap();
    }
    // another k, or a truncated file, is refused
    let p6: Params<EqAffine> = Params::new(6);
    assert!(VerifyingKey::<EqAffine>::read::<_, Mul>(&mut &vk_bytes[..], &p6).is_err());
    assert!(
        ProvingKey::<EqAffine>::read::<_, Mul>(&mut &pk_bytes[..pk_bytes.len() - 7], &params)
            .is_err()
    );
}
