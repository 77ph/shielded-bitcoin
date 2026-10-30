//! docs/VARIANT-A.md: the cost of a Halo 2 (IPA over Pasta) shielded
//! proof on this laptop, measured on the nearest production relation to
//! this project's transfer: Zcash Orchard's Action circuit (the crate
//! `orchard`, the one `kupermind/confidant` reuses unchanged). A bundle
//! of n actions is n (dummy spend, output) pairs proven in one proof; this
//! project's 2-in-2-out transfer corresponds to two actions. Printed: key
//! generation, proof size, proving and verification time per bundle size.

use orchard::{
    builder::{Builder, BundleType},
    bundle::BundleVersion,
    circuit::{OrchardCircuitVersion, ProvingKey, VerifyingKey},
    keys::{FullViewingKey, Scope, SpendingKey},
    value::NoteValue,
    Anchor, Bundle,
};
use rand::rngs::OsRng;
use std::time::Instant;

fn main() {
    let rng = OsRng;
    let sk = SpendingKey::from_bytes([7; 32]).unwrap();
    let recipient = FullViewingKey::from(&sk).address_at(0u32, Scope::External);

    println!("circuit rows: 2^11 (orchard::circuit::K = 11 in orchard 0.15.5)");
    let t = Instant::now();
    let vk = VerifyingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    println!("verifying key: {:.1} s", t.elapsed().as_secs_f64());
    let t = Instant::now();
    let pk = ProvingKey::build(OrchardCircuitVersion::FixedPostNu6_2);
    println!("proving key: {:.1} s", t.elapsed().as_secs_f64());

    for n in 1..=4usize {
        let mut builder = Builder::new(
            BundleType::DEFAULT,
            BundleVersion::orchard_v2(),
            BundleVersion::orchard_v2().default_flags(),
            Anchor::from_bytes([0; 32]).unwrap(),
        )
        .unwrap();
        for _ in 0..n {
            builder
                .add_output(None, recipient, NoteValue::from_raw(10), [0; 512])
                .unwrap();
        }
        let bundle: Bundle<_, i64> = builder.build(rng).unwrap().unwrap().0;
        let instances: Vec<_> = bundle
            .actions()
            .iter()
            .map(|a| a.to_instance(*bundle.flags(), *bundle.anchor()))
            .collect();
        let t = Instant::now();
        let proof = bundle
            .authorization()
            .create_proof(&pk, &instances, rng)
            .unwrap();
        let prove = t.elapsed().as_secs_f64();
        let t = Instant::now();
        let ok = proof.verify(&vk, &instances).is_ok();
        let verify = t.elapsed().as_secs_f64() * 1000.0;
        println!(
            "{n} action(s): proof {} bytes, prove {prove:.2} s, verify {verify:.1} ms, ok {ok}",
            proof.as_ref().len()
        );
    }
}
