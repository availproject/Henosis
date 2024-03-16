#![no_main]
use risc0_zkvm::guest::env;
use fflonk_verifier::verifier::verify;
use fflonk_verifier::utils::{G1Point, Proof, ProofWithPubSignal};
use zksync_verifier::verifier::verify as zksyncVerifier;
use ark_bn254::{
    g1, g1::Parameters, Bn254, Fq, FqParameters, Fr, FrParameters, G1Projective, G2Projective,
};
use ark_bn254::{g2, Fq2, Fq2Parameters, G2Affine};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::*;
use ark_ff::{
    field_new, Field, Fp256, Fp256Parameters, Fp2ParamsWrapper, One, PrimeField, QuadExtField,
    UniformRand, Zero,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

risc0_zkvm::guest::entry!(main);

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProofInput {
    input: [Vec<String>; 1],
    signal: [String; 1]
}

fn main() {
    let proof_input: ProofInput = env::read();
    let start = env::cycle_count();
    // zksyncVerifier();

    let pr_value = &proof_input.clone().input[0];
    let pr = pr_value.iter().map(|x| x.as_str()).collect::<Vec<&str>>();

    let c1_x = <G1Point as AffineCurve>::BaseField::from_str(pr[0]).unwrap();
    let c1_y = <G1Point as AffineCurve>::BaseField::from_str(pr[1]).unwrap();
    let c1_affine = G1Projective::new(
        c1_x,
        c1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let c2_x = <G1Point as AffineCurve>::BaseField::from_str(pr[2]).unwrap();
    let c2_y = <G1Point as AffineCurve>::BaseField::from_str(pr[3]).unwrap();
    let c2_affine = G1Projective::new(
        c2_x,
        c2_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let w1_x = <G1Point as AffineCurve>::BaseField::from_str(pr[4]).unwrap();
    let w1_y = <G1Point as AffineCurve>::BaseField::from_str(pr[5]).unwrap();
    let w1_affine = G1Projective::new(
        w1_x,
        w1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let w2_x = <G1Point as AffineCurve>::BaseField::from_str(pr[6]).unwrap();
    let w2_y = <G1Point as AffineCurve>::BaseField::from_str(pr[7]).unwrap();
    let w2_affine = G1Projective::new(
        w2_x,
        w2_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let proof = Proof {
        c1: c1_affine,
        c2: c2_affine,
        w1: w1_affine,
        w2: w2_affine,
        eval_ql: Fr::from_str(pr[8]).unwrap(),
        eval_qr: Fr::from_str(pr[9]).unwrap(),
        eval_qm: Fr::from_str(pr[10]).unwrap(),
        eval_qo: Fr::from_str(pr[11]).unwrap(),
        eval_qc: Fr::from_str(pr[12]).unwrap(),
        eval_s1: Fr::from_str(pr[13]).unwrap(),
        eval_s2: Fr::from_str(pr[14]).unwrap(),
        eval_s3: Fr::from_str(pr[15]).unwrap(),
        eval_a: Fr::from_str(pr[16]).unwrap(),
        eval_b: Fr::from_str(pr[17]).unwrap(),
        eval_c: Fr::from_str(pr[18]).unwrap(),
        eval_z: Fr::from_str(pr[19]).unwrap(),
        eval_zw: Fr::from_str(pr[20]).unwrap(),
        eval_t1w: Fr::from_str(pr[21]).unwrap(),
        eval_t2w: Fr::from_str(pr[22]).unwrap(),
        eval_inv: Fr::from_str(pr[23]).unwrap(),
    };

    let proof_with_pub_signal = ProofWithPubSignal {
        proof,
        pub_signal: Fr::from_str(proof_input.clone().signal[0].as_str()).unwrap(),
    };

    let isP1Verified: bool = verify(proof_with_pub_signal);

    // let pr_value = &proof_input.clone().input[1];
    // let pr = pr_value.iter().map(|x| x.as_str()).collect::<Vec<&str>>();

    // let c1_x = <G1Point as AffineCurve>::BaseField::from_str(pr[0]).unwrap();
    // let c1_y = <G1Point as AffineCurve>::BaseField::from_str(pr[1]).unwrap();
    // let c1_affine = G1Projective::new(
    //     c1_x,
    //     c1_y,
    //     <G1Projective as ProjectiveCurve>::BaseField::one(),
    // )
    // .into_affine();

    // let c2_x = <G1Point as AffineCurve>::BaseField::from_str(pr[2]).unwrap();
    // let c2_y = <G1Point as AffineCurve>::BaseField::from_str(pr[3]).unwrap();
    // let c2_affine = G1Projective::new(
    //     c2_x,
    //     c2_y,
    //     <G1Projective as ProjectiveCurve>::BaseField::one(),
    // )
    // .into_affine();

    // let w1_x = <G1Point as AffineCurve>::BaseField::from_str(pr[4]).unwrap();
    // let w1_y = <G1Point as AffineCurve>::BaseField::from_str(pr[5]).unwrap();
    // let w1_affine = G1Projective::new(
    //     w1_x,
    //     w1_y,
    //     <G1Projective as ProjectiveCurve>::BaseField::one(),
    // )
    // .into_affine();

    // let w2_x = <G1Point as AffineCurve>::BaseField::from_str(pr[6]).unwrap();
    // let w2_y = <G1Point as AffineCurve>::BaseField::from_str(pr[7]).unwrap();
    // let w2_affine = G1Projective::new(
    //     w2_x,
    //     w2_y,
    //     <G1Projective as ProjectiveCurve>::BaseField::one(),
    // )
    // .into_affine();

    // let proof = Proof {
    //     c1: c1_affine,
    //     c2: c2_affine,
    //     w1: w1_affine,
    //     w2: w2_affine,
    //     eval_ql: Fr::from_str(pr[8]).unwrap(),
    //     eval_qr: Fr::from_str(pr[9]).unwrap(),
    //     eval_qm: Fr::from_str(pr[10]).unwrap(),
    //     eval_qo: Fr::from_str(pr[11]).unwrap(),
    //     eval_qc: Fr::from_str(pr[12]).unwrap(),
    //     eval_s1: Fr::from_str(pr[13]).unwrap(),
    //     eval_s2: Fr::from_str(pr[14]).unwrap(),
    //     eval_s3: Fr::from_str(pr[15]).unwrap(),
    //     eval_a: Fr::from_str(pr[16]).unwrap(),
    //     eval_b: Fr::from_str(pr[17]).unwrap(),
    //     eval_c: Fr::from_str(pr[18]).unwrap(),
    //     eval_z: Fr::from_str(pr[19]).unwrap(),
    //     eval_zw: Fr::from_str(pr[20]).unwrap(),
    //     eval_t1w: Fr::from_str(pr[21]).unwrap(),
    //     eval_t2w: Fr::from_str(pr[22]).unwrap(),
    //     eval_inv: Fr::from_str(pr[23]).unwrap(),
    // };

    // let proof_with_pub_signal = ProofWithPubSignal {
    //     proof,
    //     pub_signal: Fr::from_str(proof_input.signal[1].as_str()).unwrap(),
    // };

    // eprintln!("Start verifying second proof");

    // let isP2Verified: bool = verify(proof_with_pub_signal);
    // eprintln!("isP1Verified: {:?}", isP1Verified);

    // let isVerified: bool = isP1Verified & isP2Verified;
    let isVerified: bool = isP1Verified;

    let end = env::cycle_count();
    let cycle_count = end - start;
    env::commit(&isVerified);
}
