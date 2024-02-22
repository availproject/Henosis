#![no_main]
use risc0_zkvm::guest::env;
// use plonk_verifier::verifier::verifier::verify;
use fflonk_verifier::verifier::verify;
use fflonk_verifier::utils::{G1Point, Proof};
// use ark_bn254::{g1, g1::Parameters, Bn254, FqParameters, Fr, FrParameters, G1Projective};
// use ark_ec::short_weierstrass_jacobian::GroupAffine;
// use ark_ff::{Field, Fp256, Fp256Parameters, One, PrimeField, UniformRand, Zero};
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
struct proofInput {
    input: Vec<String>
}


fn main() {

    let proof_input: proofInput = env::read();

    let pr_value = proof_input.input;
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

    let isVerifierd: bool = verify(proof);

    env::log(&format!("IsVerified {}", isVerifierd));
    env::commit(&isVerifierd);
}
