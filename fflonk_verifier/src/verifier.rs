use ark_bn254::{Bn254, FqParameters, Fr, FrParameters, G1Projective, g1::Parameters, g1};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::*;
use ark_ff::{Field, Fp256, One, PrimeField, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{domain, Polynomial};
use std::fmt::{Debug, DebugMap, Display};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};
use std::str::FromStr;
use num_bigint::*;

pub type G1Point = <Bn254 as PairingEngine>::G1Affine;
pub type G2Point = <Bn254 as PairingEngine>::G2Affine;




pub fn verify() {

    let alpha: Fp256<FrParameters> = Fr::from_str(
        "7322047676393218637481338970179134619960969643173747239601962635317485088344",
    )
    .unwrap();

    let beta: Fp256<FrParameters> = Fr::from_str(
        "555960103527329154567657609884853810354674391984649378679184507744444027027",
    )
    .unwrap();

    let gamma: Fp256<FrParameters> = Fr::from_str(
        "6957574725743056350363256008332060958376811930570348194340253625274403224161",
    )
    .unwrap();

    let xiseed: Fp256<FrParameters> = Fr::from_str(
        "7896530194749115621350184803828649182986933409800667201245111721654183640928",
    ).unwrap();

    let xiseed2: Fp256<FrParameters> = Fr::from_str(
        "9144946180881585340800612715529400610463547442756395931665142563665450056128",
    ).unwrap();

    let y: Fp256<FrParameters> = Fr::from_str(
        "13096643561003703188657823618924776735424142649986849213485512124502494958287",
    ).unwrap();

    let xi: Fp256<FrParameters> = Fr::from_str(
        "10393185035615259318552712605767090377249145892581385744729012713520677048218",
    ).unwrap();
    println!("Verifying proof...");
}
