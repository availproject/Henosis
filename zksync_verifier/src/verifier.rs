pub use crate::utils::{get_domain_size, get_omegas, get_proof, get_pubSignals, Omegas, Proof, ProofWithPubSignal};
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
use ark_poly::{domain, Polynomial};
use core::num;
use std::fmt::{format, Debug, DebugMap, Display};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};
use std::str::FromStr;
use std::vec;
use crate::utils::get_proog_bigint;
use num_bigint::*;

use tiny_keccak::{Hasher, Keccak};
use num_bigint::BigUint;


pub type G1Point = <Bn254 as PairingEngine>::G1Affine;
pub type G2Point = <Bn254 as PairingEngine>::G2Affine;

pub fn verify() {
    // do something here above and beyond !!
}