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
    println!("Verifying proof...");
}


fn calculateR0() {
    let eval_ql = Fr::from_str("1972554287366869807517068788787992038621302618305780153544292964897315682091").unwrap();
    let eval_qr = Fr::from_str("13012702442141574024514112866712813523553321876510290446303561347565844930654").unwrap();
    let eval_qm = Fr::from_str("6363613431504422665441435540021253583148414748729550612486380209002057984394").unwrap();
    let eval_qo = Fr::from_str("16057866832337652851142304414708366836077577338023656646690877057031251541947").unwrap();
    let eval_qc = Fr::from_str("12177497208173170035464583425607209406245985123797536695060336171641250404407").unwrap();
    let eval_s1 = Fr::from_str("1606928575748882874942488864331180511279674792603033713048693169239812670017").unwrap();
    let eval_s2 = Fr::from_str("12502690277925689095499239281542937835831064619179570213662273016815222024218").unwrap();
    let eval_s3 = Fr::from_str("21714950310348017755786780913378098925832975432250486683702036755613488957178").unwrap();

    let y = Fr::from_str("18114356613745441247482203073267633537370200178307819717076375664896589995966").unwrap();

    let mut num = Fr::from_str("1");
    let y__8 = y.pow(8);
    num = num * (y__8);

    

    // num = num * (y.)

    


    // y_term
    // num_term
    // h0w80_term
    // c0Value_term
    // res_1

}
