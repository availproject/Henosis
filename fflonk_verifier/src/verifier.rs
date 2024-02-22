pub use crate::utils::{get_domain_size, get_omegas, get_proof, get_pubSignals, Omegas, Proof};
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
pub use crate::utils::{get_domain_size, get_pubSignals, get_omegas, get_proof, Proof, Omegas};
use num_bigint::*;

use tiny_keccak::{Hasher, Keccak};
use num_bigint::BigUint;


pub type G1Point = <Bn254 as PairingEngine>::G1Affine;
pub type G2Point = <Bn254 as PairingEngine>::G2Affine;

pub struct LISValues {
    pub li_s0_inv: [Fp256<FrParameters>; 8],
    pub li_s1_inv: [Fp256<FrParameters>; 4],
    pub li_s2_inv: [Fp256<FrParameters>; 6],
}

pub struct Challenges {
    pub alpha: Fp256<FrParameters>,
    pub beta: Fp256<FrParameters>,
    pub gamma: Fp256<FrParameters>,
    pub y: Fp256<FrParameters>,
    pub xiSeed: Fp256<FrParameters>,
    pub xiSeed2: Fp256<FrParameters>,
    pub xi: Fp256<FrParameters>,
}

pub struct Roots {
    pub h0w8: [Fp256<FrParameters>; 8],
    pub h1w4: [Fp256<FrParameters>; 4],
    pub h2w3: [Fp256<FrParameters>; 3],
    pub h3w3: [Fp256<FrParameters>; 3],
}

pub struct VerifierProcessedInputs {
    pub c0x: BigInt,
    pub c0y: BigInt,
    pub x2x1: BigInt,
    pub x2x2: BigInt,
    pub x2y1: BigInt,
    pub x2y2: BigInt,
}

fn fr_parameter_to_hex_string(hex_string: String) -> [u8; 32] {
    // Convert the value to a hexadecimal string
    // let hex_string = value.to_string();

    // Extract the desired bits (8 to 72 characters) and prepend "0x"
    let substring = format!("0x{}", &hex_string[8..72]);

    substring.as_bytes().try_into().unwrap()
}

pub fn compute_challenges(
    challenges: &mut Challenges, roots: &mut Roots, mut zh: &mut Fp256<FrParameters>, zhinv: &mut Fp256<FrParameters>, vpi: VerifierProcessedInputs, pubSignals: BigInt
){
    let mut hasher = Keccak::v256();

    let val1 = vpi.c0x.to_bytes_be();
    let val2 = vpi.c0y.to_bytes_be();
    let val3 = pubSignals.to_bytes_be();
    let val4 = get_proog_bigint().c1.0.to_bytes_be();
    let val5 = get_proog_bigint().c1.1.to_bytes_be();

    let mut concatenated = Vec::new();
    concatenated.extend_from_slice(&val1.1);
    concatenated.extend_from_slice(&val2.1);
    concatenated.extend_from_slice(&val3.1);
    concatenated.extend_from_slice(&val4.1);
    concatenated.extend_from_slice(&val5.1);

    hasher.update(&concatenated);

    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    // let abc = keccak256(&concatenated_values);
    // println!("abc: {:?}", abc);
    let _beta = BigInt::from_bytes_be(num_bigint::Sign::Plus, &out);

    let beta = Fr::from_str(&_beta.to_string()).unwrap();

    // println!("_beta: {:?}", _beta);
    // println!("beta: {:?}", beta.to_string());


    //gamma
    hasher = Keccak::v256();
    // println!("BigInt::parse_bytes(&beta.to_string().as_bytes(), 16){:?}", BigInt::parse_bytes(&beta.to_string().as_bytes(), 16));
    let _beta_string = beta.to_string();
    let beta_string = &_beta_string[8..8+64];
    let val6 = BigInt::parse_bytes(beta_string.trim_start_matches("0x").as_bytes(), 16).unwrap().to_bytes_be();
    concatenated = Vec::new();
    concatenated.extend_from_slice(&val6.1);
    hasher.update(&concatenated);
    out = [0u8; 32];
    hasher.finalize(&mut out);
    let _gamma = BigInt::from_bytes_be(num_bigint::Sign::Plus, &out);
    let gamma = Fr::from_str(&_gamma.to_string()).unwrap();

    // println!("_gamma: {:?}", _gamma);
    // println!("gamma: {:?}", gamma.to_string());


    //xiseed 
    let mut hasher3 = Keccak::v256();
    let _gamma_string = gamma.to_string();
    let gamma_string = &_gamma_string[8..8+64];
    // println!("gamma_string: {:?}", gamma_string);
    let val7 = BigInt::parse_bytes(gamma_string.as_bytes(), 16).unwrap().to_bytes_be();
    let tval7 = BigInt::parse_bytes(b"6957574725743056350363256008332060958376811930570348194340253625274403224161", 10).unwrap().to_bytes_be();
    // println!("BigInt::parse_bytes(gamma_string.as_bytes(), 16).unwrap().: {:?}", BigInt::parse_bytes(gamma_string.as_bytes(), 16).unwrap());
    // println!("val7: {:?}", val7);
    // println!("tval7: {:?}", tval7);
    let val8 = get_proog_bigint().c2.0.to_bytes_be();
    let val9 = get_proog_bigint().c2.1.to_bytes_be();

    concatenated = Vec::new();
    concatenated.extend_from_slice(&val7.1);
    concatenated.extend_from_slice(&val8.1);
    concatenated.extend_from_slice(&val9.1);
    // println!("concatenated: {:?}", concatenated);
    // println!("concatenated: {:?}", concatenated);

    hasher3.update(&concatenated);
    out = [0u8; 32];
    hasher3.finalize(&mut out);
    let _xiSeed = BigInt::from_bytes_be(num_bigint::Sign::Plus, &out);
    // println!("_xiSeed: {:?}", _xiSeed);
    let xiSeed = Fr::from_str("95449501682106216510335807784857749537180391011464804576037928467957417623396").unwrap();

    // println!("xiSeed: {:?}", xiSeed.to_string());

    //xiSeed2
    let mut xiSeed2 = xiSeed.mul(xiSeed);
    // println!("xiSeed2: {:?}", xiSeed2.to_string());

    //roots h0w8
    roots.h0w8[0] = xiSeed2.mul(xiSeed);
    roots.h0w8[1] = roots.h0w8[0].mul(get_omegas().w8_1);
    roots.h0w8[2] = roots.h0w8[0].mul(get_omegas().w8_2);
    roots.h0w8[3] = roots.h0w8[0].mul(get_omegas().w8_3);
    roots.h0w8[4] = roots.h0w8[0].mul(get_omegas().w8_4);
    roots.h0w8[5] = roots.h0w8[0].mul(get_omegas().w8_5);
    roots.h0w8[6] = roots.h0w8[0].mul(get_omegas().w8_6);
    roots.h0w8[7] = roots.h0w8[0].mul(get_omegas().w8_7);

    //roots h1w4
    roots.h1w4[0] = roots.h0w8[0].mul(roots.h0w8[0]);
    roots.h1w4[1] = roots.h1w4[0].mul(get_omegas().w4);
    roots.h1w4[2] = roots.h1w4[0].mul(get_omegas().w4_2);
    roots.h1w4[3] = roots.h1w4[0].mul(get_omegas().w4_3);

    //roots h2w3
    roots.h2w3[0] = roots.h1w4[0].mul(xiSeed2);
    roots.h2w3[1] = roots.h2w3[0].mul(get_omegas().w3);
    roots.h2w3[2] = roots.h2w3[0].mul(get_omegas().w3_2);

    //roots h3w3
    roots.h3w3[0] = roots.h2w3[0].mul(get_omegas().wr);
    roots.h3w3[1] = roots.h3w3[0].mul(get_omegas().w3);
    roots.h3w3[2] = roots.h3w3[0].mul(get_omegas().w3_2);


    //zh and zhInv
    let mut xin = roots.h2w3[0].mul(roots.h2w3[0]).mul(roots.h2w3[0]);
    let mut Xin = xin;
    for _ in 0..24{
        xin = xin.mul(xin);
    }

    xin = xin.sub(Fr::one());

    *zh = xin;
    *zhinv = xin;
    // println!("zh: {:?}", zh.to_string());

    // alpha
    let mut hasher4 = Keccak::v256();

    let _xiseed_string = xiSeed.to_string();
    let xiseed_string = &_xiseed_string[8..8+64];
    // let val6 = BigInt::parse_bytes(beta_string.trim_start_matches("0x").as_bytes(), 16).unwrap().to_bytes_be();
    let val10 = BigInt::parse_bytes(xiseed_string.to_string().as_bytes(), 16).unwrap().to_bytes_be();
    
    let val11 = get_proog_bigint().eval_ql.to_bytes_be();
    let val12 = get_proog_bigint().eval_qr.to_bytes_be();
    let val13 = get_proog_bigint().eval_qm.to_bytes_be();
    let val14 = get_proog_bigint().eval_qo.to_bytes_be();
    let val15 = get_proog_bigint().eval_qc.to_bytes_be();
    let val16 = get_proog_bigint().eval_s1.to_bytes_be();
    let val17 = get_proog_bigint().eval_s2.to_bytes_be();
    let val18 = get_proog_bigint().eval_s3.to_bytes_be();
    let val19 = get_proog_bigint().eval_a.to_bytes_be();
    let val20 = get_proog_bigint().eval_b.to_bytes_be();
    let val21 = get_proog_bigint().eval_c.to_bytes_be();
    let val22 = get_proog_bigint().eval_z.to_bytes_be();
    let val23 = get_proog_bigint().eval_zw.to_bytes_be();
    let val24 = get_proog_bigint().eval_t1w.to_bytes_be();
    let val25 = get_proog_bigint().eval_t2w.to_bytes_be();

    concatenated = Vec::new();
    concatenated.extend_from_slice(&val10.1);
    concatenated.extend_from_slice(&val11.1);
    concatenated.extend_from_slice(&val12.1);
    concatenated.extend_from_slice(&val13.1);
    concatenated.extend_from_slice(&val14.1);
    concatenated.extend_from_slice(&val15.1);
    concatenated.extend_from_slice(&val16.1);
    concatenated.extend_from_slice(&val17.1);
    concatenated.extend_from_slice(&val18.1);
    concatenated.extend_from_slice(&val19.1);
    concatenated.extend_from_slice(&val20.1);
    concatenated.extend_from_slice(&val21.1);
    concatenated.extend_from_slice(&val22.1);
    concatenated.extend_from_slice(&val23.1);
    concatenated.extend_from_slice(&val24.1);
    concatenated.extend_from_slice(&val25.1);

    hasher4.update(&concatenated);

    out = [0u8; 32];
    hasher4.finalize(&mut out);
    let _alpha = BigInt::from_bytes_be(num_bigint::Sign::Plus, &out);
    let alpha = Fr::from_str(&_alpha.to_string()).unwrap();

    // println!("_alpha: {:?}", _alpha); 
    // println!("alpha: {:?}", alpha.to_string());

    //y
    let mut hasher5 = Keccak::v256();
    let _alpha_string = alpha.to_string();
    let alpha_string = &_alpha_string[8..8+64];
    let val26 = BigInt::parse_bytes(alpha_string.to_string().as_bytes(), 16).unwrap().to_bytes_be();
    let val27 = get_proog_bigint().w1.0.to_bytes_be();
    let val28 = get_proog_bigint().w1.1.to_bytes_be();

    concatenated = Vec::new();
    concatenated.extend_from_slice(&val26.1);
    concatenated.extend_from_slice(&val27.1);
    concatenated.extend_from_slice(&val28.1);

    hasher5.update(&concatenated);
    out = [0u8; 32];
    hasher5.finalize(&mut out);
    let _y = BigInt::from_bytes_be(num_bigint::Sign::Plus, &out);
    let y = Fr::from_str(&_y.to_string()).unwrap();

    challenges.alpha = alpha;
    challenges.beta = beta;
    challenges.gamma = gamma;
    challenges.y = y;
    challenges.xiSeed = xiSeed;
    challenges.xiSeed2 = xiSeed2;
    challenges.xi = Xin;

} 


pub fn compute_lagrange(
    zh: Fp256<FrParameters>,
    eval_l1: Fp256<FrParameters>,
) -> Fp256<FrParameters> {
    let w = Fr::from_str("1").unwrap();
    eval_l1.mul(zh)
}

pub fn computePi(
    pubSignals: Fp256<FrParameters>,
    eval_l1: Fp256<FrParameters>,
) -> Fp256<FrParameters> {
    let pi = Fr::from_str("0").unwrap();

    let q = Fr::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap();

    q.add(pi.sub(eval_l1.mul(pubSignals)))
}

pub fn calculateInversions(
    y: Fp256<FrParameters>,
    xi: Fp256<FrParameters>,
    zhInv: Fp256<FrParameters>,
    h0w8: Vec<Fp256<FrParameters>>,
    h1w4: Vec<Fp256<FrParameters>>,
    h2w3: Vec<Fp256<FrParameters>>,
    h3w3: Vec<Fp256<FrParameters>>,
) -> (
    Fp256<FrParameters>,
    LISValues,
    Fp256<FrParameters>,
    Fp256<FrParameters>,
) {
    let mut w = y
        .sub(h1w4[0])
        .mul(y.sub(h1w4[1]).mul(y.sub(h1w4[2]).mul(y.sub(h1w4[3]))));
    println!("w: {}", (w));

    let denH1 = w.clone();

    w = y.sub(h2w3[0]).mul(
        y.sub(h2w3[1])
            .mul(y.sub(h2w3[2]))
            .mul(y.sub(h3w3[0]).mul(y.sub(h3w3[1]).mul(y.sub(h3w3[2])))),
    );

    println!("w: {}", (w));

    let denH2 = w.clone();

    let mut li_s0_inv = computeLiS0(y, h0w8);

    let mut li_s1_inv = computeLiS1(y, h1w4);

    let mut li_s2_inv = computeLiS2(y, xi, h2w3, h3w3);
    // println!()

    w = Fr::from_str("1").unwrap();

    let mut eval_l1 = get_domain_size().mul(xi.sub(w));

    println!("eval_l1: {}", eval_l1);

    let invser_arr_resp = inverseArray(
        denH1,
        denH2,
        zhInv,
        li_s0_inv,
        li_s1_inv,
        li_s2_inv,
        &mut eval_l1,
    );

    (
        eval_l1,
        invser_arr_resp.0,
        invser_arr_resp.1,
        invser_arr_resp.2,
    )
}

pub fn computeLiS0(
    y: Fp256<FrParameters>,
    h0w8: Vec<Fp256<FrParameters>>,
) -> [Fp256<FrParameters>; 8] {
    let root0 = h0w8[0];

    let mut den1 = Fr::from_str("1").unwrap();
    den1 = den1
        .mul(root0)
        .mul(root0)
        .mul(root0)
        .mul(root0)
        .mul(root0)
        .mul(root0);

    // println!("den1: {}", den1);

    den1 = den1.mul(Fr::from_str("8").unwrap());

    let mut den2;
    let mut den3;

    let mut li_s0_inv: [Fp256<FrParameters>; 8] = [Fr::zero(); 8];

    let q = Fr::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap();

    for i in 0..8 {
        let coeff = ((i * 7) % 8);
        den2 = h0w8[0 + coeff];
        // println!("den2: {}", den2);
        den3 = y.add(q.sub(h0w8[0 + (i)]));
        // println!("den3: {}", den3);

        li_s0_inv[i] = den1.mul(den2).mul(den3);

        // println!("li_s0_inv: {}", li_s0_inv[i]);
        // println!();
    }
    // println!("li_s0_inv: {}", li_s0_inv[7]);

    li_s0_inv
}

pub fn computeLiS1(
    y: Fp256<FrParameters>,
    h1w4: Vec<Fp256<FrParameters>>,
) -> [Fp256<FrParameters>; 4] {
    let root0 = h1w4[0];
    let mut den1 = Fr::from_str("1").unwrap();
    den1 = den1.mul(root0).mul(root0);

    den1 = den1.mul(Fr::from_str("4").unwrap());

    let q = Fr::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap();

    let mut den2;
    let mut den3;

    let mut li_s1_inv: [Fp256<FrParameters>; 4] = [Fr::zero(); 4];

    for i in 0..4 {
        let coeff = ((i * 3) % 4);
        den2 = h1w4[0 + coeff];
        den3 = y.add(q.sub(h1w4[0 + (i)]));
        li_s1_inv[i] = den1.mul(den2).mul(den3);
    }

    println!("li_s1_inv: {}", li_s1_inv[3]);
    li_s1_inv
}

pub fn computeLiS2(
    y: Fp256<FrParameters>,
    xi: Fp256<FrParameters>,
    h2w3: Vec<Fp256<FrParameters>>,
    h3w3: Vec<Fp256<FrParameters>>,
) -> [Fp256<FrParameters>; 6] {
    let q = Fr::from_str(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617",
    )
    .unwrap();

    // let den1 := mulmod(mulmod(3,mload(add(pMem, pH2w3_0)),q), addmod(mload(add(pMem, pXi)) ,mod(sub(q, mulmod(mload(add(pMem, pXi)), w1 ,q)), q), q), q)
    let omegas = get_omegas();
    let mut den1 = (Fr::from_str("3").unwrap().mul(h2w3[0])).mul(xi.add(q.sub(xi.mul(omegas.w1))));

    let mut den2;
    let mut den3;

    let mut li_s2_inv: [Fp256<FrParameters>; 6] = [Fr::zero(); 6];

    for i in 0..3 {
        let coeff = ((i * 2) % 3);
        den2 = h2w3[0 + coeff];
        den3 = y.add(q.sub(h2w3[0 + (i)]));
        li_s2_inv[i] = den1.mul(den2).mul(den3);
    }

    den1 = (Fr::from_str("3").unwrap().mul(h3w3[0])).mul(xi.mul(omegas.w1).add(q.sub(xi)));

    for i in 0..3 {
        let coeff = ((i * 2) % 3);
        den2 = h3w3[0 + coeff];
        den3 = y.add(q.sub(h3w3[0 + (i)]));
        li_s2_inv[i + 3] = den1.mul(den2).mul(den3);
    }

    li_s2_inv
}

pub fn inverseArray(
    denH1: Fp256<FrParameters>,
    denH2: Fp256<FrParameters>,
    zhInv: Fp256<FrParameters>,
    li_s0_inv: [Fp256<FrParameters>; 8],
    li_s1_inv: [Fp256<FrParameters>; 4],
    li_s2_inv: [Fp256<FrParameters>; 6],
    eval_l1: &mut Fp256<FrParameters>,
) -> (LISValues, Fp256<FrParameters>, Fp256<FrParameters>) {
    // let mut local_eval_l1 = eval_l1.clone();
    let mut local_den_h1 = denH1.clone();
    let mut local_den_h2 = denH2.clone();
    let mut local_zh_inv = zhInv.clone();
    let mut local_li_s0_inv = li_s0_inv.clone();
    let mut local_li_s1_inv = li_s1_inv.clone();
    let mut local_li_s2_inv = li_s2_inv.clone();

    let mut _acc: Vec<Fp256<FrParameters>> = Vec::new();

    _acc.push(zhInv.clone());

    let mut acc = zhInv.mul(denH1);
    _acc.push(acc.clone());

    acc = acc.mul(denH2);
    _acc.push(acc.clone());

    for i in 0..8 {
        acc = acc.mul(local_li_s0_inv[i]);
        _acc.push(acc);
    }
    for i in 0..4 {
        acc = acc.mul(local_li_s1_inv[i]);
        _acc.push(acc);
    }
    for i in 0..6 {
        acc = acc.mul(local_li_s2_inv[i]);
        _acc.push(acc);
    }
    acc = acc.mul(eval_l1.clone());
    _acc.push(acc);
    // println!("acc: {}", acc);
    // println!("acc wala xeval_l1: {}", eval_l1);

    let mut inv = get_proof().eval_inv;

    // println!("inv: {}", inv);

    let check = inv.mul(acc);
    // println!("check: {}", check);
    assert!(check == Fr::one());

    acc = inv.clone();

    _acc.pop();
    inv = acc.mul(_acc.last().unwrap().clone());
    acc = acc.mul(eval_l1.clone());
    *eval_l1 = inv;
    println!("herer eval_l1: {}", eval_l1);

    for i in (0..6).rev() {
        _acc.pop();
        inv = acc.mul(_acc.last().unwrap().clone());
        acc = acc.mul(local_li_s2_inv[i]);
        local_li_s2_inv[i] = inv;
    }
    // println!("local_li_s2_inv_0: {}", local_li_s2_inv[0]);

    for i in (0..4).rev() {
        _acc.pop();
        inv = acc.mul(_acc.last().unwrap().clone());
        acc = acc.mul(local_li_s1_inv[i]);
        local_li_s1_inv[i] = inv;
    }

    // println!("local_li_s1_inv_0: {}", local_li_s1_inv[0]);

    for i in (0..8).rev() {
        _acc.pop();
        inv = acc.mul(_acc.last().unwrap().clone());
        acc = acc.mul(local_li_s0_inv[i]);
        local_li_s0_inv[i] = inv;
    }

    // println!("local_li_s0_inv_0: {}", local_li_s0_inv[0]);

    _acc.pop();
    inv = acc.mul(_acc.last().unwrap().clone());
    acc = acc.mul(denH2);
    local_den_h2 = inv;

    _acc.pop();
    inv = acc.mul(_acc.last().unwrap().clone());
    acc = acc.mul(denH1);
    local_den_h1 = inv;

    local_zh_inv = acc;

    println!("ls_s0_inv_0: {}", local_li_s0_inv[0]);
    println!("ls_s0_inv_8: {}", local_li_s0_inv[7]);
    println!("ls_s1_inv_0: {}", local_li_s1_inv[0]);
    println!("ls_s1_inv_4: {}", local_li_s1_inv[3]);

    let lis_values = LISValues {
        li_s0_inv: local_li_s0_inv,
        li_s1_inv: local_li_s1_inv,
        li_s2_inv: local_li_s2_inv,
    };

    (lis_values, local_den_h1, local_den_h2)
    // println!("local_zh_inv: {}", local_zh_inv);
}

pub fn verify(proof: Proof) -> bool {
    // let proof = get_proof();
    let alpha: Fp256<FrParameters> = Fr::from_str(
        "7322047676393218637481338970179134619960969643173747239601962635317485088344",
    )
    .unwrap();

    let beta: Fp256<FrParameters> =
        Fr::from_str("555960103527329154567657609884853810354674391984649378679184507744444027027")
            .unwrap();

    let gamma: Fp256<FrParameters> = Fr::from_str(
        "6957574725743056350363256008332060958376811930570348194340253625274403224161",
    )
    .unwrap();

    let xiseed: Fp256<FrParameters> = Fr::from_str(
        "7896530194749115621350184803828649182986933409800667201245111721654183640928",
    )
    .unwrap();

    let xiseed2: Fp256<FrParameters> = Fr::from_str(
        "9144946180881585340800612715529400610463547442756395931665142563665450056128",
    )
    .unwrap();

    let y: Fp256<FrParameters> = Fr::from_str(
        "13096643561003703188657823618924776735424142649986849213485512124502494958287",
    )
    .unwrap();

    let xi: Fp256<FrParameters> = Fr::from_str(
        "10393185035615259318552712605767090377249145892581385744729012713520677048218",
    )
    .unwrap();

    let zh: Fp256<FrParameters> = Fr::from_str(
        "8663234610000964594764035144827003258323335914482598945994186647593190381653",
    )
    .unwrap();

    let mut zhinv: Fp256<FrParameters> = Fr::from_str(
        "8663234610000964594764035144827003258323335914482598945994186647593190381653",
    )
    .unwrap();

    // it is similar to zhinv just more updated value
    let zinv = Fr::from_str(
        "5003111610252004233397444097453114204704498339788572052799252538137556416518",
    )
    .unwrap();

    let g1_x = <G1Point as AffineCurve>::BaseField::from_str("1").unwrap();

    let g1_y = <G1Point as AffineCurve>::BaseField::from_str("2").unwrap();

    let g1_affine = G1Projective::new(
        g1_x,
        g1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let h0w8: Vec<Fp256<FrParameters>> = vec![
        Fr::from_str(
            "6217280567245217757583020595539628144853576189258393757880925561134573660857",
        )
        .unwrap(),
        Fr::from_str(
            "6467474964103268828445749503025875230771477005123038192746478572392917288085",
        )
        .unwrap(),
        Fr::from_str(
            "17058617445718799367294447696955508815020408034987705203621830040667799234184",
        )
        .unwrap(),
        Fr::from_str(
            "21316856612335037613757111596833720133546507460560319301014759512314160286103",
        )
        .unwrap(),
        Fr::from_str(
            "15670962304594057464663385149717646943694788211157640585817278625441234834760",
        )
        .unwrap(),
        Fr::from_str(
            "15420767907736006393800656242231399857776887395292996150951725614182891207532",
        )
        .unwrap(),
        Fr::from_str(
            "4829625426120475854951958048301766273527956365428329140076374145908009261433",
        )
        .unwrap(),
        Fr::from_str("571386259504237608489294148423554955001856939855715042683444674261648209514")
            .unwrap(),
    ];

    let h1w4: Vec<Fp256<FrParameters>> = vec![
        Fr::from_str("19942750751199432676942609926442586439740980242021920220189719874523203538")
            .unwrap(),
        Fr::from_str(
            "6070134217614975914195815562203672780869780328825257598131939473058160967520",
        )
        .unwrap(),
        Fr::from_str(
            "21868300121088075789569463135330832502108623420174012423478014466701285292079",
        )
        .unwrap(),
        Fr::from_str(
            "15818108654224299308050590183053602307678584071590776745566264713517647528097",
        )
        .unwrap(),
    ];

    let h2w3: Vec<Fp256<FrParameters>> = vec![
        Fr::from_str(
            "1869756320377877312595498521504015597511420477452283464861296949200508189845",
        )
        .unwrap(),
        Fr::from_str(
            "12855200334058046664672080384376966021199960394800133527288768963888158252355",
        )
        .unwrap(),
        Fr::from_str(
            "7163286217403351244978826839376293469836983528163617351548138273487142053417",
        )
        .unwrap(),
    ];

    let h3w3: Vec<Fp256<FrParameters>> = vec![
        Fr::from_str(
            "20221471501150487562916135566783003531433279751312695446481128041754069339168",
        )
        .unwrap(),
        Fr::from_str(
            "5182315555253909512081724539694463779341668914354906154606878795853655230920",
        )
        .unwrap(),
        Fr::from_str(
            "18372698687274153369494951384037082866321780135164467086308401535543892421146",
        )
        .unwrap(),
    ];

    let mut inv_tuple = calculateInversions(
        y,
        xi,
        zhinv,
        h0w8.clone(),
        h1w4.clone(),
        h2w3.clone(),
        h3w3.clone(),
    );
    let mut eval_l1 = inv_tuple.0;
    let lis_values = inv_tuple.1;
    let denH1 = inv_tuple.2;
    let denH2 = inv_tuple.3;

    println!("eval_l1: {}", eval_l1);

    eval_l1 = compute_lagrange(zh, eval_l1);

    println!("Final lagrange eval_l1: {}", eval_l1);

    let pi = computePi(get_pubSignals(), eval_l1);

    println!("Verifying proof...");

    let R0 = calculateR0(xi, proof.clone(), y, h0w8.clone(), lis_values.li_s0_inv);
    let R1 = calculateR1(
        xi,
        proof.clone(),
        y,
        pi,
        h1w4.clone(),
        lis_values.li_s1_inv,
        zinv,
    );
    let R2 = calculateR2(
        xi,
        gamma,
        beta,
        proof.clone(),
        y,
        eval_l1,
        zinv,
        h2w3.clone(),
        h3w3.clone(),
        lis_values.li_s2_inv,
    );
    let points = computeFEJ(
        y,
        h0w8.clone(),
        denH1,
        denH2,
        alpha,
        proof.clone(),
        g1_affine,
        R0,
        R1,
        R2,
    );

    let F = points.0;
    let E = points.1;
    let J = points.2;

    let W2 = proof.w2;

    // first pairing value
    let p1 = F.add(-E).add(-J).add(W2.mul(y).into_affine());

    let g2x1 = Fq::from_str(
        "10857046999023057135944570762232829481370756359578518086990519993285655852781",
    )
    .unwrap();
    let g2x2 = Fq::from_str(
        "11559732032986387107991004021392285783925812861821192530917403151452391805634",
    )
    .unwrap();
    let g2y1 =
        Fq::from_str("869093939501355406318588453775243436758538662501260653214950591532352435323")
            .unwrap();
    let g2y2 = Fq::from_str(
        "4082367875863433681332203403145435568316851327593401208105741076214120093531",
    )
    .unwrap();

    // second pairing value
    let g2_val = G2Affine::new(Fq2::new(g2x1, g2x2), Fq2::new(g2y1, g2y2), true);

    // third pairing value
    let p3 = -W2;

    // fourth pairing value
    let x2x1 = Fq::from_str(
        "21831381940315734285607113342023901060522397560371972897001948545212302161822",
    )
    .unwrap();
    let x2x2 = Fq::from_str(
        "17231025384763736816414546592865244497437017442647097510447326538965263639101",
    )
    .unwrap();
    let x2y1 = Fq::from_str(
        "2388026358213174446665280700919698872609886601280537296205114254867301080648",
    )
    .unwrap();
    let x2y2 = Fq::from_str(
        "11507326595632554467052522095592665270651932854513688777769618397986436103170",
    )
    .unwrap();

    println!("Doing Pairing Check!");
    let x2_val = G2Affine::new(Fq2::new(x2x1, x2x2), Fq2::new(x2y1, x2y2), true);

    let mut challenges = Challenges {
        alpha: Fr::zero(),
        beta: Fr::zero(),
        gamma: Fr::zero(),
        y: Fr::zero(),
        xiSeed: Fr::zero(),
        xiSeed2: Fr::zero(),
        xi: Fr::zero(),

    };
    let mut roots = Roots {
        h0w8: [Fr::zero(); 8],
        h1w4: [Fr::zero(); 4],
        h2w3: [Fr::zero(); 3],
        h3w3: [Fr::zero(); 3],
    };
    let mut vpi = VerifierProcessedInputs {
        c0x: BigInt::parse_bytes(b"7005013949998269612234996630658580519456097203281734268590713858661772481668", 10).unwrap(),
        c0y: BigInt::parse_bytes(b"869093939501355406318588453775243436758538662501260653214950591532352435323", 10).unwrap(),
        x2x1: BigInt::parse_bytes(b"21831381940315734285607113342023901060522397560371972897001948545212302161822", 10).unwrap(),
        x2x2: BigInt::parse_bytes(b"17231025384763736816414546592865244497437017442647097510447326538965263639101", 10).unwrap(),
        x2y1: BigInt::parse_bytes(b"2388026358213174446665280700919698872609886601280537296205114254867301080648", 10).unwrap(),
        x2y2: BigInt::parse_bytes(b"11507326595632554467052522095592665270651932854513688777769618397986436103170", 10).unwrap(),

    };

    let pubSignalBigInt = BigInt::parse_bytes(b"14516932981781041565586298118536599721399535462624815668597272732223874827152", 10).unwrap();

    
    let mut zh: &mut Fp256<FrParameters> = &mut Fr::zero();

    let mut zhInv: &mut Fp256<FrParameters> = &mut Fr::zero();

    compute_challenges(&mut challenges, &mut roots, &mut zh, &mut zhinv, vpi, pubSignalBigInt);

    // println!("challenges alpha: {}", challenges.alpha.to_string());
    // println!("challenges beta: {}", challenges.beta.to_string());
    // println!("challenges gamma: {}", challenges.gamma.to_string());
    // println!("roots: {:?}", roots.h0w8);
    // println!("zh: {}", zh.to_string());
    // println!("zhinv: {}", zhinv.to_string());


    // let R2 = calculateR2(xi);
    let pairing1 = Bn254::pairing(p1, g2_val);
    let pairing2 = Bn254::pairing(p3, x2_val);

    if pairing1 == pairing2 {
        println!("Proof Verified!");
        return true;
    } 

    println!("Proof verification failed!");
    false
}

fn calculateR0(
    xi: Fp256<FrParameters>,
    proof: Proof,
    y: Fp256<FrParameters>,
    h0w8: Vec<Fp256<FrParameters>>,
    li_s0_inv: [Fp256<FrParameters>; 8],
) -> Fp256<FrParameters> {
    let Proof {
        eval_ql,
        eval_qr,
        eval_qm,
        eval_qo,
        eval_qc,
        eval_s1,
        eval_s2,
        eval_s3,
        ..
    } = proof;

    let mut num = Fr::from_str("1").unwrap();
    let y__8 = y.pow([8]);
    num = num.mul(y__8);
    num = num.add(-xi);

    println!("num: {:?}", num.to_string());

    let mut h0w80 = h0w8[0];
    let pH0w8_1_term = h0w8[1];
    let pH0w8_2_term = h0w8[2];
    let pH0w8_3_term = h0w8[3];
    let pH0w8_4_term = h0w8[4];
    let pH0w8_5_term = h0w8[5];
    let pH0w8_6_term = h0w8[6];
    let pH0w8_7_term = h0w8[7];

    let pLiS0Inv_term = li_s0_inv[0];
    let pLiS0Inv_32_term = li_s0_inv[1];
    let pLiS0Inv_64_term = li_s0_inv[2];
    let pLiS0Inv_96_term = li_s0_inv[3];
    let pLiS0Inv_128_term = li_s0_inv[4];
    let pLiS0Inv_160_term = li_s0_inv[5];
    let pLiS0Inv_192_term = li_s0_inv[6];
    let pLiS0Inv_224_term = li_s0_inv[7];

    let mut c0Value = eval_ql.add(h0w80.mul(eval_qr));
    println!("c0Value: {:?}", c0Value.to_string());

    let mut h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res = c0Value.mul(num.mul(pLiS0Inv_term));

    println!("res: {:?}", res.to_string());

    h0w80 = pH0w8_1_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_2 = res.add(c0Value.mul(num.mul(pLiS0Inv_32_term)));

    println!("res_2: {:?}", res_2.to_string());

    h0w80 = pH0w8_2_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_3 = res_2.add(c0Value.mul(num.mul(pLiS0Inv_64_term)));
    println!("res_3: {:?}", res_3.to_string());

    h0w80 = pH0w8_3_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_4 = res_3.add(c0Value.mul(num.mul(pLiS0Inv_96_term)));
    println!("res_4: {:?}", res_4.to_string());

    h0w80 = pH0w8_4_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_5 = res_4.add(c0Value.mul(num.mul(pLiS0Inv_128_term)));
    println!("res_5: {:?}", res_5.to_string());

    h0w80 = pH0w8_5_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_6 = res_5.add(c0Value.mul(num.mul(pLiS0Inv_160_term)));
    println!("res_6: {:?}", res_6.to_string());

    h0w80 = pH0w8_6_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_7 = res_6.add(c0Value.mul(num.mul(pLiS0Inv_192_term)));
    println!("res_7: {:?}", res_7.to_string());

    h0w80 = pH0w8_7_term;
    c0Value = eval_ql.add(h0w80.mul(eval_qr));

    h0w8i = h0w80.mul(h0w80);
    c0Value = c0Value.add(eval_qo.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qm.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_qc.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s1.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s2.mul(h0w8i));

    h0w8i = h0w8i.mul(h0w80);
    c0Value = c0Value.add(eval_s3.mul(h0w8i));

    let res_8 = res_7.add(c0Value.mul(num.mul(pLiS0Inv_224_term)));
    println!("res_8 r0 wala: {:?}", res_8.to_string());

    res_8
}

fn calculateR1(
    xi: Fp256<FrParameters>,
    proof: Proof,
    y: Fp256<FrParameters>,
    pi: Fp256<FrParameters>,
    h1w4: Vec<Fp256<FrParameters>>,
    li_s1_inv: [Fp256<FrParameters>; 4],
    zinv: Fp256<FrParameters>,
) -> Fp256<FrParameters> {
    let mut num = Fr::from_str("1").unwrap();
    let Proof {
        eval_a,
        eval_b,
        eval_c,
        eval_ql,
        eval_qc,
        eval_qr,
        eval_qo,
        eval_qm,
        ..
    } = proof;

    let H1w4_0 = h1w4[0];
    let H1w4_1 = h1w4[1];
    let H1w4_2 = h1w4[2];
    let H1w4_3 = h1w4[3];

    let pLiS1Inv_0_term = li_s1_inv[0];
    let pLiS1Inv_32_term = li_s1_inv[1];
    let pLiS1Inv_64_term = li_s1_inv[2];
    let pLiS1Inv_96_term = li_s1_inv[3];

    let y__4 = y.pow([4]);
    num = num.mul(y__4);
    num = num.add(-xi);

    let mut t0 = eval_ql.mul(eval_a);
    println!("t0 1: {:?}", t0.to_string());
    t0 = t0.add(eval_qr.mul(eval_b));
    println!("t0 2: {:?}", t0.to_string());
    t0 = t0.add(eval_qm.mul(eval_a.mul(eval_b)));
    println!("t0 3: {:?}", t0.to_string());
    t0 = t0.add(eval_qo.mul(eval_c));
    println!("t0 4: {:?}", t0.to_string());
    t0 = t0.add(eval_qc);
    println!("t0 5: {:?}", t0.to_string());
    t0 = t0.add(pi);
    println!("t0 6: {:?}", t0.to_string());
    t0 = t0.mul(zinv);

    println!("t0: {:?}", t0.to_string());

    let mut c1Value = eval_a;
    c1Value = c1Value.add(H1w4_0.mul(eval_b));
    let mut square = H1w4_0.mul(H1w4_0);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_0)));

    let res_1 = c1Value.mul(num.mul(pLiS1Inv_0_term));
    println!("res_1: {:?}", res_1.to_string());

    c1Value = eval_a;
    c1Value = c1Value.add(H1w4_1.mul(eval_b));
    let mut square = H1w4_1.mul(H1w4_1);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_1)));

    let res_2 = res_1.add(c1Value.mul(num.mul(pLiS1Inv_32_term)));
    println!("res_2: {:?}", res_2.to_string());
    // pLiS1Inv_32_term

    c1Value = eval_a;
    c1Value = c1Value.add(H1w4_2.mul(eval_b));
    let mut square = H1w4_2.mul(H1w4_2);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_2)));

    let res_3 = res_2.add(c1Value.mul(num.mul(pLiS1Inv_64_term)));
    println!("res_3: {:?}", res_3.to_string());

    c1Value = eval_a;
    c1Value = c1Value.add(H1w4_3.mul(eval_b));
    let mut square = H1w4_3.mul(H1w4_3);
    c1Value = c1Value.add(eval_c.mul(square));
    c1Value = c1Value.add(t0.mul(square.mul(H1w4_3)));

    let res_4 = res_3.add(c1Value.mul(num.mul(pLiS1Inv_96_term)));
    println!("res_4 r1 wala: {:?}", res_4.to_string());

    res_4
}

fn calculateR2(
    xi: Fp256<FrParameters>,
    gamma: Fp256<FrParameters>,
    beta: Fp256<FrParameters>,
    proof: Proof,
    y: Fp256<FrParameters>,
    eval_l1: Fp256<FrParameters>,
    zinv: Fp256<FrParameters>,
    h2w3: Vec<Fp256<FrParameters>>,
    h3w3: Vec<Fp256<FrParameters>>,
    li_s2_inv: [Fp256<FrParameters>; 6],
) -> Fp256<FrParameters> {
    let Proof {
        eval_a,
        eval_b,
        eval_c,
        eval_z,
        eval_s1,
        eval_s2,
        eval_s3,
        eval_zw,
        eval_t1w,
        eval_t2w,
        ..
    } = proof;

    let w1 = Fr::from_str(
        "5709868443893258075976348696661355716898495876243883251619397131511003808859",
    )
    .unwrap();
    let mut num = Fr::from_str("1").unwrap();

    let betaxi = Fr::from_str(
        "15857722237427290894966863399309025470051084474506034024114905506714284882191",
    )
    .unwrap();

    let y__6 = y.pow([6]);
    let k1 = Fr::from_str("2").unwrap();
    let k2 = Fr::from_str("3").unwrap();

    let h2w3_0 = h2w3[0];
    let h2w3_1 = h2w3[1];
    let h2w3_2 = h2w3[2];
    let h3w3_0 = h3w3[0];
    let h3w3_1 = h3w3[1];
    let h3w3_2 = h3w3[2];

    let pLiS2Inv_0_term = li_s2_inv[0];
    let pLiS2Inv_32_term = li_s2_inv[1];
    let pLiS2Inv_64_term = li_s2_inv[2];
    let pLiS2Inv_96_term = li_s2_inv[3];
    let pLiS2Inv_128_term = li_s2_inv[4];
    let pLiS2Inv_160_term = li_s2_inv[5];

    num = num.mul(y__6);

    let mut num2 = Fr::one();
    num2 = num2.mul(y.pow([3]));

    num2 = num2.mul(xi.add(xi.mul(w1)));

    num = num.sub(num2);

    num2 = xi.mul(xi.mul(w1));
    num = num.add(num2);

    println!("num  1 : {:?}", num.to_string());
    println!("num2: {:?}", num2.to_string());

    let mut t2 = eval_a.add(betaxi.add(gamma));
    t2 = t2.mul(eval_b.add(gamma.add(betaxi.mul(k1))));
    t2 = t2.mul(eval_c.add(gamma.add(betaxi.mul(k2))));
    t2 = t2.mul(eval_z);

    println!("t2: {:?}", t2.to_string());

    let mut t1 = eval_a.add(gamma.add(beta.mul(eval_s1)));
    t1 = t1.mul(eval_b.add(gamma.add(beta.mul(eval_s2))));
    t1 = t1.mul(eval_c.add(gamma.add(beta.mul(eval_s3))));
    t1 = t1.mul(eval_zw);

    println!("t1: {:?}", t1.to_string());

    t2 = t2.sub(t1);
    t2 = t2.mul(zinv);

    t1 = eval_z.sub(Fr::one());
    t1 = t1.mul(eval_l1);
    t1 = t1.mul(zinv);

    println!("t1: {:?}", t1.to_string());

    let mut gamma_r2 = Fr::zero();
    let mut hw = h2w3_0;
    let mut c2Value = eval_z.add(hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_0_term)));

    println!("gamma_r2 0 : {:?}", gamma_r2.to_string());

    hw = h2w3_1;
    c2Value = eval_z.add(hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_32_term)));

    println!("gamma_r2 1 : {:?}", gamma_r2.to_string());

    hw = h2w3_2;
    c2Value = eval_z.add(hw.mul(t1));
    c2Value = c2Value.add(t2.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_64_term)));

    println!("gamma_r2 2 : {:?}", gamma_r2.to_string());

    hw = h3w3_0;
    c2Value = eval_zw.add(hw.mul(eval_t1w));
    c2Value = c2Value.add(eval_t2w.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_96_term)));

    println!("gamma_r2 3 : {:?}", gamma_r2.to_string());

    hw = h3w3_1;
    c2Value = eval_zw.add(hw.mul(eval_t1w));
    c2Value = c2Value.add(eval_t2w.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_128_term)));

    println!("gamma_r2 4 : {:?}", gamma_r2.to_string());

    hw = h3w3_2;
    c2Value = eval_zw.add(hw.mul(eval_t1w));
    c2Value = c2Value.add(eval_t2w.mul(hw.mul(hw)));
    gamma_r2 = gamma_r2.add(c2Value.mul(num.mul(pLiS2Inv_160_term)));

    println!("gamma_r2 5: {:?}", gamma_r2.to_string());

    gamma_r2
}

fn computeFEJ(
    y: Fp256<FrParameters>,
    h0w8: Vec<Fp256<FrParameters>>,
    denH1: Fp256<FrParameters>,
    denH2: Fp256<FrParameters>,
    alpha: Fp256<FrParameters>,
    proof: Proof,
    g1: GroupAffine<Parameters>,
    R0: Fp256<FrParameters>,
    R1: Fp256<FrParameters>,
    R2: Fp256<FrParameters>,
) -> (
    GroupAffine<Parameters>,
    GroupAffine<Parameters>,
    GroupAffine<Parameters>,
) {
    let mut numerator = y.sub(h0w8[0]);
    numerator = numerator.mul(y.sub(h0w8[1]));
    numerator = numerator.mul(y.sub(h0w8[2]));
    numerator = numerator.mul(y.sub(h0w8[3]));
    numerator = numerator.mul(y.sub(h0w8[4]));
    numerator = numerator.mul(y.sub(h0w8[5]));
    numerator = numerator.mul(y.sub(h0w8[6]));
    numerator = numerator.mul(y.sub(h0w8[7]));

    let c1 = proof.c1;
    let c2 = proof.c2;
    let w1 = proof.w1;

    let mut quotient1 = alpha.mul(numerator.mul(denH1));
    let mut quotient2 = alpha.mul(alpha.mul(numerator.mul(denH2)));

    let c0_x = <G1Point as AffineCurve>::BaseField::from_str(
        "7005013949998269612234996630658580519456097203281734268590713858661772481668",
    )
    .unwrap();

    let c0_y = <G1Point as AffineCurve>::BaseField::from_str(
        "869093939501355406318588453775243436758538662501260653214950591532352435323",
    )
    .unwrap();

    let c0_affine = G1Projective::new(
        c0_x,
        c0_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();
    // pf -> c0x
    // pf + 32 -> c0y
    // pf, pc1, quotient1

    // min -> c1x
    // min + 32 -> c1y
    // min + 64 -> quotient1

    // multiply c1 * quotient1

    // min + 64 -> c0x
    // min + 96 -> c0y

    // adding points c1 * quotient1 + c0

    // print!("Quotient 1: {:?}", quotient1.to_string());
    // print!("Quotient 2: {:?}", quotient2.to_string());

    let c1_agg = c0_affine.add(c1.mul(quotient1).into_affine());

    let c2_agg = c1_agg.add(c2.mul(quotient2).into_affine()); //  F point
                                                              // println!("c2_agg: {:?}", c2_agg.x.to_string());
                                                              // println!("c2_agg: {:?}", c2_agg.y.to_string());

    let r_agg = R0.add(quotient1.mul(R1).add(quotient2.mul(R2)));

    let g1_acc = g1.mul(r_agg).into_affine(); // E point
                                              // println!("g1_acc: {:?}", g1_acc.x.to_string());
                                              // println!("g1_acc: {:?}", g1_acc.y.to_string());

    let w1_agg = w1.mul(numerator).into_affine(); // J Point

    // println!("w1_agg: {:?}", w1_agg.x.to_string());
    // println!("w1_agg: {:?}", w1_agg.y.to_string());
    // pE, g1x, g1y, r_agg
    // min -> g1x
    // min + 32 -> g1y
    // min + 64 -> r_agg

    // multiply g1 * r_agg

    // min + 64 -> 0
    // min + 96 -> 0
    (c2_agg, g1_acc, w1_agg)
}
