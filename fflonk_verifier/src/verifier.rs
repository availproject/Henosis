pub use crate::utils::{get_domain_size, get_omegas, get_proof, get_pubSignals, Omegas, Proof, ProofWithPubSignal};
use ark_bn254::{
     g1::Parameters, Bn254, Fq, Fr, FrParameters, G1Projective,
};
use ark_bn254::{ Fq2, G2Affine};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::*;
use ark_ff::{
    Field, Fp256, One, Zero,
};
use std::ops::{Add, Mul, Sub};
use std::str::FromStr;
use std::vec;
use crate::utils::{get_fr_from_bytes, get_proog_bigint, padd_bytes32};
use num_bigint::*;

use tiny_keccak::{Hasher, Keccak};

pub type G1Point = <Bn254 as PairingEngine>::G1Affine;
pub type G2Point = <Bn254 as PairingEngine>::G2Affine;


const VALUES_TO_SKIP: usize = 8;

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
    pub xi_seed: Fp256<FrParameters>,
    pub xi_seed2: Fp256<FrParameters>,
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



pub fn compute_challenges(
    challenges: &mut Challenges, roots: &mut Roots, zh: &mut Fp256<FrParameters>, zhinv: &mut Fp256<FrParameters>, vpi: VerifierProcessedInputs, pub_signals: BigInt
){
    let mut hasher = Keccak::v256();

    let mut concatenated = Vec::new();

    let vals = [
        vpi.c0x.to_bytes_be(),
        vpi.c0y.to_bytes_be(),
        pub_signals.to_bytes_be(),
        get_proog_bigint().c1.0.to_bytes_be(),
        get_proog_bigint().c1.1.to_bytes_be(),
    ];

    for val in &vals {
        hasher.update(&padd_bytes32(val.1.clone()));
    }

    let mut out = [0u8; 32];
    hasher.finalize(&mut out);
    let beta = get_fr_from_bytes(out);

    //gamma
    hasher = Keccak::v256();

    let _beta_string = beta.to_string();
    let beta_string = &_beta_string[VALUES_TO_SKIP..VALUES_TO_SKIP+64];
    let val6 = BigInt::parse_bytes(beta_string.trim_start_matches("0x").as_bytes(), 16).unwrap().to_bytes_be();
    concatenated = Vec::new();
    concatenated.extend_from_slice(&padd_bytes32(val6.1));
    hasher.update(&concatenated);
    out = [0u8; 32];
    hasher.finalize(&mut out);
    let gamma = get_fr_from_bytes(out);

    //xiseed 
    let mut hasher3 = Keccak::v256();
    let _gamma_string = gamma.to_string();
    let gamma_string = &_gamma_string[VALUES_TO_SKIP..VALUES_TO_SKIP+64];

    let vals = [
        BigInt::parse_bytes(gamma_string.as_bytes(), 16).unwrap().to_bytes_be(),
        get_proog_bigint().c2.0.to_bytes_be(),
        get_proog_bigint().c2.1.to_bytes_be(),
    ];

    concatenated = Vec::new();
    for val in &vals {
        concatenated.extend_from_slice(&padd_bytes32(val.1.clone()));
    }

    hasher3.update(&concatenated);
    out = [0u8; 32];
    hasher3.finalize(&mut out);
    let xi_seed = get_fr_from_bytes(out);

    //xiSeed2
    let xi_seed2 = xi_seed.mul(xi_seed);

    //roh0w8xi_seed2
    roots.h0w8[0] = xi_seed2.mul(xi_seed);
    let omegas = get_omegas();
    for i in 1..8 {
        roots.h0w8[i] = roots.h0w8[0].mul(match i {
            1 => omegas.w8_1,
            2 => omegas.w8_2,
            3 => omegas.w8_3,
            4 => omegas.w8_4,
            5 => omegas.w8_5,
            6 => omegas.w8_6,
            _ => omegas.w8_7,
        });
    }

    //roots h1w4
    roots.h1w4[0] = roots.h0w8[0].mul(roots.h0w8[0]);
    for i in 1..4 {
        roots.h1w4[i] = roots.h1w4[0].mul(match i {
            1 => omegas.w4,
            2 => omegas.w4_2,
            _ => omegas.w4_3,
        });
    }

    //roots h2w3
    roots.h2w3[0] = roots.h1w4[0].mul(xi_seed2);
    for i in 1..3 {
        roots.h2w3[i] = roots.h2w3[0].mul(match i {
            1 => omegas.w3,
            _ => omegas.w3_2,
        });
    }

    //roots h3w3
    roots.h3w3[0] = roots.h2w3[0].mul(get_omegas().wr);
    for i in 1..3 {
        roots.h3w3[i] = roots.h3w3[0].mul(match i {
            1 => omegas.w3,
            _ => omegas.w3_2,
        });
    }

    //zh and zhInv
    let mut xin = roots.h2w3[0].mul(roots.h2w3[0]).mul(roots.h2w3[0]);
    let xin_copy = xin;
    for _ in 0..24{
        xin = xin.mul(xin);
    }

    xin = xin.sub(Fr::one());

    *zh = xin;
    *zhinv = xin;
    // println!("zh: {:?}", zh.to_string());

    // alpha
    let mut hasher4 = Keccak::v256();

    let _xiseed_string = xi_seed.to_string();
    let xiseed_string = &_xiseed_string[8..8+64];
    let vals = [
        BigInt::parse_bytes(xiseed_string.to_string().as_bytes(), 16).unwrap().to_bytes_be(),
        get_proog_bigint().eval_ql.to_bytes_be(),
        get_proog_bigint().eval_qr.to_bytes_be(),
        get_proog_bigint().eval_qm.to_bytes_be(),
        get_proog_bigint().eval_qo.to_bytes_be(),
        get_proog_bigint().eval_qc.to_bytes_be(),
        get_proog_bigint().eval_s1.to_bytes_be(),
        get_proog_bigint().eval_s2.to_bytes_be(),
        get_proog_bigint().eval_s3.to_bytes_be(),
        get_proog_bigint().eval_a.to_bytes_be(),
        get_proog_bigint().eval_b.to_bytes_be(),
        get_proog_bigint().eval_c.to_bytes_be(),
        get_proog_bigint().eval_z.to_bytes_be(),
        get_proog_bigint().eval_zw.to_bytes_be(),
        get_proog_bigint().eval_t1w.to_bytes_be(),
        get_proog_bigint().eval_t2w.to_bytes_be(),
    ];
    concatenated = Vec::new();
    for val in &vals {
        concatenated.extend_from_slice(&padd_bytes32(val.1.clone()));
    }

    hasher4.update(&concatenated);

    out = [0u8; 32];
    hasher4.finalize(&mut out);
    let alpha = get_fr_from_bytes(out);

    println!("alpha: {:?}", alpha.to_string());
    //y
    let mut hasher5 = Keccak::v256();
    let _alpha_string = alpha.to_string();
    let alpha_string = &_alpha_string[8..8+64];
    let val26 = BigInt::parse_bytes(alpha_string.to_string().as_bytes(), 16).unwrap().to_bytes_be();
    let val27 = get_proog_bigint().w1.0.to_bytes_be();
    let val28 = get_proog_bigint().w1.1.to_bytes_be();
    let vals = [
        BigInt::parse_bytes(alpha_string.to_string().as_bytes(), 16).unwrap().to_bytes_be(),
        get_proog_bigint().w1.0.to_bytes_be(),
        get_proog_bigint().w1.1.to_bytes_be(),
    ];
    concatenated = Vec::new();
    for val in &vals {
        concatenated.extend_from_slice(&padd_bytes32(val.1.clone()));
    }

    hasher5.update(&concatenated);
    out = [0u8; 32];
    hasher5.finalize(&mut out);
    let y = get_fr_from_bytes(out);

    challenges.alpha = alpha;
    challenges.beta = beta;
    challenges.gamma = gamma;
    challenges.y = y;
    challenges.xi_seed = xi_seed;
    challenges.xi_seed2 = xi_seed2;
    challenges.xi = xin_copy;

} 


pub fn compute_lagrange(
    zh: Fp256<FrParameters>,
    eval_l1: Fp256<FrParameters>,
) -> Fp256<FrParameters> {
    eval_l1.mul(zh)
}

pub fn compute_pi(
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

pub fn calculate_inversions(
    y: Fp256<FrParameters>,
    xi: Fp256<FrParameters>,
    zh_inv: Fp256<FrParameters>,
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
    // println!("w: {}", (w));

    let den_h1 = w.clone();

    w = y.sub(h2w3[0]).mul(
        y.sub(h2w3[1])
            .mul(y.sub(h2w3[2]))
            .mul(y.sub(h3w3[0]).mul(y.sub(h3w3[1]).mul(y.sub(h3w3[2])))),
    );

    // println!("w: {}", (w));

    let den_h2 = w.clone();

    let li_s0_inv = compute_li_s0(y, h0w8);

    let li_s1_inv = compute_li_s1(y, h1w4);

    let li_s2_inv = compute_li_s2(y, xi, h2w3, h3w3);
    // println!()

    w = Fr::one();

    let mut eval_l1 = get_domain_size().mul(xi.sub(w));

    // println!("eval_l1: {}", eval_l1);

    let invser_arr_resp = inverse_array(
        den_h1,
        den_h2,
        zh_inv,
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

pub fn compute_li_s0(
    y: Fp256<FrParameters>,
    h0w8: Vec<Fp256<FrParameters>>,
) -> [Fp256<FrParameters>; 8] {
    let root0 = h0w8[0];

    let mut den1 = Fr::one();
    for _ in 0..6 {
        den1 = den1.mul(&root0);
    }

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
        den3 = y.add(&q.sub(&h0w8[0 + (i)]));
        // println!("den3: {}", den3);

        li_s0_inv[i] = den1.mul(&den2).mul(&den3);

    }
    li_s0_inv
}

pub fn compute_li_s1(
    y: Fp256<FrParameters>,
    h1w4: Vec<Fp256<FrParameters>>,
) -> [Fp256<FrParameters>; 4] {
    let root0 = h1w4[0];
    let mut den1 = Fr::one();
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
        let coeff = (i * 3) % 4;
        den2 = h1w4[0 + coeff];
        den3 = y.add(q.sub(h1w4[0 + (i)]));
        li_s1_inv[i] = den1.mul(den2).mul(den3);
    }

    li_s1_inv
}

pub fn compute_li_s2(
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

pub fn inverse_array(
    den_h1: Fp256<FrParameters>,
    den_h2: Fp256<FrParameters>,
    zh_inv: Fp256<FrParameters>,
    li_s0_inv: [Fp256<FrParameters>; 8],
    li_s1_inv: [Fp256<FrParameters>; 4],
    li_s2_inv: [Fp256<FrParameters>; 6],
    eval_l1: &mut Fp256<FrParameters>,
) -> (LISValues, Fp256<FrParameters>, Fp256<FrParameters>) {
    // let mut local_eval_l1 = eval_l1.clone();
    let local_den_h1;
    let local_den_h2;
    let mut local_li_s0_inv = li_s0_inv.clone();
    let mut local_li_s1_inv = li_s1_inv.clone();
    let mut local_li_s2_inv = li_s2_inv.clone();

    let mut _acc: Vec<Fp256<FrParameters>> = Vec::new();

    _acc.push(zh_inv.clone());

    let mut acc = zh_inv.mul(den_h1);
    _acc.push(acc.clone());

    acc = acc.mul(den_h2);
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

    // TODO this should be real time
    let mut inv = get_proof().eval_inv;

    let check = inv.mul(acc);
    assert!(check == Fr::one());

    acc = inv.clone();

    _acc.pop();
    inv = acc.mul(_acc.last().unwrap().clone());
    acc = acc.mul(eval_l1.clone());
    *eval_l1 = inv;
    // println!("herer eval_l1: {}", eval_l1);

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
    acc = acc.mul(den_h2);
    local_den_h2 = inv;

    _acc.pop();
    inv = acc.mul(_acc.last().unwrap().clone());
    acc = acc.mul(den_h1);
    local_den_h1 = inv;

    let lis_values = LISValues {
        li_s0_inv: local_li_s0_inv,
        li_s1_inv: local_li_s1_inv,
        li_s2_inv: local_li_s2_inv,
    };

    (lis_values, local_den_h1, local_den_h2)
}

pub fn verify(proof_with_pub_signal: ProofWithPubSignal) -> bool {
    let proof = proof_with_pub_signal.proof;
    let pub_signal = proof_with_pub_signal.pub_signal;

    let mut challenges = Challenges {
        alpha: Fr::zero(),
        beta: Fr::zero(),
        gamma: Fr::zero(),
        y: Fr::zero(),
        xi_seed: Fr::zero(),
        xi_seed2: Fr::zero(),
        xi: Fr::zero(),
    };
    let mut roots = Roots {
        h0w8: [Fr::zero(); 8],
        h1w4: [Fr::zero(); 4],
        h2w3: [Fr::zero(); 3],
        h3w3: [Fr::zero(); 3],
    };
    let vpi = VerifierProcessedInputs {
        c0x: BigInt::parse_bytes(b"7005013949998269612234996630658580519456097203281734268590713858661772481668", 10).unwrap(),
        c0y: BigInt::parse_bytes(b"869093939501355406318588453775243436758538662501260653214950591532352435323", 10).unwrap(),
        x2x1: BigInt::parse_bytes(b"21831381940315734285607113342023901060522397560371972897001948545212302161822", 10).unwrap(),
        x2x2: BigInt::parse_bytes(b"17231025384763736816414546592865244497437017442647097510447326538965263639101", 10).unwrap(),
        x2y1: BigInt::parse_bytes(b"2388026358213174446665280700919698872609886601280537296205114254867301080648", 10).unwrap(),
        x2y2: BigInt::parse_bytes(b"11507326595632554467052522095592665270651932854513688777769618397986436103170", 10).unwrap(),
    };

    let pub_signal_big_int = BigInt::parse_bytes(b"14516932981781041565586298118536599721399535462624815668597272732223874827152", 10).unwrap();

    let mut zh: Fp256<FrParameters> = Fr::zero();
    let mut zhinv: Fp256<FrParameters> = Fr::zero();

    compute_challenges(&mut challenges, &mut roots, &mut zh, &mut zhinv, vpi, pub_signal_big_int);

    let alpha = challenges.alpha;
    let beta = challenges.beta;
    let gamma = challenges.gamma;
    let xi = challenges.xi;
    let y = challenges.y;
    let zinv = zhinv.clone();

    let g1_x = <G1Point as AffineCurve>::BaseField::from_str("1").unwrap();
    let g1_y = <G1Point as AffineCurve>::BaseField::from_str("2").unwrap();
    let g1_affine = G1Projective::new(g1_x, g1_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();

    let h0w8: Vec<Fp256<FrParameters>> = roots.h0w8.to_vec();
    let h1w4: Vec<Fp256<FrParameters>> = roots.h1w4.to_vec();
    let h2w3: Vec<Fp256<FrParameters>> = roots.h2w3.to_vec();
    let h3w3: Vec<Fp256<FrParameters>> = roots.h3w3.to_vec();

    let (mut eval_l1, lis_values, denH1, denH2) = calculate_inversions(y, xi, zhinv, h0w8.clone(), h1w4.clone(), h2w3.clone(), h3w3.clone());
    eval_l1 = compute_lagrange(zh, eval_l1);

    let pi = compute_pi(pub_signal, eval_l1);

    println!("Verifying proof...");

    let R0 = calculate_r0(xi, proof.clone(), y, h0w8.clone(), lis_values.li_s0_inv);
    let R1 = calculate_r1(xi, proof.clone(), y, pi, h1w4.clone(), lis_values.li_s1_inv, zinv);
    let R2 = calculate_r2(xi, gamma, beta, proof.clone(), y, eval_l1, zinv, h2w3.clone(), h3w3.clone(), lis_values.li_s2_inv);

    let (F, E, J) = compute_fej(y, h0w8.clone(), denH1, denH2, alpha, proof.clone(), g1_affine, R0, R1, R2);

    let W2 = proof.w2;
    let p1 = F.add(-E).add(-J).add(W2.mul(y).into_affine());

    let g2x1 = Fq::from_str("10857046999023057135944570762232829481370756359578518086990519993285655852781").unwrap();
    let g2x2 = Fq::from_str("11559732032986387107991004021392285783925812861821192530917403151452391805634").unwrap();
    let g2y1 = Fq::from_str("869093939501355406318588453775243436758538662501260653214950591532352435323").unwrap();
    let g2y2 = Fq::from_str("4082367875863433681332203403145435568316851327593401208105741076214120093531").unwrap();
    let g2_val = G2Affine::new(Fq2::new(g2x1, g2x2), Fq2::new(g2y1, g2y2), true);

    let p3 = -W2;

    let x2x1 = Fq::from_str("21831381940315734285607113342023901060522397560371972897001948545212302161822").unwrap();
    let x2x2 = Fq::from_str("17231025384763736816414546592865244497437017442647097510447326538965263639101").unwrap();
    let x2y1 = Fq::from_str("2388026358213174446665280700919698872609886601280537296205114254867301080648").unwrap();
    let x2y2 = Fq::from_str("11507326595632554467052522095592665270651932854513688777769618397986436103170").unwrap();
    let x2_val = G2Affine::new(Fq2::new(x2x1, x2x2), Fq2::new(x2y1, x2y2), true);

    println!("Doing Pairing Check!");

    let pairing1 = Bn254::pairing(p1, g2_val);
    let pairing2 = Bn254::pairing(p3, x2_val);

    if pairing1 == pairing2 {
        println!("Proof Verified!");
        return true;
    }

    println!("Proof verification failed!");
    false
}

fn calculate_r0(
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

    let num = Fr::one().mul(&y.pow([8])).add(-xi);

    fn compute_c0_value(
        eval_ql: &Fp256<FrParameters>,
        eval_qr: &Fp256<FrParameters>,
        eval_qm: &Fp256<FrParameters>,
        eval_qo: &Fp256<FrParameters>,
        eval_qc: &Fp256<FrParameters>,
        eval_s1: &Fp256<FrParameters>,
        eval_s2: &Fp256<FrParameters>,
        eval_s3: &Fp256<FrParameters>,
        h0w8: &Fp256<FrParameters>,
    ) -> Fp256<FrParameters> {
        let mut h0w8i = *h0w8;
        let mut c0_value = eval_ql.add(&h0w8.mul(eval_qr));

        h0w8i = h0w8i.mul(h0w8);
        c0_value = c0_value.add(eval_qo.mul(&h0w8i));

        h0w8i = h0w8i.mul(h0w8);
        c0_value = c0_value.add(eval_qm.mul(&h0w8i));

        h0w8i = h0w8i.mul(h0w8);
        c0_value = c0_value.add(eval_qc.mul(&h0w8i));

        h0w8i = h0w8i.mul(h0w8);
        c0_value = c0_value.add(eval_s1.mul(&h0w8i));

        h0w8i = h0w8i.mul(h0w8);
        c0_value = c0_value.add(eval_s2.mul(&h0w8i));

        h0w8i = h0w8i.mul(h0w8);
        c0_value = c0_value.add(eval_s3.mul(&h0w8i));

        c0_value
    }

    let mut res = Fr::zero();
    for i in 0..8 {
        let c0_value = compute_c0_value(
            &eval_ql, &eval_qr, &eval_qm, &eval_qo, &eval_qc,
            &eval_s1, &eval_s2, &eval_s3, &h0w8[i],
        );
        res = res.add(c0_value.mul(num.mul(&li_s0_inv[i])));
    }

    res
}

fn calculate_r1(
    xi: Fp256<FrParameters>,
    proof: Proof,
    y: Fp256<FrParameters>,
    pi: Fp256<FrParameters>,
    h1w4: Vec<Fp256<FrParameters>>,
    li_s1_inv: [Fp256<FrParameters>; 4],
    zinv: Fp256<FrParameters>,
) -> Fp256<FrParameters> {
    let mut num = Fr::one();
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

    num = num.mul(&y.pow([4]));
    num = num.add(-xi);

    let mut t0 = eval_ql.mul(&eval_a);
    t0 = t0.add(&eval_qr.mul(&eval_b));
    t0 = t0.add(&eval_qm.mul(&eval_a.mul(&eval_b)));
    t0 = t0.add(&eval_qo.mul(&eval_c));
    t0 = t0.add(&eval_qc);
    t0 = t0.add(&pi);
    t0 = t0.mul(&zinv);

    fn compute_c1_value(
        eval_a: &Fp256<FrParameters>,
        eval_b: &Fp256<FrParameters>,
        eval_c: &Fp256<FrParameters>,
        t0: &Fp256<FrParameters>,
        hw: &Fp256<FrParameters>,
    ) -> Fp256<FrParameters> {
        let mut c1_value = *eval_a;
        c1_value = c1_value.add(&hw.mul(eval_b));
        let mut square = hw.mul(hw);
        c1_value = c1_value.add(&eval_c.mul(&square));
        c1_value = c1_value.add(&t0.mul(&square.mul(hw)));
        c1_value
    }

    let mut res = Fr::zero();

    for i in 0..4 {
        let c1_value = compute_c1_value(&eval_a, &eval_b, &eval_c, &t0, &h1w4[i]);
        res = res.add(c1_value.mul(num.mul(&li_s1_inv[i])));
    }

    res
}

fn calculate_r2(
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

    let w1 = get_omegas().w1;
    let mut num = Fr::one();
    let betaxi = beta.mul(&xi);
    let y_6 = y.pow([6]);
    let k1 = Fr::from_str("2").unwrap();
    let k2 = Fr::from_str("3").unwrap();

    num = num.mul(&y_6);
    let mut num2 = Fr::one();
    num2 = num2.mul(&y.pow([3]));
    num2 = num2.mul(&xi.add(&xi.mul(&w1)));
    num = num.sub(&num2);
    num2 = xi.mul(&xi.mul(&w1));
    num = num.add(&num2);

    let mut t2 = eval_a.add(&betaxi.add(&gamma));
    t2 = t2.mul(&eval_b.add(&gamma.add(&betaxi.mul(&k1))));
    t2 = t2.mul(&eval_c.add(&gamma.add(&betaxi.mul(&k2))));
    t2 = t2.mul(&eval_z);

    let mut t1 = eval_a.add(&gamma.add(&beta.mul(&eval_s1)));
    t1 = t1.mul(&eval_b.add(&gamma.add(&beta.mul(&eval_s2))));
    t1 = t1.mul(&eval_c.add(&gamma.add(&beta.mul(&eval_s3))));
    t1 = t1.mul(&eval_zw);

    t2 = t2.sub(&t1);
    t2 = t2.mul(&zinv);

    t1 = eval_z.sub(&Fr::one());
    t1 = t1.mul(&eval_l1);
    t1 = t1.mul(&zinv);

    fn compute_c2_value(
        eval: &Fp256<FrParameters>,
        hw: &Fp256<FrParameters>,
        t1: &Fp256<FrParameters>,
        t2: &Fp256<FrParameters>,
    ) -> Fp256<FrParameters> {
        let mut c2_value = eval.add(&hw.mul(t1));
        c2_value = c2_value.add(&t2.mul(&hw.mul(hw)));
        c2_value
    }

    let mut gamma_r2 = Fr::zero();

    for i in 0..3 {
        let hw = &h2w3[i];
        let c2_value = compute_c2_value(&eval_z, hw, &t1, &t2);
        gamma_r2 = gamma_r2.add(c2_value.mul(num.mul(&li_s2_inv[i])));
    }

    for i in 0..3 {
        let hw = &h3w3[i];
        let c2_value = compute_c2_value(&eval_zw, hw, &eval_t1w, &eval_t2w);
        gamma_r2 = gamma_r2.add(c2_value.mul(num.mul(&li_s2_inv[i + 3])));
    }

    gamma_r2
}

fn compute_fej(
    y: Fp256<FrParameters>,
    h0w8: Vec<Fp256<FrParameters>>,
    den_h1: Fp256<FrParameters>,
    den_h2: Fp256<FrParameters>,
    alpha: Fp256<FrParameters>,
    proof: Proof,
    g1: GroupAffine<Parameters>,
    r0: Fp256<FrParameters>,
    r1: Fp256<FrParameters>,
    r2: Fp256<FrParameters>,
) -> (
    GroupAffine<Parameters>,
    GroupAffine<Parameters>,
    GroupAffine<Parameters>,
) {
    // Compute numerator
    let numerator = h0w8.iter().fold(y, |acc, &h| acc.mul(y.sub(h)));

    let Proof {
        c1, c2, w1, ..
    } = proof;

    let alpha_squared = alpha.mul(&alpha);
    let quotient1 = alpha.mul(&numerator).mul(&den_h1);
    let quotient2 = alpha_squared.mul(&numerator).mul(&den_h2);

    // Define c0 affine point
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

    // Compute c1_agg
    let c1_agg = c0_affine.add(c1.mul(*&quotient1).into_affine());

    // Compute c2_agg
    let c2_agg = c1_agg.add(c2.mul(*&quotient2).into_affine());

    // Compute r_agg
    let r_agg = r0.add(&quotient1.mul(&r1).add(&quotient2.mul(&r2)));

    // Compute g1_acc
    let g1_acc = g1.mul(*&r_agg).into_affine();

    // Compute w1_agg
    let w1_agg = w1.mul(*&numerator).into_affine();

    (c2_agg, g1_acc, w1_agg)
}