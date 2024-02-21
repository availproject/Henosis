use ark_bn254::{Bn254, FqParameters, Fr, FrParameters, G1Projective, g1::Parameters, g1};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::*;
use ark_ff::{Field, Fp256, One, PrimeField, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{domain, Polynomial};
use ethers::core::rand;
use std::fmt::{Debug, DebugMap, Display};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};
use std::str::FromStr;
use num_bigint::*;

pub type G1Point = <Bn254 as PairingEngine>::G1Affine;
pub type G2Point = <Bn254 as PairingEngine>::G2Affine;
use ethers::{
    abi::{Token, Tokenizable},
    types::U256,
};



//  // Proof calldata
//     // Byte offset of every parameter of the calldata
//     // Polynomial commitments
//     uint16 constant pC1       = 4 + 0;     // [C1]_1
//     uint16 constant pC2       = 4 + 32*2;  // [C2]_1
//     uint16 constant pW1       = 4 + 32*4;  // [W]_1
//     uint16 constant pW2       = 4 + 32*6;  // [W']_1
//     // Opening evaluations
//     uint16 constant pEval_ql  = 4 + 32*8;  // q_L(xi)
//     uint16 constant pEval_qr  = 4 + 32*9;  // q_R(xi)
//     uint16 constant pEval_qm  = 4 + 32*10; // q_M(xi)
//     uint16 constant pEval_qo  = 4 + 32*11; // q_O(xi)
//     uint16 constant pEval_qc  = 4 + 32*12; // q_C(xi)
//     uint16 constant pEval_s1  = 4 + 32*13; // S_{sigma_1}(xi)
//     uint16 constant pEval_s2  = 4 + 32*14; // S_{sigma_2}(xi)
//     uint16 constant pEval_s3  = 4 + 32*15; // S_{sigma_3}(xi)
//     uint16 constant pEval_a   = 4 + 32*16; // a(xi)
//     uint16 constant pEval_b   = 4 + 32*17; // b(xi)
//     uint16 constant pEval_c   = 4 + 32*18; // c(xi)
//     uint16 constant pEval_z   = 4 + 32*19; // z(xi)
//     uint16 constant pEval_zw  = 4 + 32*20; // z_omega(xi)
//     uint16 constant pEval_t1w = 4 + 32*21; // T_1(xi omega)
//     uint16 constant pEval_t2w = 4 + 32*22; // T_2(xi omega)
//     uint16 constant pEval_inv = 4 + 32*23; // inv(batch) sent by the prover to avoid any inverse calculation to save gas,
//                                            // we check the correctness of the inv(batch) by computing batch
//                                            // and checking inv(batch) * batch == 1



struct Proof{
    c1: G1Point,
    c2: G1Point,
    w1: G1Point,
    w2: G1Point,

    eval_ql: Fp256<FrParameters>,
    eval_qr: Fp256<FrParameters>,
    eval_qm: Fp256<FrParameters>,
    eval_qo: Fp256<FrParameters>,
    eval_qc: Fp256<FrParameters>,
    eval_s1: Fp256<FrParameters>,
    eval_s2: Fp256<FrParameters>,
    eval_s3: Fp256<FrParameters>,
    eval_a: Fp256<FrParameters>,
    eval_b: Fp256<FrParameters>,
    eval_c: Fp256<FrParameters>,
    eval_z: Fp256<FrParameters>,
    eval_zw: Fp256<FrParameters>,
    eval_t1w: Fp256<FrParameters>,
    eval_t2w: Fp256<FrParameters>,
    eval_inv: Fp256<FrParameters>,
}

struct Omegas{
    w1: Fp256<FrParameters>,
    wr: Fp256<FrParameters>,

    w3: Fp256<FrParameters>,
    w3_2: Fp256<FrParameters>,

    w4: Fp256<FrParameters>,
    w4_2: Fp256<FrParameters>,
    w4_3: Fp256<FrParameters>,

    w8_1: Fp256<FrParameters>,
    w8_2: Fp256<FrParameters>,
    w8_3: Fp256<FrParameters>,
    w8_4: Fp256<FrParameters>,
    w8_5: Fp256<FrParameters>,
    w8_6: Fp256<FrParameters>,
    w8_7: Fp256<FrParameters>,
}

pub fn get_omegas()->Omegas{
    Omegas{
        w1: Fr::from_str("5709868443893258075976348696661355716898495876243883251619397131511003808859").unwrap(),
        wr: Fr::from_str("18200100796661656210024324131237448517259556535315737226009542456080026430510").unwrap(),

        w3: Fr::from_str("21888242871839275217838484774961031246154997185409878258781734729429964517155").unwrap(),
        w3_2: Fr::from_str("4407920970296243842393367215006156084916469457145843978461").unwrap(),

        w4: Fr::from_str("21888242871839275217838484774961031246007050428528088939761107053157389710902").unwrap(),
        w4_2: Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495616").unwrap(),
        w4_3: Fr::from_str("4407920970296243842541313971887945403937097133418418784715").unwrap(),

        w8_1: Fr::from_str("19540430494807482326159819597004422086093766032135589407132600596362845576832").unwrap(),
        w8_2: Fr::from_str("21888242871839275217838484774961031246007050428528088939761107053157389710902").unwrap(),
        w8_3: Fr::from_str("13274704216607947843011480449124596415239537050559949017414504948711435969894").unwrap(),
        w8_4: Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495616").unwrap(),
        w8_5: Fr::from_str("2347812377031792896086586148252853002454598368280444936565603590212962918785").unwrap(),
        w8_6: Fr::from_str("4407920970296243842541313971887945403937097133418418784715").unwrap(),
        w8_7: Fr::from_str("8613538655231327379234925296132678673308827349856085326283699237864372525723").unwrap(),

    }
}

pub fn get_proof() -> Proof{

    let pr = vec!["0x1af638185408dfa5b1470887ab5bf38a7363f6c26479828ab16eb45219715936",
     "0x2b129ebcbf22e11bb2442800922bf1c9979bb7a6c895e17411325e6a1c195912",
     "0x0098d7bc29d322c680263a7dba99490333dd42aeafc4ca99f870288f1052cd86",
     "0x11c911bfb298b409c74838c0a3c16f7171dac07cddaba283e36090eef091d67f",
     "0x29c8c4c86c9d63a57e65dcef548f50c06ce41ffcaadf21f279f66a9f6b59f619",
     "0x01eb8b4841e587df317141dd2c198d0160eb974c34dd303f75b27cdac46ce887",
     "0x220c39420aa977359e2f2fb3c5d7b9b28a23a7f0c78d6b215d4178d3f2b1ba72",
     "0x045c6d18f3e18cc4aac314316a47f0010ba8b1035b7dab678933e5bcd248f72b",
     "0x1cc4edb75ac4f07466f70f097d263bad6ca1e1e506bccbccd7de94b39dd3a05e",
     "0x0e11ad74cead5ed3d142083b8ad873acf20cb6e39059d88e61a84982386a698a",
     "0x23806e3836d9fb0467b1ade5a51564aeda10cc9b97f596456cafa149f6c9bfbb",
     "0x1aec381b720257b672376b5ccbd1fe787247e3cc7b2c6ec2d171be1c5c1a5837",
     "0x038d7d45919eee4e6c7e47c586b1d55e32d102e56d64513575d94a9aeba30241",
     "0x1ba4459cca4bb8b75808d4f38598e4b6cf6a8577f7294def8e85b5955abc681a",
     "0x300239f087b7a581948dc4b14cdc9d5ae13ba8a9cbf56998f764ba13549ac6fa",
     "0x104d55e131742e10144e0c9023635ee7e000de29d76c05ad56f6a74e40ac9924",
     "0x177d85cc56ecaac98dc3c835668105f9ff8311a73767f7ba145d443af8d00999",
     "0x1bd5b487cf64d1973cdfbcf8587319d681ab87e595ef347d68067418cca5368f",
     "0x27144e4b99a6508fecc7b0fdc1a64d4be4760a1035730e29a907dd091c6b95ac",
     "0x1e8841cdf20050bfe02cbeb022b26960e8b544774112e09a21a440c8bba503d3",
     "0x15273dd6fecfedef5adde005a7ab5ee48a7eefdaa85ef4e356d0f3dcd92bcb64",
     "0x267735dcdbd34c8c5f8cf864f3990e078d26a928a54c27485133b6d0678cda9b",
     "0x1a193153f3cf956d68aab8afe447f0f6ba985f40edba7d9375b9368f1c55f31b",
     "0x0e1a49d180902645b8954552c99af04aed9315725b32ac2623965f887a7a5849"];
    
    let c1_x = <G1Point as AffineCurve>::BaseField::from_str(&U256::from_str(pr[0]).unwrap().to_string()).unwrap();
    let c1_y = <G1Point as AffineCurve>::BaseField::from_str(&U256::from_str(pr[1]).unwrap().to_string()).unwrap();
    let c1_affine = G1Projective::new(c1_x, c1_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();


    let c2_x = <G1Point as AffineCurve>::BaseField::from_str(&U256::from_str(pr[2]).unwrap().to_string()).unwrap();
    let c2_y = <G1Point as AffineCurve>::BaseField::from_str(&U256::from_str(pr[3]).unwrap().to_string()).unwrap();
    let c2_affine = G1Projective::new(c2_x, c2_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();

    let w1_x = <G1Point as AffineCurve>::BaseField::from_str(&U256::from_str(pr[4]).unwrap().to_string()).unwrap();
    let w1_y = <G1Point as AffineCurve>::BaseField::from_str(&U256::from_str(pr[5]).unwrap().to_string()).unwrap();
    let w1_affine = G1Projective::new(w1_x, w1_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();

    let w2_x = <G1Point as AffineCurve>::BaseField::from_str(&U256::from_str(pr[6]).unwrap().to_string()).unwrap();
    let w2_y = <G1Point as AffineCurve>::BaseField::from_str(&U256::from_str(pr[7]).unwrap().to_string()).unwrap();
    let w2_affine = G1Projective::new(w2_x, w2_y, <G1Projective as ProjectiveCurve>::BaseField::one()).into_affine();

    Proof{
        c1: c1_affine,
        c2: c2_affine,
        w1: w1_affine,
        w2: w2_affine,

        eval_ql: Fr::from_str(&U256::from_str(pr[8]).unwrap().to_string()).unwrap(),
        eval_qr: Fr::from_str(&U256::from_str(pr[9]).unwrap().to_string()).unwrap(),
        eval_qm: Fr::from_str(&U256::from_str(pr[10]).unwrap().to_string()).unwrap(),
        eval_qo: Fr::from_str(&U256::from_str(pr[11]).unwrap().to_string()).unwrap(),
        eval_qc: Fr::from_str(&U256::from_str(pr[12]).unwrap().to_string()).unwrap(),
        eval_s1: Fr::from_str(&U256::from_str(pr[13]).unwrap().to_string()).unwrap(),
        eval_s2: Fr::from_str(&U256::from_str(pr[14]).unwrap().to_string()).unwrap(),
        eval_s3: Fr::from_str(&U256::from_str(pr[15]).unwrap().to_string()).unwrap(),
        eval_a: Fr::from_str(&U256::from_str(pr[16]).unwrap().to_string()).unwrap(),
        eval_b: Fr::from_str(&U256::from_str(pr[17]).unwrap().to_string()).unwrap(),
        eval_c: Fr::from_str(&U256::from_str(pr[18]).unwrap().to_string()).unwrap(),
        eval_z: Fr::from_str(&U256::from_str(pr[19]).unwrap().to_string()).unwrap(),
        eval_zw: Fr::from_str(&U256::from_str(pr[20]).unwrap().to_string()).unwrap(),
        eval_t1w: Fr::from_str(&U256::from_str(pr[21]).unwrap().to_string()).unwrap(),
        eval_t2w: Fr::from_str(&U256::from_str(pr[22]).unwrap().to_string()).unwrap(),
        eval_inv: Fr::from_str(&U256::from_str(pr[23]).unwrap().to_string()).unwrap(),
    
    }
}

pub fn get_domain_size() -> Fp256<FrParameters> {
    Fr::from_str("16777216").unwrap()
}


pub fn calculateInversions(y : Fp256<FrParameters>, xi: Fp256<FrParameters> , zhInv: Fp256<FrParameters> , h0w8:Vec<Fp256<FrParameters>>  ,h1w4: Vec<Fp256<FrParameters>>, h2w3: Vec<Fp256<FrParameters>>, h3w3: Vec<Fp256<FrParameters>>) {
    let mut w = y.sub(h1w4[0]).mul(y.sub(h1w4[1]).mul(y.sub(h1w4[2]).mul(y.sub(h1w4[3]))));
    println!("w: {}", (w));

    let denH1 = w.clone();

    w = y.sub(h2w3[0]).mul(y.sub(h2w3[1]).mul(y.sub(h2w3[2])).mul(y.sub(h3w3[0]).mul(y.sub(h3w3[1]).mul(y.sub(h3w3[2])))));

    println!("w: {}", (w));

    let denH2 = w.clone();

    let mut li_s0_inv = computeLiS0(y, h0w8);

    let mut li_s1_inv = computeLiS1(y, h1w4);

    let mut li_s2_inv = computeLiS2(y, xi,  h2w3, h3w3);

    w = Fr::from_str("1").unwrap();

    let eval_l1 = get_domain_size().mul(xi.sub(w));

    inverseArray(denH1, denH2, zhInv, li_s0_inv, li_s1_inv, li_s2_inv, eval_l1);

    let hex_value = "0x1af638185408dfa5b1470887ab5bf38a7363f6c26479828ab16eb45219715936"; // Your hex value
    let u256_value = U256::from_str(hex_value).expect("Invalid hex value");

}


pub fn computeLiS0(y : Fp256<FrParameters>, h0w8: Vec<Fp256<FrParameters>>) -> [Fp256<FrParameters>; 8]{

    let root0 = h0w8[0];

    let mut den1 = Fr::from_str("1").unwrap();
    den1 = den1.mul(root0).mul(root0).mul(root0).mul(root0).mul(root0).mul(root0);

    // println!("den1: {}", den1);

    den1 = den1.mul(Fr::from_str("8").unwrap());


    let mut den2;
    let mut den3;

    let mut li_s0_inv: [Fp256<FrParameters>; 8] = [Fr::zero(); 8];

    let q= Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495617").unwrap();

    for i in 0..8{
        let coeff = ((i*7 )% 8);
        den2 = h0w8[0+coeff];
        // println!("den2: {}", den2);
        den3 = y.add(q.sub(h0w8[0+ (i)]));
        // println!("den3: {}", den3);

        li_s0_inv[i] = den1.mul(den2).mul(den3); 
        
        // println!("li_s0_inv: {}", li_s0_inv[i]);
        // println!();
    }
    // println!("li_s0_inv: {}", li_s0_inv[7]);

    li_s0_inv
}

pub fn computeLiS1(y : Fp256<FrParameters>, h1w4: Vec<Fp256<FrParameters>>) -> [Fp256<FrParameters>; 4]{

    let root0 = h1w4[0];
    let mut den1 = Fr::from_str("1").unwrap();
    den1 = den1.mul(root0).mul(root0);

    den1 = den1.mul(Fr::from_str("4").unwrap());

    let q= Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495617").unwrap();

    let mut den2;
    let mut den3;

    let mut li_s1_inv: [Fp256<FrParameters>; 4] = [Fr::zero(); 4];


    for i in 0..4{
        let coeff = ((i*3 )% 4);
        den2 = h1w4[0+coeff];
        den3 = y.add(q.sub(h1w4[0+ (i)]));
        li_s1_inv[i] = den1.mul(den2).mul(den3);     
    }

    println!("li_s1_inv: {}", li_s1_inv[3]);
    li_s1_inv
}

pub fn computeLiS2(y : Fp256<FrParameters>, xi:Fp256<FrParameters> ,h2w3: Vec<Fp256<FrParameters>>, h3w3: Vec<Fp256<FrParameters>>) -> [Fp256<FrParameters>; 6]{
    let q= Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495617").unwrap();

    // let den1 := mulmod(mulmod(3,mload(add(pMem, pH2w3_0)),q), addmod(mload(add(pMem, pXi)) ,mod(sub(q, mulmod(mload(add(pMem, pXi)), w1 ,q)), q), q), q)
    let omegas = get_omegas();
    let mut den1 = (Fr::from_str("3").unwrap().mul(h2w3[0])).mul(xi.add(q.sub(xi.mul(omegas.w1))));

    let mut den2;
    let mut den3;

    let mut li_s2_inv: [Fp256<FrParameters>; 6] = [Fr::zero(); 6];


    for i in 0..3{
        let coeff = ((i*2 )% 3);
        den2 = h2w3[0+coeff];
        den3 = y.add(q.sub(h2w3[0+ (i)])); 
        li_s2_inv[i] = den1.mul(den2).mul(den3);
    }

    den1 = (Fr::from_str("3").unwrap().mul(h3w3[0])).mul(xi.mul(omegas.w1).add(q.sub(xi)));

    for i in 0..3{
        let coeff = ((i*2 )% 3);
        den2 = h3w3[0+coeff];
        den3 = y.add(q.sub(h3w3[0+ (i)]));
        li_s2_inv[i+3] = den1.mul(den2).mul(den3);
    }

    li_s2_inv
}



pub fn inverseArray(denH1: Fp256<FrParameters>, denH2: Fp256<FrParameters>, zhInv: Fp256<FrParameters> ,li_s0_inv: [Fp256<FrParameters>; 8], li_s1_inv: [Fp256<FrParameters>; 4], li_s2_inv: [Fp256<FrParameters>; 6], eval_l1: Fp256<FrParameters>) {

    let mut local_eval_l1 = eval_l1.clone();
    let mut local_den_h1 = denH1.clone();
    let mut local_den_h2 = denH2.clone();
    let mut local_zh_inv = zhInv.clone();
    let mut local_li_s0_inv = li_s0_inv.clone();
    let mut local_li_s1_inv = li_s1_inv.clone();
    let mut local_li_s2_inv = li_s2_inv.clone();

    let mut acc = zhInv.mul(denH1).mul(denH2);
    for i in 0..8{
        acc = acc.mul(local_li_s0_inv[i]);
    }
    for i in 0..4{
        acc = acc.mul(local_li_s1_inv[i]);
    }
    for i in 0..6{
        acc = acc.mul(local_li_s2_inv[i]);
    }
    acc = acc.mul(local_eval_l1);
    println!("acc: {}", acc);

    let mut inv = get_proof().eval_inv;

    println!("inv: {}", inv);

    let check = inv.mul(acc);
    assert!(check == Fr::one());

    acc = inv.clone();

    inv = acc.mul(local_eval_l1);
    acc = acc.mul(local_eval_l1);
    local_eval_l1 = inv;

    for i in (0..6).rev(){
        inv = acc.mul(local_li_s2_inv[i]);
        acc = acc.mul(local_li_s2_inv[i]);
        local_li_s2_inv[i] = inv;
    }

    for i in (0..4).rev(){
        inv = acc.mul(local_li_s1_inv[i]);
        acc = acc.mul(local_li_s1_inv[i]);
        local_li_s1_inv[i] = inv;
    }

    for i in (0..8).rev(){
        inv = acc.mul(local_li_s0_inv[i]);
        acc = acc.mul(local_li_s0_inv[i]);
        local_li_s0_inv[i] = inv;
    }

    inv = acc.mul(denH2);
    acc = acc.mul(denH2);
    local_den_h2 = inv;

    inv = acc.mul(denH1);
    acc = acc.mul(denH1);
    local_den_h1 = inv;

    
    local_zh_inv = acc;

    println!("local_zh_inv: {}", local_zh_inv);
}



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

    let zhinv: Fp256<FrParameters> = Fr::from_str(
        "8663234610000964594764035144827003258323335914482598945994186647593190381653",
    ).unwrap();

    let h0w8: Vec<Fp256<FrParameters>> = vec![
        Fr::from_str("6217280567245217757583020595539628144853576189258393757880925561134573660857").unwrap(),
        Fr::from_str("6467474964103268828445749503025875230771477005123038192746478572392917288085").unwrap(),
        Fr::from_str("17058617445718799367294447696955508815020408034987705203621830040667799234184").unwrap(),
        Fr::from_str("21316856612335037613757111596833720133546507460560319301014759512314160286103").unwrap(),
        Fr::from_str("15670962304594057464663385149717646943694788211157640585817278625441234834760").unwrap(),
        Fr::from_str("15420767907736006393800656242231399857776887395292996150951725614182891207532").unwrap(),
        Fr::from_str("4829625426120475854951958048301766273527956365428329140076374145908009261433").unwrap(),
        Fr::from_str("571386259504237608489294148423554955001856939855715042683444674261648209514").unwrap(),
    ];

    let h1w4: Vec<Fp256<FrParameters>> = vec![
        Fr::from_str("19942750751199432676942609926442586439740980242021920220189719874523203538").unwrap(),
        Fr::from_str("6070134217614975914195815562203672780869780328825257598131939473058160967520").unwrap(),
        Fr::from_str("21868300121088075789569463135330832502108623420174012423478014466701285292079").unwrap(),
        Fr::from_str("15818108654224299308050590183053602307678584071590776745566264713517647528097").unwrap(),
    ];

    let h2w3: Vec<Fp256<FrParameters>> = vec![
        Fr::from_str("1869756320377877312595498521504015597511420477452283464861296949200508189845").unwrap(),
        Fr::from_str("12855200334058046664672080384376966021199960394800133527288768963888158252355").unwrap(),
        Fr::from_str("7163286217403351244978826839376293469836983528163617351548138273487142053417").unwrap(),
    ];

    let h3w3: Vec<Fp256<FrParameters>> = vec![
        Fr::from_str("20221471501150487562916135566783003531433279751312695446481128041754069339168").unwrap(),
        Fr::from_str("5182315555253909512081724539694463779341668914354906154606878795853655230920").unwrap(),
        Fr::from_str("18372698687274153369494951384037082866321780135164467086308401535543892421146").unwrap(),
    ];


    

    calculateInversions(y,xi,zhinv,  h0w8, h1w4, h2w3, h3w3);
    println!("Verifying proof...");
}
