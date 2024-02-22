use ark_bn254::{g1, g1::Parameters, Bn254, FqParameters, Fr, FrParameters, G1Projective};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::*;
use ark_ff::{Field, Fp256, Fp256Parameters, One, PrimeField, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{domain, Polynomial};
use ethers::core::rand;
use num_bigint::*;
use std::fmt::{Debug, DebugMap, Display};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};
use std::str::FromStr;

pub type G1Point = <Bn254 as PairingEngine>::G1Affine;
pub type G2Point = <Bn254 as PairingEngine>::G2Affine;
// use ethers::{
//     abi::{Token, Tokenizable},
//     types::U256,
// };

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

struct Proof {
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

struct Omegas {
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

pub fn get_omegas() -> Omegas {
    Omegas {
        w1: Fr::from_str(
            "5709868443893258075976348696661355716898495876243883251619397131511003808859",
        )
        .unwrap(),
        wr: Fr::from_str(
            "18200100796661656210024324131237448517259556535315737226009542456080026430510",
        )
        .unwrap(),

        w3: Fr::from_str(
            "21888242871839275217838484774961031246154997185409878258781734729429964517155",
        )
        .unwrap(),
        w3_2: Fr::from_str("4407920970296243842393367215006156084916469457145843978461").unwrap(),

        w4: Fr::from_str(
            "21888242871839275217838484774961031246007050428528088939761107053157389710902",
        )
        .unwrap(),
        w4_2: Fr::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap(),
        w4_3: Fr::from_str("4407920970296243842541313971887945403937097133418418784715").unwrap(),

        w8_1: Fr::from_str(
            "19540430494807482326159819597004422086093766032135589407132600596362845576832",
        )
        .unwrap(),
        w8_2: Fr::from_str(
            "21888242871839275217838484774961031246007050428528088939761107053157389710902",
        )
        .unwrap(),
        w8_3: Fr::from_str(
            "13274704216607947843011480449124596415239537050559949017414504948711435969894",
        )
        .unwrap(),
        w8_4: Fr::from_str(
            "21888242871839275222246405745257275088548364400416034343698204186575808495616",
        )
        .unwrap(),
        w8_5: Fr::from_str(
            "2347812377031792896086586148252853002454598368280444936565603590212962918785",
        )
        .unwrap(),
        w8_6: Fr::from_str("4407920970296243842541313971887945403937097133418418784715").unwrap(),
        w8_7: Fr::from_str(
            "8613538655231327379234925296132678673308827349856085326283699237864372525723",
        )
        .unwrap(),
    }
}

pub fn get_proof() -> Proof {
    // let pr = vec![
    //     "0x1af638185408dfa5b1470887ab5bf38a7363f6c26479828ab16eb45219715936",
    //     "0x2b129ebcbf22e11bb2442800922bf1c9979bb7a6c895e17411325e6a1c195912",
    //     "0x0098d7bc29d322c680263a7dba99490333dd42aeafc4ca99f870288f1052cd86",
    //     "0x11c911bfb298b409c74838c0a3c16f7171dac07cddaba283e36090eef091d67f",
    //     "0x29c8c4c86c9d63a57e65dcef548f50c06ce41ffcaadf21f279f66a9f6b59f619",
    //     "0x01eb8b4841e587df317141dd2c198d0160eb974c34dd303f75b27cdac46ce887",
    //     "0x220c39420aa977359e2f2fb3c5d7b9b28a23a7f0c78d6b215d4178d3f2b1ba72",
    //     "0x045c6d18f3e18cc4aac314316a47f0010ba8b1035b7dab678933e5bcd248f72b",
    //     "0x1cc4edb75ac4f07466f70f097d263bad6ca1e1e506bccbccd7de94b39dd3a05e",
    //     "0x0e11ad74cead5ed3d142083b8ad873acf20cb6e39059d88e61a84982386a698a",
    //     "0x23806e3836d9fb0467b1ade5a51564aeda10cc9b97f596456cafa149f6c9bfbb",
    //     "0x1aec381b720257b672376b5ccbd1fe787247e3cc7b2c6ec2d171be1c5c1a5837",
    //     "0x038d7d45919eee4e6c7e47c586b1d55e32d102e56d64513575d94a9aeba30241",
    //     "0x1ba4459cca4bb8b75808d4f38598e4b6cf6a8577f7294def8e85b5955abc681a",
    //     "0x300239f087b7a581948dc4b14cdc9d5ae13ba8a9cbf56998f764ba13549ac6fa",
    //     "0x104d55e131742e10144e0c9023635ee7e000de29d76c05ad56f6a74e40ac9924",
    //     "0x177d85cc56ecaac98dc3c835668105f9ff8311a73767f7ba145d443af8d00999",
    //     "0x1bd5b487cf64d1973cdfbcf8587319d681ab87e595ef347d68067418cca5368f",
    //     "0x27144e4b99a6508fecc7b0fdc1a64d4be4760a1035730e29a907dd091c6b95ac",
    //     "0x1e8841cdf20050bfe02cbeb022b26960e8b544774112e09a21a440c8bba503d3",
    //     "0x15273dd6fecfedef5adde005a7ab5ee48a7eefdaa85ef4e356d0f3dcd92bcb64",
    //     "0x267735dcdbd34c8c5f8cf864f3990e078d26a928a54c27485133b6d0678cda9b",
    //     "0x1a193153f3cf956d68aab8afe447f0f6ba985f40edba7d9375b9368f1c55f31b",
    //     "0x0e1a49d180902645b8954552c99af04aed9315725b32ac2623965f887a7a5849",
    // ];

    let pr = vec![
        "12195165594784431822497303968938621279445690754376121387655513728730220550454", 
        "19482351300768228183728567743975524187837254971200066453308487514712354412818", 
        "270049702185508019342640204324826241417613526941291105097079886683911146886", 
        "8044577183782099118358991257374623532841698893838076750142877485824795072127", 
        "18899554350581376849619715242908819289791150067233598694602356239698407061017", 
        "868483199604273061042760252576862685842931472081080113229115026384087738503" ,
        "15400234196629481957150851143665757067987965100904384175896686561307554593394", 
        "1972554287366869807517068788787992038621302618305780153544292964897315682091" ,
        "13012702442141574024514112866712813523553321876510290446303561347565844930654" ,
        "6363613431504422665441435540021253583148414748729550612486380209002057984394" ,
        "16057866832337652851142304414708366836077577338023656646690877057031251541947" ,
        "12177497208173170035464583425607209406245985123797536695060336171641250404407" ,
        "1606928575748882874942488864331180511279674792603033713048693169239812670017" ,
        "12502690277925689095499239281542937835831064619179570213662273016815222024218" ,
        "21714950310348017755786780913378098925832975432250486683702036755613488957178" ,
        "7373645520955771058170141217317033724805640797155623483741097103589211150628" ,
        "10624974841759884514517518996672059640247361745924203600968035963539096078745" ,
        "12590031312322329503809710776715067780944838760473156014126576247831324341903" ,
        "17676078410435205056317710999346173532618821076911845052950090109177062725036" ,
        "13810130824095164415807955516712763121131180676617650812233616232528698737619" ,
        "9567903658565551430748252507556148460902008866092926659415720362326593620836" ,
        "17398514793767712415669438995039049448391479578008786242788501594157890722459" ,
        "11804645688707233673914574834599506530652461017683048951953032091830492459803" ,
        "6378827379501409574366452872421073840754012879130221505294134572417254316105" ,
    ];

    // for i in 0..pr.len() {
    //     // println!("{}: {}", i, pr[i]);
    //   let val = &U256::from_str(pr[i]).unwrap().to_string();
    //   println!(" \"{},\" ", val);
    // }

    let c1_x =
        <G1Point as AffineCurve>::BaseField::from_str(pr[0])
            .unwrap();
    let c1_y =
        <G1Point as AffineCurve>::BaseField::from_str(pr[1])
            .unwrap();
    let c1_affine = G1Projective::new(
        c1_x,
        c1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let c2_x =
        <G1Point as AffineCurve>::BaseField::from_str(pr[2])
            .unwrap();
    let c2_y =
        <G1Point as AffineCurve>::BaseField::from_str(pr[3])
            .unwrap();
    let c2_affine = G1Projective::new(
        c2_x,
        c2_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let w1_x =
        <G1Point as AffineCurve>::BaseField::from_str(pr[4])
            .unwrap();
    let w1_y =
        <G1Point as AffineCurve>::BaseField::from_str(pr[5])
            .unwrap();
    let w1_affine = G1Projective::new(
        w1_x,
        w1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let w2_x =
        <G1Point as AffineCurve>::BaseField::from_str(pr[6])
            .unwrap();
    let w2_y =
        <G1Point as AffineCurve>::BaseField::from_str(pr[7])
            .unwrap();
    let w2_affine = G1Projective::new(
        w2_x,
        w2_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    Proof {
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
    }
}

pub fn get_domain_size() -> Fp256<FrParameters> {
    Fr::from_str("16777216").unwrap()
}

pub fn get_pubSignals() -> Fp256<FrParameters> {
    Fr::from_str("14516932981781041565586298118536599721399535462624815668597272732223874827152")
        .unwrap()
}

pub fn computeLagrange(
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
) -> Fp256<FrParameters> {
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

    inverseArray(
        denH1,
        denH2,
        zhInv,
        li_s0_inv,
        li_s1_inv,
        li_s2_inv,
        &mut eval_l1,
    );

    eval_l1
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
) {
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

    for i in 0..8{
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

    // println!("local_zh_inv: {}", local_zh_inv);
}

pub fn verify() {
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

    let zhinv: Fp256<FrParameters> = Fr::from_str(
        "8663234610000964594764035144827003258323335914482598945994186647593190381653",
    )
    .unwrap();

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

    let mut eval_l1 = calculateInversions(y, xi, zhinv, h0w8, h1w4, h2w3, h3w3);
    println!("eval_l1: {}", eval_l1);

    eval_l1 = computeLagrange(zh, eval_l1);

    println!("Final lagrange eval_l1: {}", eval_l1);

    // computePi(get_pubSignals(), eval_l1);

    println!("Verifying proof...");

    let R0 = calculateR0(xi);
    let R1 = calculateR1(xi);
    calculateR2(xi, gamma, beta);
    // let R2 = calculateR2(xi);
}

fn calculateR0(xi: Fp256<FrParameters>) -> Fp256<FrParameters> {
    let eval_ql = Fr::from_str(
        "13012702442141574024514112866712813523553321876510290446303561347565844930654",
    )
    .unwrap();
    let eval_qr = Fr::from_str(
        "6363613431504422665441435540021253583148414748729550612486380209002057984394",
    )
    .unwrap();
    let eval_qm = Fr::from_str(
        "16057866832337652851142304414708366836077577338023656646690877057031251541947",
    )
    .unwrap();
    let eval_qo = Fr::from_str(
        "12177497208173170035464583425607209406245985123797536695060336171641250404407",
    )
    .unwrap();
    let eval_qc = Fr::from_str(
        "1606928575748882874942488864331180511279674792603033713048693169239812670017",
    )
    .unwrap();
    let eval_s1 = Fr::from_str(
        "12502690277925689095499239281542937835831064619179570213662273016815222024218",
    )
    .unwrap();
    let eval_s2 = Fr::from_str(
        "21714950310348017755786780913378098925832975432250486683702036755613488957178",
    )
    .unwrap();
    let eval_s3 = Fr::from_str(
        "7373645520955771058170141217317033724805640797155623483741097103589211150628",
    )
    .unwrap();

    let y = Fr::from_str(
        "13096643561003703188657823618924776735424142649986849213485512124502494958287",
    )
    .unwrap();

    let mut num = Fr::from_str("1").unwrap();
    let y__8 = y.pow([8]);
    num = num.mul(y__8);
    num = num.add(-xi);

    println!("num: {:?}", num.to_string());

    let mut h0w80 = Fr::from_str(
        "6217280567245217757583020595539628144853576189258393757880925561134573660857",
    )
    .unwrap();

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

    let pLiS0Inv_term =
        Fr::from_str("169426721603702040203361260122099036844252568090350847256434782251913759428")
            .unwrap();
    let pH0w8_1_term = Fr::from_str(
        "6467474964103268828445749503025875230771477005123038192746478572392917288085",
    )
    .unwrap();

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

    let pLiS0Inv_32_term = Fr::from_str(
        "14857415132211068553935392518689134105014595040875579698823186778843823625742",
    )
    .unwrap();

    let res_2 = res.add(c0Value.mul(num.mul(pLiS0Inv_32_term)));

    println!("res_2: {:?}", res_2.to_string());

    let pH0w8_2_term = Fr::from_str(
        "17058617445718799367294447696955508815020408034987705203621830040667799234184",
    )
    .unwrap();

    let pH0w8_3_term = Fr::from_str(
        "21316856612335037613757111596833720133546507460560319301014759512314160286103",
    )
    .unwrap();
    let pH0w8_4_term = Fr::from_str(
        "15670962304594057464663385149717646943694788211157640585817278625441234834760",
    )
    .unwrap();
    let pH0w8_5_term = Fr::from_str(
        "15420767907736006393800656242231399857776887395292996150951725614182891207532",
    )
    .unwrap();
    let pH0w8_6_term = Fr::from_str(
        "4829625426120475854951958048301766273527956365428329140076374145908009261433",
    )
    .unwrap();
    let pH0w8_7_term =
        Fr::from_str("571386259504237608489294148423554955001856939855715042683444674261648209514")
            .unwrap();

    let pLiS0Inv_64_term = Fr::from_str(
        "19499818470877388188618764011908347522427981376836110889591294651706164036883",
    )
    .unwrap();
    let pLiS0Inv_96_term = Fr::from_str(
        "12230430430123277051648593193909194010524731523942713458960326841142416752492",
    )
    .unwrap();
    let pLiS0Inv_128_term = Fr::from_str(
        "5126944045649383063127925823049128280433624872562175779448940177189724065181",
    )
    .unwrap();
    let pLiS0Inv_160_term = Fr::from_str(
        "5568669638657658207374981883763206083144030294353644128404077931588257238271",
    )
    .unwrap();
    let pLiS0Inv_192_term = Fr::from_str(
        "13729581809580474302278683247897745531424316205584835263519833651663333148307",
    )
    .unwrap();
    let pLiS0Inv_224_term = Fr::from_str(
        "10213683763403643593212850841764869657247040603744661309904686540295590892881",
    )
    .unwrap();

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
    println!("res_8: {:?}", res_8.to_string());

    res_8
}

fn calculateR1(xi: Fp256<FrParameters>) -> Fp256<FrParameters> {
    let mut num = Fr::from_str("1").unwrap();
    let y = Fr::from_str(
        "13096643561003703188657823618924776735424142649986849213485512124502494958287",
    )
    .unwrap();
    let eval_a = Fr::from_str(
        "10624974841759884514517518996672059640247361745924203600968035963539096078745",
    )
    .unwrap();
    let eval_b = Fr::from_str(
        "12590031312322329503809710776715067780944838760473156014126576247831324341903",
    )
    .unwrap();
    let eval_c = Fr::from_str(
        "17676078410435205056317710999346173532618821076911845052950090109177062725036",
    )
    .unwrap();
    let pi = Fr::from_str(
        "8186154661026746046469382287670065360733981791589619791068274898784422808583",
    )
    .unwrap();
    let zinv = Fr::from_str(
        "5003111610252004233397444097453114204704498339788572052799252538137556416518",
    )
    .unwrap();

    let H1w4_0 =
        Fr::from_str("19942750751199432676942609926442586439740980242021920220189719874523203538")
            .unwrap();
    let H1w4_1 = Fr::from_str(
        "6070134217614975914195815562203672780869780328825257598131939473058160967520",
    )
    .unwrap();
    let H1w4_2 = Fr::from_str(
        "21868300121088075789569463135330832502108623420174012423478014466701285292079",
    )
    .unwrap();
    let H1w4_3 = Fr::from_str(
        "15818108654224299308050590183053602307678584071590776745566264713517647528097",
    )
    .unwrap();
    let eval_ql = Fr::from_str(
        "13012702442141574024514112866712813523553321876510290446303561347565844930654",
    )
    .unwrap();
    let eval_qr = Fr::from_str(
        "6363613431504422665441435540021253583148414748729550612486380209002057984394",
    )
    .unwrap();
    let eval_qm = Fr::from_str(
        "16057866832337652851142304414708366836077577338023656646690877057031251541947",
    )
    .unwrap();
    let eval_qo = Fr::from_str(
        "12177497208173170035464583425607209406245985123797536695060336171641250404407",
    )
    .unwrap();
    let eval_qc = Fr::from_str(
        "1606928575748882874942488864331180511279674792603033713048693169239812670017",
    )
    .unwrap();
    let pLiS1Inv_0_term =
        Fr::from_str("256600192143913399847065388940725172783235866632911365432425934771171503129")
            .unwrap();
    let pLiS1Inv_32_term = Fr::from_str(
        "3934696977981541056227007359974293215605002917158416054650075484355207678854",
    )
    .unwrap();
    let pLiS1Inv_64_term = Fr::from_str(
        "10842349659271580751215767090163155520270237289395195387702921929214464444051",
    )
    .unwrap();
    let pLiS1Inv_96_term = Fr::from_str(
        "14288814425393068574743899923526789505554250926531613540112244065507183041260",
    )
    .unwrap();

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
    println!("res_4: {:?}", res_4.to_string());

    res_4
}

fn calculateR2(xi: Fp256<FrParameters>, gamma: Fp256<FrParameters>, beta: Fp256<FrParameters>) {
    let eval_a = Fr::from_str(
        "10624974841759884514517518996672059640247361745924203600968035963539096078745",
    )
    .unwrap();
    let eval_b = Fr::from_str(
        "12590031312322329503809710776715067780944838760473156014126576247831324341903",
    )
    .unwrap();
    let eval_c = Fr::from_str(
        "17676078410435205056317710999346173532618821076911845052950090109177062725036",
    )
    .unwrap();
    let w1 = Fr::from_str(
        "5709868443893258075976348696661355716898495876243883251619397131511003808859",
    )
    .unwrap();
    let mut num = Fr::from_str("1").unwrap();
    let eval_z = Fr::from_str(
        "13810130824095164415807955516712763121131180676617650812233616232528698737619",
    )
    .unwrap();
    let betaxi = Fr::from_str(
        "15857722237427290894966863399309025470051084474506034024114905506714284882191",
    )
    .unwrap();
    let y = Fr::from_str(
        "13096643561003703188657823618924776735424142649986849213485512124502494958287",
    )
    .unwrap();
    let y__6 = y.pow([6]);
    let k1 = Fr::from_str("2").unwrap();
    let k2 = Fr::from_str("3").unwrap();
    let eval_s1 = Fr::from_str(
        "12502690277925689095499239281542937835831064619179570213662273016815222024218",
    )
    .unwrap();
    let eval_s2 = Fr::from_str(
        "21714950310348017755786780913378098925832975432250486683702036755613488957178",
    )
    .unwrap();
    let eval_s3 = Fr::from_str(
        "7373645520955771058170141217317033724805640797155623483741097103589211150628",
    )
    .unwrap();
    let eval_zw = Fr::from_str(
        "9567903658565551430748252507556148460902008866092926659415720362326593620836",
    )
    .unwrap();
    let eval_l1 = Fr::from_str(
        "17123728796310884659041981565369226818029855344213299425378416793319228696720",
    )
    .unwrap();
    let zinv = Fr::from_str(
        "5003111610252004233397444097453114204704498339788572052799252538137556416518",
    )
    .unwrap();
    let h2w3_0 = Fr::from_str(
        "1869756320377877312595498521504015597511420477452283464861296949200508189845",
    )
    .unwrap();
    let h2w3_1 = Fr::from_str(
        "12855200334058046664672080384376966021199960394800133527288768963888158252355",
    )
    .unwrap();
    let h2w3_2 = Fr::from_str(
        "7163286217403351244978826839376293469836983528163617351548138273487142053417",
    )
    .unwrap();
    let h3w3_0 = Fr::from_str(
        "20221471501150487562916135566783003531433279751312695446481128041754069339168",
    )
    .unwrap();
    let h3w3_1 = Fr::from_str(
        "5182315555253909512081724539694463779341668914354906154606878795853655230920",
    )
    .unwrap();
    let h3w3_2 = Fr::from_str(
        "18372698687274153369494951384037082866321780135164467086308401535543892421146",
    )
    .unwrap();
    let pLiS2Inv_0_term =
        Fr::from_str("206374939483274985005531976845830683776047704156323693993869955347636075037")
            .unwrap();
    let pLiS2Inv_32_term = Fr::from_str(
        "17619227702648466802030149243931305700224905921105961026046579639394843879032",
    )
    .unwrap();
    let pLiS2Inv_64_term = Fr::from_str(
        "7625875599226743107833355966417515764612634159114507249220768248349546906394",
    )
    .unwrap();
    let pLiS2Inv_96_term = Fr::from_str(
        "21800233121663628999560820763114161007935197834912703103987736478449695374075",
    )
    .unwrap();
    let pLiS2Inv_128_term = Fr::from_str(
        "10282071463295254039490411320866497845965519995172511751077123617826155505212",
    )
    .unwrap();
    let pLiS2Inv_160_term = Fr::from_str(
        "13346764022296828137286564942239033331943591246683467841936936305120517223935",
    )
    .unwrap();
    let eval_t1w = Fr::from_str(
        "17398514793767712415669438995039049448391479578008786242788501594157890722459",
    )
    .unwrap();
    let eval_t2w = Fr::from_str(
        "11804645688707233673914574834599506530652461017683048951953032091830492459803",
    )
    .unwrap();

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
}
