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
use ethers::{
    abi::{Token, Tokenizable},
    types::U256,
};


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

pub fn get_domain_size() -> Fp256<FrParameters> {
    Fr::from_str("16777216").unwrap()
}


pub fn calculateInversions(y : Fp256<FrParameters>, xi: Fp256<FrParameters>  , h0w8:Vec<Fp256<FrParameters>>  ,h1w4: Vec<Fp256<FrParameters>>, h2w3: Vec<Fp256<FrParameters>>, h3w3: Vec<Fp256<FrParameters>>) {
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

    println!("eval_l1: {}", eval_l1);

}


pub fn computeLiS0(y : Fp256<FrParameters>, h0w8: Vec<Fp256<FrParameters>>) -> Fp256<FrParameters>{

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

    li_s0_inv[7]
}

pub fn computeLiS1(y : Fp256<FrParameters>, h1w4: Vec<Fp256<FrParameters>>) -> Fp256<FrParameters>{

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
    li_s1_inv[3]
}


pub fn computeLiS2(y : Fp256<FrParameters>, xi:Fp256<FrParameters> ,h2w3: Vec<Fp256<FrParameters>>, h3w3: Vec<Fp256<FrParameters>>) -> Fp256<FrParameters>{
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

    li_s2_inv[5]
}


// function computeLiS0(pMem) {
//     let root0 := mload(add(pMem, pH0w8_0))
//     let y := mload(add(pMem, pY))
//     let den1 := 1
//     den1 := mulmod(den1, root0, q)
//     den1 := mulmod(den1, root0, q)
//     den1 := mulmod(den1, root0, q)
//     den1 := mulmod(den1, root0, q)
//     den1 := mulmod(den1, root0, q)
//     den1 := mulmod(den1, root0, q)
    
//     den1 := mulmod(8, den1, q)

//     let den2 := mload(add(pMem, add(pH0w8_0, mul(mod(mul(7, 0), 8), 32))))
//     let den3 := addmod(y, mod(sub(q, mload(add(pMem, add(pH0w8_0, mul(0, 32))))), q), q)

//     mstore(add(pMem, add(pLiS0Inv, 0)), mulmod(den1, mulmod(den2, den3, q), q))

//     den2 := mload(add(pMem, add(pH0w8_0, mul(mod(mul(7, 1), 8), 32))))
//     den3 := addmod(y, mod(sub(q, mload(add(pMem, add(pH0w8_0, mul(1, 32))))), q), q)

//     mstore(add(pMem, add(pLiS0Inv, 32)), mulmod(den1, mulmod(den2, den3, q), q))

//     den2 := mload(add(pMem, add(pH0w8_0, mul(mod(mul(7, 2), 8), 32))))
//     den3 := addmod(y, mod(sub(q, mload(add(pMem, add(pH0w8_0, mul(2, 32))))), q), q)

//     mstore(add(pMem, add(pLiS0Inv, 64)), mulmod(den1, mulmod(den2, den3, q), q))

//     den2 := mload(add(pMem, add(pH0w8_0, mul(mod(mul(7, 3), 8), 32))))
//     den3 := addmod(y, mod(sub(q, mload(add(pMem, add(pH0w8_0, mul(3, 32))))), q), q)

//     mstore(add(pMem, add(pLiS0Inv, 96)), mulmod(den1, mulmod(den2, den3, q), q))

//     den2 := mload(add(pMem, add(pH0w8_0, mul(mod(mul(7, 4), 8), 32))))
//     den3 := addmod(y, mod(sub(q, mload(add(pMem, add(pH0w8_0, mul(4, 32))))), q), q)

//     mstore(add(pMem, add(pLiS0Inv, 128)), mulmod(den1, mulmod(den2, den3, q), q))

//     den2 := mload(add(pMem, add(pH0w8_0, mul(mod(mul(7, 5), 8), 32))))
//     den3 := addmod(y, mod(sub(q, mload(add(pMem, add(pH0w8_0, mul(5, 32))))), q), q)

//     mstore(add(pMem, add(pLiS0Inv, 160)), mulmod(den1, mulmod(den2, den3, q), q))

//     den2 := mload(add(pMem, add(pH0w8_0, mul(mod(mul(7, 6), 8), 32))))
//     den3 := addmod(y, mod(sub(q, mload(add(pMem, add(pH0w8_0, mul(6, 32))))), q), q)

//     mstore(add(pMem, add(pLiS0Inv, 192)), mulmod(den1, mulmod(den2, den3, q), q))

//     den2 := mload(add(pMem, add(pH0w8_0, mul(mod(mul(7, 7), 8), 32))))
//     den3 := addmod(y, mod(sub(q, mload(add(pMem, add(pH0w8_0, mul(7, 32))))), q), q)

//     mstore(add(pMem, add(pLiS0Inv, 224)), mulmod(den1, mulmod(den2, den3, q), q))

// }



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


    

    calculateInversions(y,xi,  h0w8, h1w4, h2w3, h3w3);
    println!("Verifying proof...");
}
