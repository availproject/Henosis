use ark_bn254::{g1, g1::Parameters, Bn254, FqParameters, Fr, FrParameters, G1Projective};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::*;
use ark_ff::{Field, Fp256, Fp256Parameters, One, PrimeField, UniformRand, Zero};
use ark_poly::univariate::DensePolynomial;
use ark_poly::{domain, Polynomial};
use num_bigint::*;
use std::fmt::{Debug, DebugMap, Display};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};
use std::str::FromStr;

pub type G1Point = <Bn254 as PairingEngine>::G1Affine;
pub type G2Point = <Bn254 as PairingEngine>::G2Affine;
//  // Proof calldata


pub struct ProofBigInt {
    pub c1: (BigInt, BigInt),
    pub c2: (BigInt, BigInt),
    pub w1: (BigInt, BigInt),
    pub w2: (BigInt, BigInt),

    pub eval_ql: BigInt,
    pub eval_qr: BigInt,
    pub eval_qm: BigInt,
    pub eval_qo: BigInt,
    pub eval_qc: BigInt,
    pub eval_s1: BigInt,
    pub eval_s2: BigInt,
    pub eval_s3: BigInt,
    pub eval_a: BigInt,
    pub eval_b: BigInt,
    pub eval_c: BigInt,
    pub eval_z: BigInt,
    pub eval_zw: BigInt,
    pub eval_t1w: BigInt,
    pub eval_t2w: BigInt,
    pub eval_inv: BigInt,
}

#[derive(Debug, Clone)]
pub struct Proof {
   pub c1: G1Point,
   pub c2: G1Point,
   pub w1: G1Point,
   pub w2: G1Point,

   pub eval_ql: Fp256<FrParameters>,
   pub eval_qr: Fp256<FrParameters>,
   pub eval_qm: Fp256<FrParameters>,
   pub eval_qo: Fp256<FrParameters>,
   pub eval_qc: Fp256<FrParameters>,
   pub eval_s1: Fp256<FrParameters>,
   pub eval_s2: Fp256<FrParameters>,
   pub eval_s3: Fp256<FrParameters>,
   pub eval_a: Fp256<FrParameters>,
   pub eval_b: Fp256<FrParameters>,
   pub eval_c: Fp256<FrParameters>,
   pub eval_z: Fp256<FrParameters>,
   pub eval_zw: Fp256<FrParameters>,
   pub eval_t1w: Fp256<FrParameters>,
   pub eval_t2w: Fp256<FrParameters>,
   pub eval_inv: Fp256<FrParameters>,
}

pub struct Omegas {
    pub w1: Fp256<FrParameters>,
    pub wr: Fp256<FrParameters>,

    pub w3: Fp256<FrParameters>,
    pub w3_2: Fp256<FrParameters>,

    pub w4: Fp256<FrParameters>,
    pub w4_2: Fp256<FrParameters>,
    pub w4_3: Fp256<FrParameters>,

    pub w8_1: Fp256<FrParameters>,
    pub w8_2: Fp256<FrParameters>,
    pub w8_3: Fp256<FrParameters>,
    pub w8_4: Fp256<FrParameters>,
    pub w8_5: Fp256<FrParameters>,
    pub w8_6: Fp256<FrParameters>,
    pub w8_7: Fp256<FrParameters>,
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


pub fn get_proog_bigint() -> ProofBigInt {
    ProofBigInt{
        c1: (
            BigInt::parse_bytes(b"12195165594784431822497303968938621279445690754376121387655513728730220550454", 10).unwrap(),
            BigInt::parse_bytes(b"19482351300768228183728567743975524187837254971200066453308487514712354412818", 10).unwrap(),
        ),
        c2: (
            BigInt::parse_bytes(b"270049702185508019342640204324826241417613526941291105097079886683911146886", 10).unwrap(),
            BigInt::parse_bytes(b"8044577183782099118358991257374623532841698893838076750142877485824795072127", 10).unwrap(),
        ),
        w1: (
            BigInt::parse_bytes(b"18899554350581376849619715242908819289791150067233598694602356239698407061017", 10).unwrap(),
            BigInt::parse_bytes(b"868483199604273061042760252576862685842931472081080113229115026384087738503", 10).unwrap(),
        ),
        w2: (
            BigInt::parse_bytes(b"15400234196629481957150851143665757067987965100904384175896686561307554593394", 10).unwrap(),
            BigInt::parse_bytes(b"1972554287366869807517068788787992038621302618305780153544292964897315682091", 10).unwrap(),
        ),
        eval_ql: BigInt::parse_bytes(b"13012702442141574024514112866712813523553321876510290446303561347565844930654", 10).unwrap(),
        eval_qr: BigInt::parse_bytes(b"6363613431504422665441435540021253583148414748729550612486380209002057984394", 10
        ).unwrap(),
        eval_qm: BigInt::parse_bytes(b"16057866832337652851142304414708366836077577338023656646690877057031251541947", 10).unwrap(),
        eval_qo: BigInt::parse_bytes(b"12177497208173170035464583425607209406245985123797536695060336171641250404407", 10).unwrap(),
        eval_qc: BigInt::parse_bytes(b"1606928575748882874942488864331180511279674792603033713048693169239812670017", 10
        ).unwrap(),
        eval_s1: BigInt::parse_bytes(b"12502690277925689095499239281542937835831064619179570213662273016815222024218", 10).unwrap(),
        eval_s2: BigInt::parse_bytes(b"21714950310348017755786780913378098925832975432250486683702036755613488957178", 10).unwrap(),
        eval_s3: BigInt::parse_bytes(b"7373645520955771058170141217317033724805640797155623483741097103589211150628", 10
        ).unwrap(),
        eval_a: BigInt::parse_bytes(b"10624974841759884514517518996672059640247361745924203600968035963539096078745", 10).unwrap(),
        eval_b: BigInt::parse_bytes(b"12590031312322329503809710776715067780944838760473156014126576247831324341903", 10).unwrap(),
        eval_c: BigInt::parse_bytes(b"17676078410435205056317710999346173532618821076911845052950090109177062725036", 10).unwrap(),
        eval_z: BigInt::parse_bytes(b"13810130824095164415807955516712763121131180676617650812233616232528698737619", 10).unwrap(),
        eval_zw: BigInt::parse_bytes(b"9567903658565551430748252507556148460902008866092926659415720362326593620836", 10
        ).unwrap(),
        eval_t1w: BigInt::parse_bytes(b"17398514793767712415669438995039049448391479578008786242788501594157890722459", 10).unwrap(),
        eval_t2w: BigInt::parse_bytes(b"11804645688707233673914574834599506530652461017683048951953032091830492459803", 10).unwrap(),
        eval_inv: BigInt::parse_bytes(b"6378827379501409574366452872421073840754012879130221505294134572417254316105", 10).unwrap(),    

    }
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

pub fn get_domain_size() -> Fp256<FrParameters> {
    Fr::from_str("16777216").unwrap()
}

pub fn get_pubSignals() -> Fp256<FrParameters> {
    Fr::from_str("14516932981781041565586298118536599721399535462624815668597272732223874827152")
        .unwrap()
}
