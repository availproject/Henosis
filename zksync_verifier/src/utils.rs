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

    // uint256 internal constant PROOF_PUBLIC_INPUT = 0x200 + 0x520 + 0x000;

    // uint256 internal constant PROOF_STATE_POLYS_0_X_SLOT = 0x200 + 0x520 + 0x020;
    // uint256 internal constant PROOF_STATE_POLYS_0_Y_SLOT = 0x200 + 0x520 + 0x040;
    // uint256 internal constant PROOF_STATE_POLYS_1_X_SLOT = 0x200 + 0x520 + 0x060;
    // uint256 internal constant PROOF_STATE_POLYS_1_Y_SLOT = 0x200 + 0x520 + 0x080;
    // uint256 internal constant PROOF_STATE_POLYS_2_X_SLOT = 0x200 + 0x520 + 0x0a0;
    // uint256 internal constant PROOF_STATE_POLYS_2_Y_SLOT = 0x200 + 0x520 + 0x0c0;
    // uint256 internal constant PROOF_STATE_POLYS_3_X_SLOT = 0x200 + 0x520 + 0x0e0;
    // uint256 internal constant PROOF_STATE_POLYS_3_Y_SLOT = 0x200 + 0x520 + 0x100;

    // uint256 internal constant PROOF_COPY_PERMUTATION_GRAND_PRODUCT_X_SLOT = 0x200 + 0x520 + 0x120;
    // uint256 internal constant PROOF_COPY_PERMUTATION_GRAND_PRODUCT_Y_SLOT = 0x200 + 0x520 + 0x140;

    // uint256 internal constant PROOF_LOOKUP_S_POLY_X_SLOT = 0x200 + 0x520 + 0x160;
    // uint256 internal constant PROOF_LOOKUP_S_POLY_Y_SLOT = 0x200 + 0x520 + 0x180;

    // uint256 internal constant PROOF_LOOKUP_GRAND_PRODUCT_X_SLOT = 0x200 + 0x520 + 0x1a0;
    // uint256 internal constant PROOF_LOOKUP_GRAND_PRODUCT_Y_SLOT = 0x200 + 0x520 + 0x1c0;

    // uint256 internal constant PROOF_QUOTIENT_POLY_PARTS_0_X_SLOT = 0x200 + 0x520 + 0x1e0;
    // uint256 internal constant PROOF_QUOTIENT_POLY_PARTS_0_Y_SLOT = 0x200 + 0x520 + 0x200;
    // uint256 internal constant PROOF_QUOTIENT_POLY_PARTS_1_X_SLOT = 0x200 + 0x520 + 0x220;
    // uint256 internal constant PROOF_QUOTIENT_POLY_PARTS_1_Y_SLOT = 0x200 + 0x520 + 0x240;
    // uint256 internal constant PROOF_QUOTIENT_POLY_PARTS_2_X_SLOT = 0x200 + 0x520 + 0x260;
    // uint256 internal constant PROOF_QUOTIENT_POLY_PARTS_2_Y_SLOT = 0x200 + 0x520 + 0x280;
    // uint256 internal constant PROOF_QUOTIENT_POLY_PARTS_3_X_SLOT = 0x200 + 0x520 + 0x2a0;
    // uint256 internal constant PROOF_QUOTIENT_POLY_PARTS_3_Y_SLOT = 0x200 + 0x520 + 0x2c0;

    // uint256 internal constant PROOF_STATE_POLYS_0_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x2e0;
    // uint256 internal constant PROOF_STATE_POLYS_1_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x300;
    // uint256 internal constant PROOF_STATE_POLYS_2_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x320;
    // uint256 internal constant PROOF_STATE_POLYS_3_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x340;

    // uint256 internal constant PROOF_STATE_POLYS_3_OPENING_AT_Z_OMEGA_SLOT = 0x200 + 0x520 + 0x360;
    // uint256 internal constant PROOF_GATE_SELECTORS_0_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x380;

    // uint256 internal constant PROOF_COPY_PERMUTATION_POLYS_0_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x3a0;
    // uint256 internal constant PROOF_COPY_PERMUTATION_POLYS_1_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x3c0;
    // uint256 internal constant PROOF_COPY_PERMUTATION_POLYS_2_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x3e0;

    // uint256 internal constant PROOF_COPY_PERMUTATION_GRAND_PRODUCT_OPENING_AT_Z_OMEGA_SLOT = 0x200 + 0x520 + 0x400;
    // uint256 internal constant PROOF_LOOKUP_S_POLY_OPENING_AT_Z_OMEGA_SLOT = 0x200 + 0x520 + 0x420;
    // uint256 internal constant PROOF_LOOKUP_GRAND_PRODUCT_OPENING_AT_Z_OMEGA_SLOT = 0x200 + 0x520 + 0x440;
    // uint256 internal constant PROOF_LOOKUP_T_POLY_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x460;
    // uint256 internal constant PROOF_LOOKUP_T_POLY_OPENING_AT_Z_OMEGA_SLOT = 0x200 + 0x520 + 0x480;
    // uint256 internal constant PROOF_LOOKUP_SELECTOR_POLY_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x4a0;
    // uint256 internal constant PROOF_LOOKUP_TABLE_TYPE_POLY_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x4c0;
    // uint256 internal constant PROOF_QUOTIENT_POLY_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x4e0;
    // uint256 internal constant PROOF_LINEARISATION_POLY_OPENING_AT_Z_SLOT = 0x200 + 0x520 + 0x500;

    // uint256 internal constant PROOF_OPENING_PROOF_AT_Z_X_SLOT = 0x200 + 0x520 + 0x520;
    // uint256 internal constant PROOF_OPENING_PROOF_AT_Z_Y_SLOT = 0x200 + 0x520 + 0x540;
    // uint256 internal constant PROOF_OPENING_PROOF_AT_Z_OMEGA_X_SLOT = 0x200 + 0x520 + 0x560;
    // uint256 internal constant PROOF_OPENING_PROOF_AT_Z_OMEGA_Y_SLOT = 0x200 + 0x520 + 0x580;

    // uint256 internal constant PROOF_RECURSIVE_PART_P1_X_SLOT = 0x200 + 0x520 + 0x5a0;
    // uint256 internal constant PROOF_RECURSIVE_PART_P1_Y_SLOT = 0x200 + 0x520 + 0x5c0;

    // uint256 internal constant PROOF_RECURSIVE_PART_P2_X_SLOT = 0x200 + 0x520 + 0x5e0;
    // uint256 internal constant PROOF_RECURSIVE_PART_P2_Y_SLOT = 0x200 + 0x520 + 0x600;

    pub state_poly_0: G1Point,
    pub state_poly_1: G1Point,
    pub state_poly_2: G1Point,
    pub state_poly_3: G1Point,

    pub copy_permutation_grand_product: G1Point,

    pub lookup_s_poly: G1Point,

    pub lookup_grand_product: G1Point,

    pub quotient_poly_parts_0: G1Point,
    pub quotient_poly_parts_1: G1Point,
    pub quotient_poly_parts_2: G1Point,
    pub quotient_poly_parts_3: G1Point,

    pub state_poly_0_opening_at_z: Fr,
    pub state_poly_1_opening_at_z: Fr,
    pub state_poly_2_opening_at_z: Fr,
    pub state_poly_3_opening_at_z: Fr,

    pub state_poly_3_opening_at_z_omega: Fr,
    pub gate_selectors_0_opening_at_z: Fr,

    pub copy_permutation_polys_0_opening_at_z: Fr,
    pub copy_permutation_polys_1_opening_at_z: Fr,
    pub copy_permutation_polys_2_opening_at_z: Fr,

    pub copy_permutation_grand_product_opening_at_z_omega: Fr,
    pub lookup_s_poly_opening_at_z_omega: Fr,
    pub lookup_grand_product_opening_at_z_omega: Fr,
    pub lookup_t_poly_opening_at_z: Fr,
    pub lookup_t_poly_opening_at_z_omega: Fr,
    pub lookup_selector_poly_opening_at_z: Fr,
    pub lookup_table_type_poly_opening_at_z: Fr,
    pub quotient_poly_opening_at_z: Fr,
    pub linearisation_poly_opening_at_z: Fr,

    pub opening_proof_at_z: G1Point,
    pub opening_proof_at_z_omega: G1Point,

    // pub recursive_part_p1: G1Point,

    // pub recursive_part_p2: G1Point,
    
}

#[derive(Debug, Clone)]
pub struct ProofWithPubSignal {
    pub proof: Proof,
    pub pub_signal: Fp256<FrParameters>
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

// pub fn construct_proof(
//     proof_values: Vec<&str>,
//     pub_signal: Fp256<FrParameters>,
// ) -> ProofWithPubSignal {
//     let c1_x = <G1Point as AffineCurve>::BaseField::from_str(proof_values[0]).unwrap();
//     let c1_y = <G1Point as AffineCurve>::BaseField::from_str(proof_values[1]).unwrap();
//     let c1_affine = G1Projective::new(
//         c1_x,
//         c1_y,
//         <G1Projective as ProjectiveCurve>::BaseField::one(),
//     )
//     .into_affine();

//     let c2_x = <G1Point as AffineCurve>::BaseField::from_str(proof_values[2]).unwrap();
//     let c2_y = <G1Point as AffineCurve>::BaseField::from_str(proof_values[3]).unwrap();
//     let c2_affine = G1Projective::new(
//         c2_x,
//         c2_y,
//         <G1Projective as ProjectiveCurve>::BaseField::one(),
//     )
//     .into_affine();

//     let w1_x = <G1Point as AffineCurve>::BaseField::from_str(proof_values[4]).unwrap();
//     let w1_y = <G1Point as AffineCurve>::BaseField::from_str(proof_values[5]).unwrap();
//     let w1_affine = G1Projective::new(
//         w1_x,
//         w1_y,
//         <G1Projective as ProjectiveCurve>::BaseField::one(),
//     )
//     .into_affine();

//     let w2_x = <G1Point as AffineCurve>::BaseField::from_str(proof_values[6]).unwrap();
//     let w2_y = <G1Point as AffineCurve>::BaseField::from_str(proof_values[7]).unwrap();
//     let w2_affine = G1Projective::new(
//         w2_x,
//         w2_y,
//         <G1Projective as ProjectiveCurve>::BaseField::one(),
//     )
//     .into_affine();

//     let proof = Proof {
//         c1: c1_affine,
//         c2: c2_affine,
//         w1: w1_affine,
//         w2: w2_affine,
//         eval_ql: Fr::from_str(proof_values[8]).unwrap(),
//         eval_qr: Fr::from_str(proof_values[9]).unwrap(),
//         eval_qm: Fr::from_str(proof_values[10]).unwrap(),
//         eval_qo: Fr::from_str(proof_values[11]).unwrap(),
//         eval_qc: Fr::from_str(proof_values[12]).unwrap(),
//         eval_s1: Fr::from_str(proof_values[13]).unwrap(),
//         eval_s2: Fr::from_str(proof_values[14]).unwrap(),
//         eval_s3: Fr::from_str(proof_values[15]).unwrap(),
//         eval_a: Fr::from_str(proof_values[16]).unwrap(),
//         eval_b: Fr::from_str(proof_values[17]).unwrap(),
//         eval_c: Fr::from_str(proof_values[18]).unwrap(),
//         eval_z: Fr::from_str(proof_values[19]).unwrap(),
//         eval_zw: Fr::from_str(proof_values[20]).unwrap(),
//         eval_t1w: Fr::from_str(proof_values[21]).unwrap(),
//         eval_t2w: Fr::from_str(proof_values[22]).unwrap(),
//         eval_inv: Fr::from_str(proof_values[23]).unwrap(),
//     };

//     ProofWithPubSignal {
//         proof,
//         pub_signal
//     }
// }

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

    let pr = vec![   "1481927715054811733804695304084001679108833716381348939730805268145753672319",   "19669144057396287036614970272557992315751929115161637121425116755403567873546",   "682323284285379543874820022851345346716905264262521335320579112562769002731",   "5217046082481373877595103417334854412976806729710145608068750987850547916448",   "11521515194924070836496020366293362780278763599237451670444937035209680455608",   "16730301635986498141605740614067891009670237901703266245689883569759929817706",   "7648216166271091756697000850759109818942352153393449549967097850294823322486",   "13841059918140042479305358189720506803328611470904137853333589893028890921956",   "10682973389427934500889390913980545461720540728378117423453967866054801517546",   "19640862922252046012593809239563773424382616310643479928760400654556187984808",   "20887469144570360598226846219688412569127314117060464745189593667525340515656",   "17016442743265291319847312885025674149359385754888666855828695845548134601930",   "9589178903221618453208009241401184562093337063441620358881756562676120576984",   "13587607855302777394786571902811537225748207835844766425168460163223723298480",   "196342703472148724972325952133748424889705103389890345777635364023975370216",   "17614899337516641177585232833949194582105836997053025970644047796682698082429",   "19614815976847516185424338640248227600024228957312527212029765128340301045570",   "19288179487455265641230293305090848088167777073195579481424735403001454843339",   "21322627345806747285424422540651003500043705316685983517122519070872560726065",   "5678361803052355042251071216263713790429312783198484492885487189884430612397",   "9002531254955551070536912940387987650245696807782066392861703106041441260752",   "17776553760579063399907357086380850714130127374962466333241947482218961553245",   "3025664892310257295690669366416646012226101098007398549232319754774186205803",   "2103479791900830811261997581494396289927820373808412796596131379364316767264",   "9746738055974100534724688319587624714000386943764852782487326466491706467598",   "3117440667388512249305167413828803431193175159348741120837367035359253515212",   "15977681115418510430689616723041331137718448474191693270665710012377948663376",   "8148483208534253915927418266616456459152123251080630562782462708192922425729",   "5148318317103434325405029846136965801071929637258934964927797937732176388469",   "9350083133715632760163946740136758384048496610034417316968652465998615928235",   "20470364254908040055404858903350518240383939034306565348098332307740905863542",   "7538059542152278064360430275006244865024464052241262187047297399810715308295",   "7036240067875131759268503442624403515627271384033836780470587737696909190933",   "15834657814168463130145202123584569486416145351650914790360391211128804599867",   "790573260182333997045997353662764971783884673183303056517854663274184491762",   "1526611985826438991010848350624117895374304477623813636492366499941649169423",   "2209111850691644114898474232757656611086726698453992180215187737049963638713",   "7320378240983578507320264228195167543809287353218722858998931336614363841795",   "9314291787638126749568703763833741152670265991986629997655170540522333691468",   "19343833585712990921041961276646163448505065738578449210211290373092736702345",   "15801128222936579941344949598564623781236816860458762460020332728528749384179",   "9771480279475781628141565858177759272997414988110253046606613045403702662061",   "4605278045437359149151208117059078143501125383163755782102483779944679717239",   "20137048084395169744678501755645029481304459790001466854502391232119046446006" ];   

    let state_poly_0_x = <G1Point as AffineCurve>::BaseField::from_str(pr[0]).unwrap();
    let state_poly_0_y = <G1Point as AffineCurve>::BaseField::from_str(pr[1]).unwrap();
    let state_poly_0_affine = G1Projective::new(
        state_poly_0_x,
        state_poly_0_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let state_poly_1_x = <G1Point as AffineCurve>::BaseField::from_str(pr[2]).unwrap();
    let state_poly_1_y = <G1Point as AffineCurve>::BaseField::from_str(pr[3]).unwrap();
    let state_poly_1_affine = G1Projective::new(
        state_poly_1_x,
        state_poly_1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let state_poly_2_x = <G1Point as AffineCurve>::BaseField::from_str(pr[4]).unwrap();
    let state_poly_2_y = <G1Point as AffineCurve>::BaseField::from_str(pr[5]).unwrap();
    let state_poly_2_affine = G1Projective::new(
        state_poly_2_x,
        state_poly_2_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let state_poly_3_x = <G1Point as AffineCurve>::BaseField::from_str(pr[6]).unwrap();
    let state_poly_3_y = <G1Point as AffineCurve>::BaseField::from_str(pr[7]).unwrap();
    let state_poly_3_affine = G1Projective::new(
        state_poly_3_x,
        state_poly_3_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let copy_permutation_grand_product_x = <G1Point as AffineCurve>::BaseField::from_str(pr[8]).unwrap();
    let copy_permutation_grand_product_y = <G1Point as AffineCurve>::BaseField::from_str(pr[9]).unwrap();
    let copy_permutation_grand_product_affine = G1Projective::new(
        copy_permutation_grand_product_x,
        copy_permutation_grand_product_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let lookup_s_poly_x = <G1Point as AffineCurve>::BaseField::from_str(pr[10]).unwrap();
    let lookup_s_poly_y = <G1Point as AffineCurve>::BaseField::from_str(pr[11]).unwrap();
    let lookup_s_poly_affine = G1Projective::new(
        lookup_s_poly_x,
        lookup_s_poly_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let lookup_grand_product_x = <G1Point as AffineCurve>::BaseField::from_str(pr[12]).unwrap();
    let lookup_grand_product_y = <G1Point as AffineCurve>::BaseField::from_str(pr[13]).unwrap();
    let lookup_grand_product_affine = G1Projective::new(
        lookup_grand_product_x,
        lookup_grand_product_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let quotient_poly_parts_0_x = <G1Point as AffineCurve>::BaseField::from_str(pr[14]).unwrap();
    let quotient_poly_parts_0_y = <G1Point as AffineCurve>::BaseField::from_str(pr[15]).unwrap();
    let quotient_poly_parts_0_affine = G1Projective::new(
        quotient_poly_parts_0_x,
        quotient_poly_parts_0_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let quotient_poly_parts_1_x = <G1Point as AffineCurve>::BaseField::from_str(pr[16]).unwrap();
    let quotient_poly_parts_1_y = <G1Point as AffineCurve>::BaseField::from_str(pr[17]).unwrap();
    let quotient_poly_parts_1_affine = G1Projective::new(
        quotient_poly_parts_1_x,
        quotient_poly_parts_1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let quotient_poly_parts_2_x = <G1Point as AffineCurve>::BaseField::from_str(pr[18]).unwrap();
    let quotient_poly_parts_2_y = <G1Point as AffineCurve>::BaseField::from_str(pr[19]).unwrap();
    let quotient_poly_parts_2_affine = G1Projective::new(
        quotient_poly_parts_2_x,
        quotient_poly_parts_2_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let quotient_poly_parts_3_x = <G1Point as AffineCurve>::BaseField::from_str(pr[20]).unwrap();
    let quotient_poly_parts_3_y = <G1Point as AffineCurve>::BaseField::from_str(pr[21]).unwrap();
    let quotient_poly_parts_3_affine = G1Projective::new(
        quotient_poly_parts_3_x,
        quotient_poly_parts_3_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let state_poly_0_opening_at_z = Fr::from_str(pr[22]).unwrap();
    let state_poly_1_opening_at_z = Fr::from_str(pr[23]).unwrap();
    let state_poly_2_opening_at_z = Fr::from_str(pr[24]).unwrap();
    let state_poly_3_opening_at_z = Fr::from_str(pr[25]).unwrap();

    let state_poly_3_opening_at_z_omega = Fr::from_str(pr[26]).unwrap();
    let gate_selectors_0_opening_at_z = Fr::from_str(pr[27]).unwrap();

    let copy_permutation_polys_0_opening_at_z = Fr::from_str(pr[28]).unwrap();
    let copy_permutation_polys_1_opening_at_z = Fr::from_str(pr[29]).unwrap();
    let copy_permutation_polys_2_opening_at_z = Fr::from_str(pr[30]).unwrap();

    let copy_permutation_grand_product_opening_at_z_omega = Fr::from_str(pr[31]).unwrap();
    let lookup_s_poly_opening_at_z_omega = Fr::from_str(pr[32]).unwrap();
    let lookup_grand_product_opening_at_z_omega = Fr::from_str(pr[33]).unwrap();
    let lookup_t_poly_opening_at_z = Fr::from_str(pr[34]).unwrap();
    let lookup_t_poly_opening_at_z_omega = Fr::from_str(pr[35]).unwrap();
    let lookup_selector_poly_opening_at_z = Fr::from_str(pr[36]).unwrap();
    let lookup_table_type_poly_opening_at_z = Fr::from_str(pr[37]).unwrap();
    let quotient_poly_opening_at_z = Fr::from_str(pr[38]).unwrap();
    let linearisation_poly_opening_at_z = Fr::from_str(pr[39]).unwrap();

    let opening_proof_at_z_x = <G1Point as AffineCurve>::BaseField::from_str(pr[40]).unwrap();
    let opening_proof_at_z_y = <G1Point as AffineCurve>::BaseField::from_str(pr[41]).unwrap();
    let opening_proof_at_z_affine = G1Projective::new(
        opening_proof_at_z_x,
        opening_proof_at_z_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    let opening_proof_at_z_omega_x = <G1Point as AffineCurve>::BaseField::from_str(pr[42]).unwrap();
    let opening_proof_at_z_omega_y = <G1Point as AffineCurve>::BaseField::from_str(pr[43]).unwrap();
    let opening_proof_at_z_omega_affine = G1Projective::new(
        opening_proof_at_z_omega_x,
        opening_proof_at_z_omega_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    );

    // let recursive_part_p1_x = <G1Point as AffineCurve>::BaseField::from_str(pr[44]).unwrap();
    // let recursive_part_p1_y = <G1Point as AffineCurve>::BaseField::from_str(pr[45]).unwrap();
    // let recursive_part_p1_affine = G1Projective::new(
    //     recursive_part_p1_x,
    //     recursive_part_p1_y,
    //     <G1Projective as ProjectiveCurve>::BaseField::one(),
    // );

    // let recursive_part_p2_x = <G1Point as AffineCurve>::BaseField::from_str(pr[46]).unwrap();
    // let recursive_part_p2_y = <G1Point as AffineCurve>::BaseField::from_str(pr[47]).unwrap();
    // let recursive_part_p2_affine = G1Projective::new(
    //     recursive_part_p2_x,
    //     recursive_part_p2_y,
    //     <G1Projective as ProjectiveCurve>::BaseField::one(),
    // );

    Proof {
        state_poly_0: state_poly_0_affine.into(),
        state_poly_1: state_poly_1_affine.into(),
        state_poly_2: state_poly_2_affine.into(),
        state_poly_3: state_poly_3_affine.into(),
        copy_permutation_grand_product: copy_permutation_grand_product_affine.into(),
        lookup_s_poly: lookup_s_poly_affine.into(),
        lookup_grand_product: lookup_grand_product_affine.into(),
        quotient_poly_parts_0: quotient_poly_parts_0_affine.into(),
        quotient_poly_parts_1: quotient_poly_parts_1_affine.into(),
        quotient_poly_parts_2: quotient_poly_parts_2_affine.into(),
        quotient_poly_parts_3: quotient_poly_parts_3_affine.into(),
        state_poly_0_opening_at_z,
        state_poly_1_opening_at_z,
        state_poly_2_opening_at_z,
        state_poly_3_opening_at_z,
        state_poly_3_opening_at_z_omega,
        gate_selectors_0_opening_at_z,
        copy_permutation_polys_0_opening_at_z,
        copy_permutation_polys_1_opening_at_z,
        copy_permutation_polys_2_opening_at_z,
        copy_permutation_grand_product_opening_at_z_omega,
        lookup_s_poly_opening_at_z_omega,
        lookup_grand_product_opening_at_z_omega,
        lookup_t_poly_opening_at_z,
        lookup_t_poly_opening_at_z_omega,
        lookup_selector_poly_opening_at_z,
        lookup_table_type_poly_opening_at_z,
        quotient_poly_opening_at_z,
        linearisation_poly_opening_at_z,
        opening_proof_at_z: opening_proof_at_z_affine.into(),
        opening_proof_at_z_omega: opening_proof_at_z_omega_affine.into(),
        // recursive_part_p1: recursive_part_p1_affine.into(),
        // recursive_part_p2: recursive_part_p2_affine.into(),

    }   
}

//Partial verifier state
#[derive(Debug, Clone)]
pub struct PartialVerifierState {
   
    pub alpha: Fp256<FrParameters>,
    pub beta: Fp256<FrParameters>,
    pub gamma: Fp256<FrParameters>,
    pub power_of_alpha_2: Fp256<FrParameters>,
    pub power_of_alpha_3: Fp256<FrParameters>,
    pub power_of_alpha_4: Fp256<FrParameters>,
    pub power_of_alpha_5: Fp256<FrParameters>,
    pub power_of_alpha_6: Fp256<FrParameters>,
    pub power_of_alpha_7: Fp256<FrParameters>,
    pub power_of_alpha_8: Fp256<FrParameters>,
    pub eta: Fp256<FrParameters>,
    pub beta_lookup: Fp256<FrParameters>,
    pub gamma_lookup: Fp256<FrParameters>,
    pub beta_plus_one: Fp256<FrParameters>,
    pub beta_gamma_plus_gamma: Fp256<FrParameters>,
    pub v: Fp256<FrParameters>,
    pub u: Fp256<FrParameters>,
    pub z: Fp256<FrParameters>,
    pub z_minus_last_omega: Fp256<FrParameters>,
    pub l_0_at_z: Fp256<FrParameters>,
    pub l_n_minus_one_at_z: Fp256<FrParameters>,
    pub z_in_domain_size: Fp256<FrParameters>,
}

impl PartialVerifierState{
    pub fn new() -> Self{
        PartialVerifierState{
            alpha: Fp256::<FrParameters>::zero(),
            beta: Fp256::<FrParameters>::zero(),
            gamma: Fp256::<FrParameters>::zero(),
            power_of_alpha_2: Fp256::<FrParameters>::zero(),
            power_of_alpha_3: Fp256::<FrParameters>::zero(),
            power_of_alpha_4: Fp256::<FrParameters>::zero(),
            power_of_alpha_5: Fp256::<FrParameters>::zero(),
            power_of_alpha_6: Fp256::<FrParameters>::zero(),
            power_of_alpha_7: Fp256::<FrParameters>::zero(),
            power_of_alpha_8: Fp256::<FrParameters>::zero(),
            eta: Fp256::<FrParameters>::zero(),
            beta_lookup: Fp256::<FrParameters>::zero(),
            gamma_lookup: Fp256::<FrParameters>::zero(),
            beta_plus_one: Fp256::<FrParameters>::zero(),
            beta_gamma_plus_gamma: Fp256::<FrParameters>::zero(),
            v: Fp256::<FrParameters>::zero(),
            u: Fp256::<FrParameters>::zero(),
            z: Fp256::<FrParameters>::zero(),
            z_minus_last_omega: Fp256::<FrParameters>::zero(),
            l_0_at_z: Fp256::<FrParameters>::zero(),
            l_n_minus_one_at_z: Fp256::<FrParameters>::zero(),
            z_in_domain_size: Fp256::<FrParameters>::zero(),
        }
    }
}

pub fn get_proog_bigint() -> ProofBigInt {
    ProofBigInt {
        c1: (
            BigInt::parse_bytes(
                b"12195165594784431822497303968938621279445690754376121387655513728730220550454",
                10,
            )
            .unwrap(),
            BigInt::parse_bytes(
                b"19482351300768228183728567743975524187837254971200066453308487514712354412818",
                10,
            )
            .unwrap(),
        ),
        c2: (
            BigInt::parse_bytes(
                b"270049702185508019342640204324826241417613526941291105097079886683911146886",
                10,
            )
            .unwrap(),
            BigInt::parse_bytes(
                b"8044577183782099118358991257374623532841698893838076750142877485824795072127",
                10,
            )
            .unwrap(),
        ),
        w1: (
            BigInt::parse_bytes(
                b"18899554350581376849619715242908819289791150067233598694602356239698407061017",
                10,
            )
            .unwrap(),
            BigInt::parse_bytes(
                b"868483199604273061042760252576862685842931472081080113229115026384087738503",
                10,
            )
            .unwrap(),
        ),
        w2: (
            BigInt::parse_bytes(
                b"15400234196629481957150851143665757067987965100904384175896686561307554593394",
                10,
            )
            .unwrap(),
            BigInt::parse_bytes(
                b"1972554287366869807517068788787992038621302618305780153544292964897315682091",
                10,
            )
            .unwrap(),
        ),
        eval_ql: BigInt::parse_bytes(
            b"13012702442141574024514112866712813523553321876510290446303561347565844930654",
            10,
        )
        .unwrap(),
        eval_qr: BigInt::parse_bytes(
            b"6363613431504422665441435540021253583148414748729550612486380209002057984394",
            10,
        )
        .unwrap(),
        eval_qm: BigInt::parse_bytes(
            b"16057866832337652851142304414708366836077577338023656646690877057031251541947",
            10,
        )
        .unwrap(),
        eval_qo: BigInt::parse_bytes(
            b"12177497208173170035464583425607209406245985123797536695060336171641250404407",
            10,
        )
        .unwrap(),
        eval_qc: BigInt::parse_bytes(
            b"1606928575748882874942488864331180511279674792603033713048693169239812670017",
            10,
        )
        .unwrap(),
        eval_s1: BigInt::parse_bytes(
            b"12502690277925689095499239281542937835831064619179570213662273016815222024218",
            10,
        )
        .unwrap(),
        eval_s2: BigInt::parse_bytes(
            b"21714950310348017755786780913378098925832975432250486683702036755613488957178",
            10,
        )
        .unwrap(),
        eval_s3: BigInt::parse_bytes(
            b"7373645520955771058170141217317033724805640797155623483741097103589211150628",
            10,
        )
        .unwrap(),
        eval_a: BigInt::parse_bytes(
            b"10624974841759884514517518996672059640247361745924203600968035963539096078745",
            10,
        )
        .unwrap(),
        eval_b: BigInt::parse_bytes(
            b"12590031312322329503809710776715067780944838760473156014126576247831324341903",
            10,
        )
        .unwrap(),
        eval_c: BigInt::parse_bytes(
            b"17676078410435205056317710999346173532618821076911845052950090109177062725036",
            10,
        )
        .unwrap(),
        eval_z: BigInt::parse_bytes(
            b"13810130824095164415807955516712763121131180676617650812233616232528698737619",
            10,
        )
        .unwrap(),
        eval_zw: BigInt::parse_bytes(
            b"9567903658565551430748252507556148460902008866092926659415720362326593620836",
            10,
        )
        .unwrap(),
        eval_t1w: BigInt::parse_bytes(
            b"17398514793767712415669438995039049448391479578008786242788501594157890722459",
            10,
        )
        .unwrap(),
        eval_t2w: BigInt::parse_bytes(
            b"11804645688707233673914574834599506530652461017683048951953032091830492459803",
            10,
        )
        .unwrap(),
        eval_inv: BigInt::parse_bytes(
            b"6378827379501409574366452872421073840754012879130221505294134572417254316105",
            10,
        )
        .unwrap(),
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


// function _loadVerificationKey() internal pure virtual {
//     assembly {

//     }

pub struct VerificationKey {
    pub gate_setup: Vec<G1Point>,
    pub gate_selectors: Vec<G1Point>,
    pub permutation: Vec<G1Point>,
    pub lookup_table: Vec<G1Point>,
    pub lookup_selector: G1Point,
    pub lookup_table_type: G1Point,
    pub recursive_flag: bool,
}
pub fn get_verification_key() -> VerificationKey{

    VerificationKey{
        gate_setup: 
        vec![
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("281bdd74b0e5ce559019f68453b8ccdbc07ef97554fb9f47fc87a86f6720d9c4".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("07ed1e84e05b9e4e69ce8eed39601a0605adf9abe15f9c9ed13f642bf8c31dfb".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("04659caf7b05471ba5ba85b1ab62267aa6c456836e625f169f7119d55b9462d2".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("0ea63403692148d2ad22189a1e5420076312f4d46e62036a043a6b0b84d5b410".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("0e6696d09d65fce1e42805be03fca1f14aea247281f688981f925e77d4ce2291".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("0228f6cf8fe20c1e07e5b78bf8c41d50e55975a126d22a198d1e56acd4bbb3dd".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("14685dafe340b1dec5eafcd5e7faddaf24f3781ddc53309cc25d0b42c00541dd".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("0e651cff9447cb360198899b80fa23e89ec13bc94ff161729aa841d2b55ea5be".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("16e9ef76cb68f2750eb0ee72382dd9911a982308d0ab10ef94dada13c382ae73".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("22e404bc91350f3bc7daad1d1025113742436983c85eac5ab7b42221a181b81e".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("0d9b29613037a5025655c82b143d2b7449c98f3aea358307c8529249cc54f3b9".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("15b3c4c946ad1babfc4c03ff7c2423fd354af3a9305c499b7fb3aaebe2fee746".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("2b0287845b812b668358980e3fd51479ecd86402156fb329551f0ced5b78ff32".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("08976d4177ca333c0cffd19dda4b8ff6b65f049453235396a42151352d97a509".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("283344a1ab3e55ecfd904d0b8e9f4faea338df5a4ead2fa9a42f0e103da40abc".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("223b37b83b9687512d322993edd70e508dd80adb10bcf7321a3cc8a44c269521".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
        ]
        ,
        gate_selectors: 

        vec![
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("1f67f0ba5f7e837bc680acb4e612ebd938ad35211aa6e05b96cad19e66b82d2d".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("2820641a84d2e8298ac2ac42bd4b912c0c37f768ecc83d3a29e7c720763d15a1".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("0353257957562270292a17860ca8e8827703f828f440ee004848b1e23fdf9de2".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("305f4137fee253dff8b2bfe579038e8f25d5bd217865072af5d89fc8800ada24".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),

        ],
        permutation: 
        vec![
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("13a600154b369ff3237706d00948e465ee1c32c7a6d3e18bccd9c4a15910f2e5".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("138aa24fbf4cdddc75114811b3d59040394c218ecef3eb46ef9bd646f7e53776".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("277fff1f80c409357e2d251d79f6e3fd2164b755ce69cfd72de5c690289df662".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("25235588e28c70eea3e35531c80deac25cd9b53ea3f98993f120108bc7abf670".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("0990e07a9b001048b947d0e5bd6157214c7359b771f01bf52bd771ba563a900e".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("05e5fb090dd40914c8606d875e301167ae3047d684a02b44d9d36f1eaf43d0b4".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("1d4656690b33299db5631401a282afab3e16c78ee2c9ad9efea628171dcbc6bc".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("0ebda2ebe582f601f813ec1e3970d13ef1500c742a85cce9b7f190f333de03b0".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),

        ],
        lookup_table: 
        vec![
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("2c513ed74d9d57a5ec901e074032741036353a2c4513422e96e7b53b302d765b".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("04dd964427e430f16004076d708c0cb21e225056cc1d57418cfbd3d472981468".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("1ea83e5e65c6f8068f4677e2911678cf329b28259642a32db1f14b8347828aac".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("1d22bc884a2da4962a893ba8de13f57aaeb785ed52c5e686994839cab8f7475d".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("0b2e7212d0d9cff26d0bdf3d79b2cac029a25dfeb1cafdf49e2349d7db348d89".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("1301f9b252419ea240eb67fda720ca0b16d92364027285f95e9b1349490fa283".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),
            G1Projective::new(
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("02f7b99fdfa5b418548c2d777785820e02383cfc87e7085e280a375a358153bf".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("09d004fe08dc4d19c382df36fad22ef676185663543703e6a4b40203e50fd8a6".as_bytes(), 16).unwrap().to_string()).unwrap(),
                <G1Projective as ProjectiveCurve>::BaseField::one(),
            ).into_affine(),

        ],

        lookup_selector: G1Projective::new(
            <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("2f4d347c7fb61daaadfff881e24f4b5dcfdc0d70a95bcb148168b90ef93e0007".as_bytes(), 16).unwrap().to_string()).unwrap(),
            <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("2322632465ba8e28cd0a4befd813ea85a972f4f6fa8e8603cf5d062dbcb14065".as_bytes(), 16).unwrap().to_string()).unwrap(),
            <G1Projective as ProjectiveCurve>::BaseField::one(),
        ).into_affine(),
        lookup_table_type: G1Projective::new(
            <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("1e3c9fc98c118e4bc34f1f93d214a5d86898e980c40d8e2c180c6ada377a7467".as_bytes(), 16).unwrap().to_string()).unwrap(),
            <G1Point as AffineCurve>::BaseField::from_str(&BigInt::parse_bytes("2260a13535c35a15c173f5e5797d4b675b55d164a9995bfb7624971324bd84a8".as_bytes(), 16).unwrap().to_string()).unwrap(),
            <G1Projective as ProjectiveCurve>::BaseField::one(),
        ).into_affine(),
        recursive_flag: false,
    }
}