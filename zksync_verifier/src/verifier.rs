use crate::utils::get_proog_bigint;
pub use crate::utils::{
    get_domain_size, get_omegas, get_proof, get_pubSignals, Omegas, Proof, ProofWithPubSignal,
};
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
use num_bigint::*;
use std::fmt::{format, Debug, DebugMap, Display};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};
use std::str::FromStr;
use std::vec;

use num_bigint::BigUint;
use tiny_keccak::{Hasher, Keccak};

pub type G1Point = <Bn254 as PairingEngine>::G1Affine;
pub type G2Point = <Bn254 as PairingEngine>::G2Affine;

pub fn verify() {
    // do something here above and beyond !!

    // defining few verification keys here
    let vk_gate_setup_0_x = <G1Point as AffineCurve>::BaseField::from_str(
        "18141747246005626051799779950519336123562580942979903067313939969882919590340",
    )
    .unwrap();
    let vk_gate_setup_0_y = <G1Point as AffineCurve>::BaseField::from_str(
        "3585143329166348536377758970100845939161265326922449384523034507058404859387",
    )
    .unwrap();
    let vk_gate_setup_0_affine = G1Projective::new(
        vk_gate_setup_0_x,
        vk_gate_setup_0_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_gate_setup_1_x = <G1Point as AffineCurve>::BaseField::from_str(
        "1988784351252031472169741801544970435196545636113389178981091085566461895378",
    )
    .unwrap();
    let vk_gate_setup_1_y = <G1Point as AffineCurve>::BaseField::from_str(
        "6626035475680297406478400665575376989678110111230786600317346925351789769744",
    )
    .unwrap();
    let vk_gate_setup_1_affine = G1Projective::new(
        vk_gate_setup_1_x,
        vk_gate_setup_1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_gate_setup_2_x = <G1Point as AffineCurve>::BaseField::from_str(
        "6513639166970035139110486703908124080089475463144632993644733293246110638737",
    )
    .unwrap();
    let vk_gate_setup_2_y = <G1Point as AffineCurve>::BaseField::from_str(
        "977003005220586916659677691095356382823546077624913424654056785190852473821",
    )
    .unwrap();
    let vk_gate_setup_2_affine = G1Projective::new(
        vk_gate_setup_2_x,
        vk_gate_setup_2_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_gate_setup_3_x = <G1Point as AffineCurve>::BaseField::from_str(
        "9230655670735702119620314706239903522998966275916883375733056995058491146717",
    )
    .unwrap();
    let vk_gate_setup_3_y = <G1Point as AffineCurve>::BaseField::from_str(
        "6511031573008209933978170549284048297810619244182920356477578929223310943678",
    )
    .unwrap();
    let vk_gate_setup_3_affine = G1Projective::new(
        vk_gate_setup_3_x,
        vk_gate_setup_3_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_gate_setup_4_x = <G1Point as AffineCurve>::BaseField::from_str(
        "10364210754997381702522032157284956719005600005128484559781408547053066432115",
    )
    .unwrap();
    let vk_gate_setup_4_y = <G1Point as AffineCurve>::BaseField::from_str(
        "15781510673347999125058819560304519136658253885351485025763958725578907039774",
    )
    .unwrap();
    let vk_gate_setup_4_affine = G1Projective::new(
        vk_gate_setup_4_x,
        vk_gate_setup_4_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_gate_setup_5_x = <G1Point as AffineCurve>::BaseField::from_str(
        "6154213918416038593868317990163182893460080436875238745368931183847837856697",
    )
    .unwrap();
    let vk_gate_setup_5_y = <G1Point as AffineCurve>::BaseField::from_str(
        "9816193613520248954417193401298538403248469703169878496524632397336220198726",
    )
    .unwrap();
    let vk_gate_setup_5_affine = G1Projective::new(
        vk_gate_setup_5_x,
        vk_gate_setup_5_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_gate_setup_6_x = <G1Point as AffineCurve>::BaseField::from_str(
        "19453921487316344064341051371567074674850858847513131144999214779949439844146",
    )
    .unwrap();
    let vk_gate_setup_6_y = <G1Point as AffineCurve>::BaseField::from_str(
        "3886050750811343696486217418179023039649583171214698993490137242899280536841",
    )
    .unwrap();
    let vk_gate_setup_6_affine = G1Projective::new(
        vk_gate_setup_6_x,
        vk_gate_setup_6_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_gate_setup_7_x = <G1Point as AffineCurve>::BaseField::from_str(
        "18183096820971393578641159504664838007531678766243529655378299444935455410876",
    )
    .unwrap();
    let vk_gate_setup_7_y = <G1Point as AffineCurve>::BaseField::from_str(
        "15483265391607591192398303295188109928858243125143393303657667139744863524129",
    )
    .unwrap();
    let vk_gate_setup_7_affine: GroupAffine<Parameters> = G1Projective::new(
        vk_gate_setup_7_x,
        vk_gate_setup_7_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_gate_selectors_1_x = <G1Point as AffineCurve>::BaseField::from_str(
        "1503845488092386103648065432248698383432228205851738279222364151597624172002",
    ).unwrap();

    let vk_gate_selectors_1_y = <G1Point as AffineCurve>::BaseField::from_str(
        "21879317326302769106212942083598833971208881826953277740248006269619105618468",
    ).unwrap();

    let vk_gate_selectors_1_affine = G1Projective::new(
        vk_gate_selectors_1_x,
        vk_gate_selectors_1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    ).into_affine();

    prepare_queries(
        vk_gate_setup_0_affine,
        vk_gate_setup_1_affine,
        vk_gate_setup_2_affine,
        vk_gate_setup_3_affine,
        vk_gate_setup_4_affine,
        vk_gate_setup_5_affine,
        vk_gate_setup_6_affine,
        vk_gate_setup_7_affine,
        vk_gate_selectors_1_affine,
    );
}


// params
// QUERIES_AT_Z_1_X_SLOT,
// stateOpening0AtZ,
// stateOpening1AtZ,
// stateOpening2AtZ,
// stateOpening3AtZ

fn add_assign_permutation_linearisation_contribution_with_v(
    queries_at_z_1: GroupAffine<Parameters>,
    state_opening_0_z: Fr,
    state_opening_1_z: Fr,
    state_opening_2_z: Fr,
    state_opening_3_z: Fr,
) {

}

fn add_assign_rescue_customgate_linearisation_contribution_with_v(
    queries_at_z_1: GroupAffine<Parameters>,
    state_opening_0_z: Fr,
    state_opening_1_z: Fr,
    state_opening_2_z: Fr,
    state_opening_3_z: Fr,
    vk_gate_selectors_1_affine: GroupAffine<Parameters>
) -> GroupAffine<Parameters> {
    // challenges wire later
    let state_alpha_slot = Fr::from_str(
        "2283206971795773822103810506163842486205626492327489207776386690517719211772",
    ).unwrap();

    let state_power_of_alpha_2 = Fr::from_str(
        "826184778216175497174816455317911134904368857235156468525135792912866513770",
    ).unwrap();

    let state_power_of_alpha_3 = Fr::from_str(
        "11473813489823724163756584140835327793445011271247834568957645433130065406474",
    ).unwrap();

    let state_v_slot = Fr::from_str(
        "13330004428861975879381254388579709216101551406414154978351365682885384794150",
    ).unwrap();

    let mut accumulator: Fr;
    let mut intermediate_value: Fr;

    accumulator = state_opening_0_z.square();
    accumulator = accumulator.sub(state_opening_1_z);
    accumulator = accumulator.mul(state_alpha_slot);

    intermediate_value = state_opening_1_z.square();
    intermediate_value = intermediate_value.sub(state_opening_2_z);
    intermediate_value = intermediate_value.mul(state_power_of_alpha_2);
    accumulator = accumulator.add(intermediate_value);

    intermediate_value = state_opening_2_z.mul(state_opening_0_z);
    intermediate_value = intermediate_value.sub(state_opening_3_z);
    intermediate_value = intermediate_value.mul(state_power_of_alpha_3);
    accumulator = accumulator.add(intermediate_value);

    accumulator = accumulator.mul(state_v_slot);

    vk_gate_selectors_1_affine.mul(accumulator).into_affine().add(queries_at_z_1)

}


fn main_gate_linearisation_contribution_with_v(
    vk_gate_setup_0_affine: GroupAffine<Parameters>,
    vk_gate_setup_1_affine: GroupAffine<Parameters>,
    vk_gate_setup_2_affine: GroupAffine<Parameters>,
    vk_gate_setup_3_affine: GroupAffine<Parameters>,
    vk_gate_setup_4_affine: GroupAffine<Parameters>,
    vk_gate_setup_5_affine: GroupAffine<Parameters>,
    vk_gate_setup_6_affine: GroupAffine<Parameters>,
    vk_gate_setup_7_affine: GroupAffine<Parameters>,
    state_opening_0_z: Fr,
    state_opening_1_z: Fr,
    state_opening_2_z: Fr,
    state_opening_3_z: Fr,
) -> GroupAffine<Parameters> {
    let mut queries_at_z_1 = vk_gate_setup_0_affine.mul(state_opening_0_z).into_affine();
    queries_at_z_1 = queries_at_z_1.add(vk_gate_setup_1_affine.mul(state_opening_1_z).into_affine());
    queries_at_z_1 = queries_at_z_1.add(vk_gate_setup_2_affine.mul(state_opening_2_z).into_affine());
    queries_at_z_1 = queries_at_z_1.add(vk_gate_setup_3_affine.mul(state_opening_3_z).into_affine());
    queries_at_z_1 = queries_at_z_1.add(vk_gate_setup_4_affine.mul(state_opening_0_z.mul(state_opening_1_z)).into_affine());
    queries_at_z_1 = queries_at_z_1.add(vk_gate_setup_5_affine.mul(state_opening_0_z.mul(state_opening_2_z)).into_affine());
    queries_at_z_1 = queries_at_z_1.add(vk_gate_setup_6_affine);

    // proof value
    let proof_state_polys_3_opening_at_z_omega_slot = Fr::from_str(
        "15977681115418510430689616723041331137718448474191693270665710012377948663376",
    ).unwrap();

    // proof value
    let proof_gate_selectors_0_opening_at_z = Fr::from_str(
        "8148483208534253915927418266616456459152123251080630562782462708192922425729",
    ).unwrap();

    // challenge
    let state_v_slot = Fr::from_str(
        "13330004428861975879381254388579709216101551406414154978351365682885384794150",
    ).unwrap();

    queries_at_z_1 = queries_at_z_1.add(vk_gate_setup_7_affine.mul(proof_state_polys_3_opening_at_z_omega_slot).into_affine());

    println!("Queries at Z 1 x Slot: {:?}", queries_at_z_1.x.to_string());
    println!("Queries at Z 1 y Slot: {:?}", queries_at_z_1.y.to_string());

    let coeff = proof_gate_selectors_0_opening_at_z.mul(state_v_slot);
    queries_at_z_1 = queries_at_z_1.mul(coeff).into_affine();

    queries_at_z_1

}

fn prepare_queries(
    vk_gate_setup_0_affine: GroupAffine<Parameters>,
    vk_gate_setup_1_affine: GroupAffine<Parameters>,
    vk_gate_setup_2_affine: GroupAffine<Parameters>,
    vk_gate_setup_3_affine: GroupAffine<Parameters>,
    vk_gate_setup_4_affine: GroupAffine<Parameters>,
    vk_gate_setup_5_affine: GroupAffine<Parameters>,
    vk_gate_setup_6_affine: GroupAffine<Parameters>,
    vk_gate_setup_7_affine: GroupAffine<Parameters>,
    vk_gate_selectors_1_affine: GroupAffine<Parameters>,
) {
    let z_domain_size = Fr::from_str(
        "8306037114154435423292901166608307526952350843292506299851821833617177949622",
    )
    .unwrap();
    let mut current_z = z_domain_size;
    // let proof_quotient_poly_parts_0_x_slot = Fr::from_str("196342703472148724972325952133748424889705103389890345777635364023975370216").unwrap();
    // let proof_quotient_poly_parts_0_y_slot = Fr::from_str("17614899337516641177585232833949194582105836997053025970644047796682698082429").unwrap();

    let proof_quotient_poly_parts_0_x = <G1Point as AffineCurve>::BaseField::from_str(
        "196342703472148724972325952133748424889705103389890345777635364023975370216",
    )
    .unwrap();
    let proof_quotient_poly_parts_0_y = <G1Point as AffineCurve>::BaseField::from_str(
        "17614899337516641177585232833949194582105836997053025970644047796682698082429",
    )
    .unwrap();
    let proof_quotient_poly_parts_0_affine = G1Projective::new(
        proof_quotient_poly_parts_0_x,
        proof_quotient_poly_parts_0_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let proof_quotient_poly_parts_1_x = <G1Point as AffineCurve>::BaseField::from_str(
        "19614815976847516185424338640248227600024228957312527212029765128340301045570",
    )
    .unwrap();
    let proof_quotient_poly_parts_1_y = <G1Point as AffineCurve>::BaseField::from_str(
        "19288179487455265641230293305090848088167777073195579481424735403001454843339",
    )
    .unwrap();
    let proof_quotient_poly_parts_1_affine = G1Projective::new(
        proof_quotient_poly_parts_1_x,
        proof_quotient_poly_parts_1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let proof_quotient_poly_parts_2_x = <G1Point as AffineCurve>::BaseField::from_str(
        "21322627345806747285424422540651003500043705316685983517122519070872560726065",
    )
    .unwrap();
    let proof_quotient_poly_parts_2_y = <G1Point as AffineCurve>::BaseField::from_str(
        "5678361803052355042251071216263713790429312783198484492885487189884430612397",
    )
    .unwrap();
    let proof_quotient_poly_parts_2_affine = G1Projective::new(
        proof_quotient_poly_parts_2_x,
        proof_quotient_poly_parts_2_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let proof_quotient_poly_parts_3_x = <G1Point as AffineCurve>::BaseField::from_str(
        "9002531254955551070536912940387987650245696807782066392861703106041441260752",
    )
    .unwrap();
    let proof_quotient_poly_parts_3_y = <G1Point as AffineCurve>::BaseField::from_str(
        "17776553760579063399907357086380850714130127374962466333241947482218961553245",
    )
    .unwrap();
    let proof_quotient_poly_parts_3_affine = G1Projective::new(
        proof_quotient_poly_parts_3_x,
        proof_quotient_poly_parts_3_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let mut queries_at_z_0 = proof_quotient_poly_parts_1_affine
        .mul(z_domain_size)
        .into_affine()
        .add(proof_quotient_poly_parts_0_affine);

    current_z = current_z.mul(z_domain_size);

    queries_at_z_0 = proof_quotient_poly_parts_2_affine
        .mul(current_z)
        .into_affine()
        .add(queries_at_z_0);

    println!("Queries at Z 0 x Slot: {:?}", queries_at_z_0.x.to_string());
    println!("Queries at Z 0 y Slot: {:?}", queries_at_z_0.y.to_string());

    current_z = current_z.mul(z_domain_size);

    queries_at_z_0 = proof_quotient_poly_parts_3_affine
        .mul(current_z)
        .into_affine()
        .add(queries_at_z_0);

    println!("Queries at Z 0 x Slot: {:?}", queries_at_z_0.x.to_string());
    println!("Queries at Z 0 y Slot: {:?}", queries_at_z_0.y.to_string());

    let state_opening_0_z = Fr::from_str(
        "3025664892310257295690669366416646012226101098007398549232319754774186205803",
    )
    .unwrap();
    let state_opening_1_z = Fr::from_str(
        "2103479791900830811261997581494396289927820373808412796596131379364316767264",
    )
    .unwrap();
    let state_opening_2_z = Fr::from_str(
        "9746738055974100534724688319587624714000386943764852782487326466491706467598",
    )
    .unwrap();
    let state_opening_3_z = Fr::from_str(
        "3117440667388512249305167413828803431193175159348741120837367035359253515212",
    )
    .unwrap();

    let mut queries_at_z_1 = main_gate_linearisation_contribution_with_v(
        vk_gate_setup_0_affine,
        vk_gate_setup_1_affine,
        vk_gate_setup_2_affine,
        vk_gate_setup_3_affine,
        vk_gate_setup_4_affine,
        vk_gate_setup_5_affine,
        vk_gate_setup_6_affine,
        vk_gate_setup_7_affine,
        state_opening_0_z,
        state_opening_1_z,
        state_opening_2_z,
        state_opening_3_z,
    );

    println!("Queries at Z 1 x Slot: {:?}", queries_at_z_1.x.to_string());
    println!("Queries at Z 1 y Slot: {:?}", queries_at_z_1.y.to_string());

    queries_at_z_1 = add_assign_rescue_customgate_linearisation_contribution_with_v(
        queries_at_z_1,
        state_opening_0_z,
        state_opening_1_z,
        state_opening_2_z,
        state_opening_3_z,
        vk_gate_selectors_1_affine
    );

    println!(" Queries at Z 1 x Slot: {:?}", queries_at_z_1.x.to_string());
    println!(" Queries at Z 1 y Slot: {:?}", queries_at_z_1.y.to_string());
    // PROOF_QUOTIENT_POLY_PARTS_1_X_SLOT currentz QUERIES_AT_Z_0_X_SLOT


}

// PROOF_QUOTIENT_POLY_PARTS_1_X_SLOT_term
// QUERIES_AT_Z_0_X_SLOT_term
// QUERIES_AT_Z_0_X_SLOT_y_term
