use crate::utils::get_proog_bigint;
pub use crate::utils::{
    get_domain_size, get_omegas, get_proof, get_pubSignals, Omegas, Proof, ProofWithPubSignal,
};
use ark_bn254::{
    g1, g1::Parameters, Bn254, Fq, FqParameters, Fr, FrParameters, G1Projective, G2Projective,
};
use ark_bn254::{g2, Fq2, Fq2Parameters, G2Affine};
use ark_ec::group::Group;
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

    let vk_gate_selectors_0_x = <G1Point as AffineCurve>::BaseField::from_str(
        "14205344997483453838751247319875941252565270087237127926142565059361638985005",
    )
    .unwrap();

    let vk_gate_selectors_0_y = <G1Point as AffineCurve>::BaseField::from_str(
        "18149743938984840795673757375540800526102537869676573169262794906671381288353",
    )
    .unwrap();

    let vk_gate_selectors_0_affine = G1Projective::new(
        vk_gate_selectors_0_x,
        vk_gate_selectors_0_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_gate_selectors_1_x = <G1Point as AffineCurve>::BaseField::from_str(
        "1503845488092386103648065432248698383432228205851738279222364151597624172002",
    )
    .unwrap();

    let vk_gate_selectors_1_y = <G1Point as AffineCurve>::BaseField::from_str(
        "21879317326302769106212942083598833971208881826953277740248006269619105618468",
    )
    .unwrap();

    let vk_gate_selectors_1_affine = G1Projective::new(
        vk_gate_selectors_1_x,
        vk_gate_selectors_1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_permutation_0_x = <G1Point as AffineCurve>::BaseField::from_str(
        "8887241309915046403987404266456327687371133714343160532258729830564274172645",
    )
    .unwrap();

    let vk_permutation_0_y = <G1Point as AffineCurve>::BaseField::from_str(
        "8838889250911714005233937797167402728703848047545768220993868516057541850998",
    )
    .unwrap();

    let vk_permutation_0_affine = G1Projective::new(
        vk_permutation_0_x,
        vk_permutation_0_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_permutation_1_x = <G1Point as AffineCurve>::BaseField::from_str(
        "17866351466611640086959034867757326106027853848164149106032164116282644231778",
    )
    .unwrap();

    let vk_permutation_1_y = <G1Point as AffineCurve>::BaseField::from_str(
        "16798005383698675803387212328766642387080095868926572635337761193563305801328",
    )
    .unwrap();

    let vk_permutation_1_affine = G1Projective::new(
        vk_permutation_1_x,
        vk_permutation_1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_permutation_2_x = <G1Point as AffineCurve>::BaseField::from_str(
        "4326790911196090693615815054100226120696011467971033242010235740528024653838",
    )
    .unwrap();

    let vk_permutation_2_y = <G1Point as AffineCurve>::BaseField::from_str(
        "2667904803179432515334522273897040123387024681693314908213001653352082428084",
    )
    .unwrap();

    let vk_permutation_2_affine = G1Projective::new(
        vk_permutation_2_x,
        vk_permutation_2_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_permutation_3_x = <G1Point as AffineCurve>::BaseField::from_str(
        "13241348285608918471072487692417300120464835839349641979417147697821842654908",
    )
    .unwrap();

    let vk_permutation_3_y = <G1Point as AffineCurve>::BaseField::from_str(
        "6667438418074879936583072531555518534485986002689774883125728666911040734128",
    )
    .unwrap();

    let vk_permutation_3_affine = G1Projective::new(
        vk_permutation_3_x,
        vk_permutation_3_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_lookp_table_0_x = <G1Point as AffineCurve>::BaseField::from_str(
        "20045313662746578028950791395157660351198208045597010788369662325700141348443",
    )
    .unwrap();

    let vk_lookp_table_0_y = <G1Point as AffineCurve>::BaseField::from_str(
        "2200761695078532224145807378118591946349840073460005094399078719163643466856",
    )
    .unwrap();

    let vk_lookp_table_0_affine = G1Projective::new(
        vk_lookp_table_0_x,
        vk_lookp_table_0_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_lookp_table_1_x = <G1Point as AffineCurve>::BaseField::from_str(
        "13866646217607640441607041956684111087071997201218815349460750486791109380780",
    )
    .unwrap();

    let vk_lookp_table_1_y = <G1Point as AffineCurve>::BaseField::from_str(
        "13178446611795019678701878053235714968797421377761816259103804833273256298333",
    )
    .unwrap();

    let vk_lookp_table_1_affine = G1Projective::new(
        vk_lookp_table_1_x,
        vk_lookp_table_1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_lookp_table_2_x = <G1Point as AffineCurve>::BaseField::from_str(
        "5057503605752869531452842486824745179648819794307492731589448195268672785801",
    )
    .unwrap();

    let vk_lookp_table_2_y = <G1Point as AffineCurve>::BaseField::from_str(
        "8597434312520299647191152876265164941580478223412397470356037586993894367875",
    )
    .unwrap();

    let vk_lookp_table_2_affine = G1Projective::new(
        vk_lookp_table_2_x,
        vk_lookp_table_2_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_lookp_table_3_x = <G1Point as AffineCurve>::BaseField::from_str(
        "1342318055425277544055386589364579054544440640110901993487861472578322387903",
    )
    .unwrap();

    let vk_lookp_table_3_y = <G1Point as AffineCurve>::BaseField::from_str(
        "4438354282468267034382897187461199764068502038746983055473062465446039509158",
    )
    .unwrap();

    let vk_lookp_table_3_affine = G1Projective::new(
        vk_lookp_table_3_x,
        vk_lookp_table_3_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_lookup_selector_x = <G1Point as AffineCurve>::BaseField::from_str(
        "21395113354694454854762351476959063468617925208554049154496069024740903092231",
    )
    .unwrap();

    let vk_lookup_selector_y = <G1Point as AffineCurve>::BaseField::from_str(
        "15891706754776486805263804095178072926455306765747241658585867789806580351077",
    )
    .unwrap();

    let vk_lookup_selector_affine = G1Projective::new(
        vk_lookup_selector_x,
        vk_lookup_selector_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let vk_lookup_table_type_x = <G1Point as AffineCurve>::BaseField::from_str(
        "13676499092754057396636024302761872225487134427308588428518404161282906944615",
    )
    .unwrap();

    let vk_lookup_table_type_y = <G1Point as AffineCurve>::BaseField::from_str(
        "15549366785750703306676216604027102943243480133735900281635344353668198401192",
    )
    .unwrap();

    let vk_lookup_table_type_affine = G1Projective::new(
        vk_lookup_table_type_x,
        vk_lookup_table_type_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let queries = prepare_queries(
        vk_gate_setup_0_affine,
        vk_gate_setup_1_affine,
        vk_gate_setup_2_affine,
        vk_gate_setup_3_affine,
        vk_gate_setup_4_affine,
        vk_gate_setup_5_affine,
        vk_gate_setup_6_affine,
        vk_gate_setup_7_affine,
        vk_gate_selectors_1_affine,
        vk_permutation_3_affine,
        vk_lookp_table_0_affine,
        vk_lookp_table_1_affine,
        vk_lookp_table_2_affine,
        vk_lookp_table_3_affine,
    );

    let lookup_s_first_aggregated_commitment_coeff = queries.3;

    prepare_aggregated_commitment(
        queries,
        vk_gate_selectors_0_affine,
        vk_gate_selectors_1_affine,
        vk_permutation_0_affine,
        vk_permutation_1_affine,
        vk_permutation_2_affine,
        vk_lookup_selector_affine,
        vk_lookup_table_type_affine,
        queries.2,
        lookup_s_first_aggregated_commitment_coeff,
        queries.4,
        queries.5,
    );
}

// params
// QUERIES_AT_Z_1_X_SLOT,
// stateOpening0AtZ,
// stateOpening1AtZ,
// stateOpening2AtZ,
// stateOpening3AtZ

fn add_assign_lookup_linearisation_contribution_with_v(
    queries_at_z_1: GroupAffine<Parameters>,
    state_opening_0_z: Fr,
    state_opening_1_z: Fr,
    state_opening_2_z: Fr,
) -> (Fr, Fr) {
    // this is part of proof
    let proof_copy_permutation_grand_product_opening_at_z_omega = Fr::from_str(
        "7538059542152278064360430275006244865024464052241262187047297399810715308295",
    )
    .unwrap();

    let state_power_of_alpha_6 = Fr::from_str(
        "8319164303429084971911245066442068933512569563880543098813813308827829606918",
    )
    .unwrap();

    let state_power_of_alpha_7 = Fr::from_str(
        "5129674270777039881019141106592790354882335596282377700229200108640921885885",
    )
    .unwrap();

    let state_power_of_alpha_8 = Fr::from_str(
        "7368618184218696583873857280284780670315006906762991940416936213864621895772",
    )
    .unwrap();

    let state_l_n_minus_1_at_z = Fr::from_str(
        "5758032436361615273499003282171634310788590443862971126347537499319196954720",
    )
    .unwrap();

    let state_z_minus_last_omega = Fr::from_str(
        "6960146633092105328029573621741727691156028174137047893187470702741186149724",
    )
    .unwrap();

    let state_v_slot = Fr::from_str(
        "13330004428861975879381254388579709216101551406414154978351365682885384794150",
    )
    .unwrap();

    let proof_lookup_t_poly_opening_at_z_omega = Fr::from_str(
        "1526611985826438991010848350624117895374304477623813636492366499941649169423",
    )
    .unwrap();

    let proof_lookup_t_poly_opening_at_z =
        Fr::from_str("790573260182333997045997353662764971783884673183303056517854663274184491762")
            .unwrap();

    let state_beta_lookup = Fr::from_str(
        "11528514326249514252855703437809342841453735434183305817156029513988866631298",
    )
    .unwrap();

    let state_beta_gamma_plus_gamma = Fr::from_str(
        "11983334460880557356576830398288108328144139034428008470735158345550044764455",
    )
    .unwrap();

    let state_eta = Fr::from_str(
        "13927658615988103753598521980340228631453479498558491767944846275014039690937",
    )
    .unwrap();

    let proof_looup_table_type_poly_opening_at_z = Fr::from_str(
        "7320378240983578507320264228195167543809287353218722858998931336614363841795",
    )
    .unwrap();

    let proof_lookup_selector_poly_opening_at_z = Fr::from_str(
        "2209111850691644114898474232757656611086726698453992180215187737049963638713",
    )
    .unwrap();

    let state_gamma_lookup = Fr::from_str(
        "10143450367578341384865650570084054672128122620763568488049428709968718700978",
    )
    .unwrap();

    let state_beta_plus_one = Fr::from_str(
        "11528514326249514252855703437809342841453735434183305817156029513988866631299",
    )
    .unwrap();

    let proof_lookup_grand_product_opening_at_z_omega = Fr::from_str(
        "15834657814168463130145202123584569486416145351650914790360391211128804599867",
    )
    .unwrap();

    // check is this assignment even correct ??
    let mut factor = proof_lookup_grand_product_opening_at_z_omega;
    factor = factor.mul(state_power_of_alpha_6);
    factor = factor.mul(state_z_minus_last_omega);
    factor = factor.mul(state_v_slot);

    // saving factor into
    let lookup_s_first_aggregated_commitment_coeff = factor;

    factor = proof_lookup_t_poly_opening_at_z_omega;
    factor = factor.mul(state_beta_lookup);
    factor = factor.add(proof_lookup_t_poly_opening_at_z);
    factor = factor.add(state_beta_gamma_plus_gamma);

    println!("Factor aa: {:?}", factor.to_string());

    let mut freconstructed = state_opening_0_z;
    let eta = state_eta;
    let mut currenteta = eta;

    freconstructed = currenteta.mul(state_opening_1_z).add(freconstructed);
    currenteta = currenteta.mul(eta);
    freconstructed = currenteta.mul(state_opening_2_z).add(freconstructed);
    currenteta = currenteta.mul(eta);

    freconstructed = freconstructed.add(proof_looup_table_type_poly_opening_at_z.mul(currenteta));
    freconstructed = freconstructed.mul(proof_lookup_selector_poly_opening_at_z);
    freconstructed = freconstructed.add(state_gamma_lookup);

    factor = factor.mul(freconstructed);
    factor = factor.mul(state_beta_plus_one);
    factor = -factor;
    factor = factor.mul(state_power_of_alpha_6);
    factor = factor.mul(state_z_minus_last_omega);

    // calcualated somewhere in the middle
    let state_l_0_at_z = Fr::from_str(
        "16998705531439461081194953598960002453935573094468931463486819379249964474322",
    )
    .unwrap();

    factor = factor.add(state_l_0_at_z.mul(state_power_of_alpha_7));
    factor = factor.add(state_l_n_minus_1_at_z.mul(state_power_of_alpha_8));

    factor = factor.mul(state_v_slot);

    println!("Factor: {:?}", factor.to_string());

    (lookup_s_first_aggregated_commitment_coeff, factor)
    // LOOKUP_GRAND_PRODUCT_FIRST_AGGREGATED_COMMITMENT_COEFF

    // factor // need to store it in somewhere
}

fn add_assign_permutation_linearisation_contribution_with_v(
    queries_at_z_1: GroupAffine<Parameters>,
    state_opening_0_z: Fr,
    state_opening_1_z: Fr,
    state_opening_2_z: Fr,
    state_opening_3_z: Fr,
    vk_permutation_3_affine: GroupAffine<Parameters>,
) -> (GroupAffine<Parameters>, Fr) {
    let state_power_of_alpha_4 =
        Fr::from_str("734209011026075698694513990691048474879478463182218074328095486857043273273")
            .unwrap();

    let state_power_of_alpha_5 = Fr::from_str(
        "7399691123282490587915741115649146455372988827023544966495551648103740997779",
    )
    .unwrap();

    // z and beta are challeneges
    let state_z_slot = Fr::from_str(
        "2401351998492944598364033620572509016859399460686508186648075303585158829617",
    )
    .unwrap();

    let state_beta = Fr::from_str(
        "12819959800729781851236209017775043683910680801328587115581833969386363164195",
    )
    .unwrap();

    let state_gamma = Fr::from_str(
        "11403742565483582924983523425979943864732047046431924490681313122123733997653",
    )
    .unwrap();

    let state_v_slot = Fr::from_str(
        "13330004428861975879381254388579709216101551406414154978351365682885384794150",
    )
    .unwrap();

    // this is part of proof
    let proof_copy_permutation_grand_product_opening_at_z_omega = Fr::from_str(
        "7538059542152278064360430275006244865024464052241262187047297399810715308295",
    )
    .unwrap();

    let proof_copy_permutation_polys_0_opening_at_z = Fr::from_str(
        "5148318317103434325405029846136965801071929637258934964927797937732176388469",
    )
    .unwrap();

    let proof_copy_permutation_polys_1_opening_at_z = Fr::from_str(
        "9350083133715632760163946740136758384048496610034417316968652465998615928235",
    )
    .unwrap();

    let proof_copy_permutation_polys_2_opening_at_z = Fr::from_str(
        "20470364254908040055404858903350518240383939034306565348098332307740905863542",
    )
    .unwrap();

    let non_residue_0 = Fr::from_str("5").unwrap();
    let non_residue_1 = Fr::from_str("7").unwrap();
    let non_residue_2 = Fr::from_str("10").unwrap();

    let mut factor = state_power_of_alpha_4;

    let zmulbeta = state_z_slot.mul(state_beta);

    let mut intermediate_value = state_opening_0_z.add(zmulbeta.add(state_gamma));
    factor = factor.mul(intermediate_value);

    intermediate_value = (zmulbeta.mul(non_residue_0))
        .add(state_gamma)
        .add(state_opening_1_z);
    factor = factor.mul(intermediate_value);

    intermediate_value = (zmulbeta.mul(non_residue_1))
        .add(state_gamma)
        .add(state_opening_2_z);
    factor = factor.mul(intermediate_value);

    intermediate_value = (zmulbeta.mul(non_residue_2))
        .add(state_gamma)
        .add(state_opening_3_z);
    factor = factor.mul(intermediate_value);

    println!("Factor: {:?}", factor.to_string());
    println!("intermediate_value: {:?}", intermediate_value.to_string());

    // calcualated somewhere in the middle
    let state_l_0_at_z = Fr::from_str(
        "16998705531439461081194953598960002453935573094468931463486819379249964474322",
    )
    .unwrap();

    factor = factor.add(state_l_0_at_z.mul(state_power_of_alpha_5));
    factor = factor.mul(state_v_slot);
    // skipping storing factor for now or else we need to store it into this
    let copy_permutation_first_aggregated_commitment_coeff = factor;

    factor = state_power_of_alpha_4.mul(state_beta);

    factor = factor.mul(proof_copy_permutation_grand_product_opening_at_z_omega);

    println!("Factor 2: {:?}", factor.to_string());

    intermediate_value = state_opening_0_z
        .add(state_gamma.add(proof_copy_permutation_polys_0_opening_at_z.mul(state_beta)));
    factor = factor.mul(intermediate_value);

    intermediate_value = state_opening_1_z
        .add(state_gamma.add(proof_copy_permutation_polys_1_opening_at_z.mul(state_beta)));
    factor = factor.mul(intermediate_value);

    intermediate_value = state_opening_2_z
        .add(state_gamma.add(proof_copy_permutation_polys_2_opening_at_z.mul(state_beta)));
    factor = factor.mul(intermediate_value);

    println!("factor 2: {:?}", factor.to_string());
    println!("intermediate_value 2: {:?}", intermediate_value.to_string());

    factor = factor.mul(state_v_slot);

    let temp_query_val = vk_permutation_3_affine.mul(factor).into_affine();
    println!("Temp Query Val: {:?}", temp_query_val.x.to_string());
    println!("Temp Query Val: {:?}", temp_query_val.y.to_string());

    (
        queries_at_z_1.add(-temp_query_val),
        copy_permutation_first_aggregated_commitment_coeff,
    )
}

fn add_assign_rescue_customgate_linearisation_contribution_with_v(
    queries_at_z_1: GroupAffine<Parameters>,
    state_opening_0_z: Fr,
    state_opening_1_z: Fr,
    state_opening_2_z: Fr,
    state_opening_3_z: Fr,
    vk_gate_selectors_1_affine: GroupAffine<Parameters>,
) -> GroupAffine<Parameters> {
    // challenges wire later
    let state_alpha_slot = Fr::from_str(
        "2283206971795773822103810506163842486205626492327489207776386690517719211772",
    )
    .unwrap();

    let state_power_of_alpha_2 =
        Fr::from_str("826184778216175497174816455317911134904368857235156468525135792912866513770")
            .unwrap();

    let state_power_of_alpha_3 = Fr::from_str(
        "11473813489823724163756584140835327793445011271247834568957645433130065406474",
    )
    .unwrap();

    let state_v_slot = Fr::from_str(
        "13330004428861975879381254388579709216101551406414154978351365682885384794150",
    )
    .unwrap();

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

    vk_gate_selectors_1_affine
        .mul(accumulator)
        .into_affine()
        .add(queries_at_z_1)
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
    queries_at_z_1 =
        queries_at_z_1.add(vk_gate_setup_1_affine.mul(state_opening_1_z).into_affine());
    queries_at_z_1 =
        queries_at_z_1.add(vk_gate_setup_2_affine.mul(state_opening_2_z).into_affine());
    queries_at_z_1 =
        queries_at_z_1.add(vk_gate_setup_3_affine.mul(state_opening_3_z).into_affine());
    queries_at_z_1 = queries_at_z_1.add(
        vk_gate_setup_4_affine
            .mul(state_opening_0_z.mul(state_opening_1_z))
            .into_affine(),
    );
    queries_at_z_1 = queries_at_z_1.add(
        vk_gate_setup_5_affine
            .mul(state_opening_0_z.mul(state_opening_2_z))
            .into_affine(),
    );
    queries_at_z_1 = queries_at_z_1.add(vk_gate_setup_6_affine);

    // proof value
    let proof_state_polys_3_opening_at_z_omega_slot = Fr::from_str(
        "15977681115418510430689616723041331137718448474191693270665710012377948663376",
    )
    .unwrap();

    // proof value
    let proof_gate_selectors_0_opening_at_z = Fr::from_str(
        "8148483208534253915927418266616456459152123251080630562782462708192922425729",
    )
    .unwrap();

    // challenge
    let state_v_slot = Fr::from_str(
        "13330004428861975879381254388579709216101551406414154978351365682885384794150",
    )
    .unwrap();

    queries_at_z_1 = queries_at_z_1.add(
        vk_gate_setup_7_affine
            .mul(proof_state_polys_3_opening_at_z_omega_slot)
            .into_affine(),
    );

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
    vk_permutation_3_affine: GroupAffine<Parameters>,
    vk_lookp_table_0_affine: GroupAffine<Parameters>,
    vk_lookp_table_1_affine: GroupAffine<Parameters>,
    vk_lookp_table_2_affine: GroupAffine<Parameters>,
    vk_lookp_table_3_affine: GroupAffine<Parameters>,
) -> (
    GroupAffine<Parameters>,
    GroupAffine<Parameters>,
    Fr,
    Fr,
    GroupAffine<Parameters>,
    Fr
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
        vk_gate_selectors_1_affine,
    );

    println!(" Queries at Z 1 x Slot: {:?}", queries_at_z_1.x.to_string());
    println!(" Queries at Z 1 y Slot: {:?}", queries_at_z_1.y.to_string());
    // PROOF_QUOTIENT_POLY_PARTS_1_X_SLOT currentz QUERIES_AT_Z_0_X_SLOT
    // queries_at_z_1

    let resp = add_assign_permutation_linearisation_contribution_with_v(
        queries_at_z_1,
        state_opening_0_z,
        state_opening_1_z,
        state_opening_2_z,
        state_opening_3_z,
        vk_permutation_3_affine,
    );

    queries_at_z_1 = resp.0;
    let copy_permutation_first_aggregated_commitment_coeff = resp.1;

    println!("Queries at Z 1 x Slot: {:?}", queries_at_z_1.x.to_string());
    println!("Queries at Z 1 y Slot: {:?}", queries_at_z_1.y.to_string());

    // we are assigning few things here internally which would be required later on
    let (lookup_s_first_aggregated_commitment_coeff ,
        lookup_grand_product_first_aggregated_commitment_coeff) =
        add_assign_lookup_linearisation_contribution_with_v(
            queries_at_z_1,
            state_opening_0_z,
            state_opening_1_z,
            state_opening_2_z,
        );

    let state_eta = Fr::from_str(
        "13927658615988103753598521980340228631453479498558491767944846275014039690937",
    )
    .unwrap();

    let eta = state_eta;
    let mut currenteta = eta;

    let mut queries_t_poly_aggregated = vk_lookp_table_0_affine;
    queries_t_poly_aggregated = vk_lookp_table_1_affine
        .mul(currenteta)
        .into_affine()
        .add(queries_t_poly_aggregated);

    currenteta = currenteta.mul(eta);
    queries_t_poly_aggregated = vk_lookp_table_2_affine
        .mul(currenteta)
        .into_affine()
        .add(queries_t_poly_aggregated);
    currenteta = currenteta.mul(eta);

    queries_t_poly_aggregated = vk_lookp_table_3_affine
        .mul(currenteta)
        .into_affine()
        .add(queries_t_poly_aggregated);

    println!(
        "Queries T Poly Aggregated x Slot: {:?}",
        queries_t_poly_aggregated.x.to_string()
    );
    println!(
        "Queries T Poly Aggregated y Slot: {:?}",
        queries_t_poly_aggregated.y.to_string()
    );

    (
        queries_at_z_0,
        queries_at_z_1,
        copy_permutation_first_aggregated_commitment_coeff,
        lookup_s_first_aggregated_commitment_coeff,
        queries_t_poly_aggregated,
        lookup_grand_product_first_aggregated_commitment_coeff
    )
}

fn prepare_aggregated_commitment(
    queries: (
        GroupAffine<Parameters>,
        GroupAffine<Parameters>,
        Fr,
        Fr,
        GroupAffine<Parameters>,
        Fr
    ),
    vk_gate_selectors_0_affine: GroupAffine<Parameters>,
    vk_gate_selectors_1_affine: GroupAffine<Parameters>,
    vk_permutation_0_affine: GroupAffine<Parameters>,
    vk_permutation_1_affine: GroupAffine<Parameters>,
    vk_permutation_2_affine: GroupAffine<Parameters>,
    vk_lookup_selector_affine: GroupAffine<Parameters>,
    vk_lookup_table_type_affine: GroupAffine<Parameters>,
    copy_permutation_first_aggregated_commitment_coeff: Fr,
    lookup_s_first_aggregated_commitment_coeff: Fr,
    queries_t_poly_aggregated: GroupAffine<Parameters>,
    lookup_grand_product_first_aggregated_commitment_coeff: Fr,
) {
    let queries_z_0 = queries.0;
    let queries_z_1 = queries.1;

    println!(
        "Queries Z 0 x Slot: {:?}",
        queries_z_0.x.to_string()
    );
    let mut aggregation_challenge = Fr::from_str("1").unwrap();

    let first_d_coeff: Fr;
    let first_t_coeff: Fr;

    let mut aggregated_at_z = queries_z_0;
    let proof_quotient_poly_opening_at_z_slot = Fr::from_str(
        "9314291787638126749568703763833741152670265991986629997655170540522333691468",
    )
    .unwrap();

    let state_v_slot = Fr::from_str(
        "13330004428861975879381254388579709216101551406414154978351365682885384794150",
    )
    .unwrap();

    let proof_linearisation_poly_opening_at_z_slot = Fr::from_str(
        "19343833585712990921041961276646163448505065738578449210211290373092736702345",
    )
    .unwrap();

    let proof_state_polys_0_x = <G1Point as AffineCurve>::BaseField::from_str(
        "1481927715054811733804695304084001679108833716381348939730805268145753672319",
    )
    .unwrap();

    let proof_state_polys_0_y = <G1Point as AffineCurve>::BaseField::from_str(
        "19669144057396287036614970272557992315751929115161637121425116755403567873546",
    )
    .unwrap();

    let proof_state_polys_0 = G1Projective::new(
        proof_state_polys_0_x,
        proof_state_polys_0_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let proof_state_polys_1_x: Fp256<FqParameters> = <G1Point as AffineCurve>::BaseField::from_str(
        "682323284285379543874820022851345346716905264262521335320579112562769002731",
    )
    .unwrap();

    let proof_state_polys_1_y = <G1Point as AffineCurve>::BaseField::from_str(
        "5217046082481373877595103417334854412976806729710145608068750987850547916448",
    )
    .unwrap();

    let proof_state_polys_1 = G1Projective::new(
        proof_state_polys_1_x,
        proof_state_polys_1_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let proof_state_polys_2_x = <G1Point as AffineCurve>::BaseField::from_str(
        "11521515194924070836496020366293362780278763599237451670444937035209680455608",
    )
    .unwrap();

    let proof_state_polys_2_y = <G1Point as AffineCurve>::BaseField::from_str(
        "16730301635986498141605740614067891009670237901703266245689883569759929817706",
    )
    .unwrap();

    let proof_state_polys_2 = G1Projective::new(
        proof_state_polys_2_x,
        proof_state_polys_2_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

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

    let proof_gate_selectors_0_opening_at_z = Fr::from_str(
        "8148483208534253915927418266616456459152123251080630562782462708192922425729",
    )
    .unwrap();

    let proof_copy_permutation_polys_0_opening_at_z = Fr::from_str(
        "5148318317103434325405029846136965801071929637258934964927797937732176388469",
    )
    .unwrap();

    let proof_copy_permutation_polys_1_opening_at_z = Fr::from_str(
        "9350083133715632760163946740136758384048496610034417316968652465998615928235",
    )
    .unwrap();

    let proof_copy_permutation_polys_2_opening_at_z = Fr::from_str(
        "20470364254908040055404858903350518240383939034306565348098332307740905863542",
    )
    .unwrap();

    let proof_lookup_t_poly_opening_at_z =
        Fr::from_str("790573260182333997045997353662764971783884673183303056517854663274184491762")
            .unwrap();

    let proof_lookup_selector_poly_opening_at_z = Fr::from_str(
        "2209111850691644114898474232757656611086726698453992180215187737049963638713",
    )
    .unwrap();

    let proof_lookup_table_type_poly_opening_at_z = Fr::from_str(
        "7320378240983578507320264228195167543809287353218722858998931336614363841795",
    )
    .unwrap();

    let mut aggregated_opening_at_z = proof_quotient_poly_opening_at_z_slot;

    aggregated_at_z = aggregated_at_z.add(queries_z_1);
    aggregation_challenge = aggregation_challenge.mul(state_v_slot);

    aggregated_opening_at_z = aggregated_opening_at_z
        .add(aggregation_challenge.mul(proof_linearisation_poly_opening_at_z_slot));

    fn update_aggregation_challenge(
        queries_commitment_pt: GroupAffine<Parameters>,
        value_at_z: Fr,
        curr_aggregation_challenge: Fr,
        current_agg_opening_at_z: Fr,
        state_v_slot: Fr,
        aggregated_at_z: GroupAffine<Parameters>,
    ) -> (Fr, GroupAffine<Parameters>, Fr) {
        let mut new_agg_challenege = curr_aggregation_challenge.mul(state_v_slot);
        let new_aggregated_at_z = queries_commitment_pt
            .mul(new_agg_challenege)
            .into_affine()
            .add(aggregated_at_z);
        let new_agg_opening_at_z = new_agg_challenege
            .mul(value_at_z)
            .add(current_agg_opening_at_z);
        (
            new_agg_challenege,
            new_aggregated_at_z,
            new_agg_opening_at_z,
        )
    }

    let mut update_agg_challenge = update_aggregation_challenge(
        proof_state_polys_0,
        state_opening_0_z,
        aggregation_challenge,
        aggregated_opening_at_z,
        state_v_slot,
        aggregated_at_z,
    );

    aggregated_at_z = update_agg_challenge.1;
    
    println!("Aggregated at z 1 {:?}", aggregated_at_z.x.to_string());


    aggregation_challenge = update_agg_challenge.0;
    println!("Aggregation Challenge 1 {:?}", aggregation_challenge.to_string());
    aggregated_opening_at_z = update_agg_challenge.2;

    update_agg_challenge = update_aggregation_challenge(
        proof_state_polys_1,
        state_opening_1_z,
        aggregation_challenge,
        aggregated_opening_at_z,
        state_v_slot,
        aggregated_at_z,
    );

    aggregated_at_z = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_at_z = update_agg_challenge.2;
    println!("Aggregated at z 2 {:?}", aggregated_at_z.x.to_string());
    println!("Aggregation Challenge 2 {:?}", aggregation_challenge.to_string());


    update_agg_challenge = update_aggregation_challenge(
        proof_state_polys_2,
        state_opening_2_z,
        aggregation_challenge,
        aggregated_opening_at_z,
        state_v_slot,
        aggregated_at_z,
    );

    aggregated_at_z = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_at_z = update_agg_challenge.2;
    println!("Aggregated at z 3 {:?}", aggregated_at_z.x.to_string());
    println!("Aggregation Challenge 3 {:?}", aggregation_challenge.to_string());


    aggregation_challenge = aggregation_challenge.mul(state_v_slot);
    first_d_coeff = aggregation_challenge;

    aggregated_opening_at_z = aggregation_challenge
        .mul(state_opening_3_z)
        .add(aggregated_opening_at_z);

    update_agg_challenge = update_aggregation_challenge(
        vk_gate_selectors_0_affine,
        proof_gate_selectors_0_opening_at_z,
        aggregation_challenge,
        aggregated_opening_at_z,
        state_v_slot,
        aggregated_at_z,
    );

    aggregated_at_z = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_at_z = update_agg_challenge.2;

    println!("Aggregated at z 4 {:?}", aggregated_at_z.x.to_string());
    println!("Aggregation Challenge 4 {:?}", aggregation_challenge.to_string());



    update_agg_challenge = update_aggregation_challenge(
        vk_permutation_0_affine,
        proof_copy_permutation_polys_0_opening_at_z,
        aggregation_challenge,
        aggregated_opening_at_z,
        state_v_slot,
        aggregated_at_z,
    );

    aggregated_at_z = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_at_z = update_agg_challenge.2;

    println!("Aggregated at z 5 {:?}", aggregated_at_z.x.to_string());
    println!("Aggregation Challenge 5 {:?}", aggregation_challenge.to_string());

    update_agg_challenge = update_aggregation_challenge(
        vk_permutation_1_affine,
        proof_copy_permutation_polys_1_opening_at_z,
        aggregation_challenge,
        aggregated_opening_at_z,
        state_v_slot,
        aggregated_at_z,
    );

    aggregated_at_z = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_at_z = update_agg_challenge.2;

    println!("Aggregated at z 6 {:?}", aggregated_at_z.x.to_string());
    println!("Aggregation Challenge 6 {:?}", aggregation_challenge.to_string());

    update_agg_challenge = update_aggregation_challenge(
        vk_permutation_2_affine,
        proof_copy_permutation_polys_2_opening_at_z,
        aggregation_challenge,
        aggregated_opening_at_z,
        state_v_slot,
        aggregated_at_z,
    );

    aggregated_at_z = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_at_z = update_agg_challenge.2;

    println!("Aggregated at z 7 {:?}", aggregated_at_z.x.to_string());
    println!("Aggregation Challenge 7 {:?}", aggregation_challenge.to_string());

    aggregation_challenge = aggregation_challenge.mul(state_v_slot);
    first_t_coeff = aggregation_challenge;

    aggregated_opening_at_z = aggregation_challenge
        .mul(proof_lookup_t_poly_opening_at_z)
        .add(aggregated_opening_at_z);

    update_agg_challenge = update_aggregation_challenge(
        vk_lookup_selector_affine,
        proof_lookup_selector_poly_opening_at_z,
        aggregation_challenge,
        aggregated_opening_at_z,
        state_v_slot,
        aggregated_at_z,
    );

    aggregated_at_z = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_at_z = update_agg_challenge.2;

    println!("Aggregated at z 8 {:?}", aggregated_at_z.x.to_string());
    println!("Aggregation Challenge 8 {:?}", aggregation_challenge.to_string());

    update_agg_challenge = update_aggregation_challenge(
        vk_lookup_table_type_affine,
        proof_lookup_table_type_poly_opening_at_z,
        aggregation_challenge,
        aggregated_opening_at_z,
        state_v_slot,
        aggregated_at_z,
    );

    aggregated_at_z = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_at_z = update_agg_challenge.2;
    println!("Aggregated at z 9 {:?}", aggregated_at_z.x.to_string());
    println!("Aggregation Challenge 9 {:?}", aggregation_challenge.to_string());

    // storing aggregated opening at z
    // mstore(AGGREGATED_OPENING_AT_Z_SLOT, aggregatedOpeningAtZ)
    println!(
        "Aggregated Opening at Z x Slot: {:?}",
        aggregated_opening_at_z.to_string()
    );

    aggregation_challenge = aggregation_challenge.mul(state_v_slot);

    let state_u = Fr::from_str(
        "1288818797502384203299534503559211197379962355037926217584736460242183741135",
    )
    .unwrap();

    let copy_permutation_coeff = aggregation_challenge
        .mul(state_u)
        .add(copy_permutation_first_aggregated_commitment_coeff);



    // proof component
    let proof_copy_permutation_grand_product_x = <G1Point as AffineCurve>::BaseField::from_str(
        "10682973389427934500889390913980545461720540728378117423453967866054801517546",
    )
    .unwrap();

    let proof_copy_permutation_grand_product_y = <G1Point as AffineCurve>::BaseField::from_str(
        "19640862922252046012593809239563773424382616310643479928760400654556187984808",
    )
    .unwrap();

    let proof_copy_permutation_grand_product_affine = G1Projective::new(
        proof_copy_permutation_grand_product_x,
        proof_copy_permutation_grand_product_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();



    let proof_copy_permutation_grand_product_opening_at_z_omega = Fr::from_str(
        "7538059542152278064360430275006244865024464052241262187047297399810715308295",
    )
    .unwrap();

    let mut aggregated_z_omega = proof_copy_permutation_grand_product_affine
        .mul(copy_permutation_coeff)
        .into_affine();

    println!("Copy perm coeff {:?}", copy_permutation_coeff.to_string());
    println!(
        "Aggfldkhbldkghf Slot: {:?}",
        aggregated_z_omega.x.to_string()
    );

    let mut aggregated_opening_z_omega =
        proof_copy_permutation_grand_product_opening_at_z_omega.mul(aggregation_challenge);

    println!(
        "Aggregated Opening at Z Omega x Slot: {:?}",
        aggregated_opening_z_omega.to_string()
    );

    let proof_state_polys_3_x = <G1Point as AffineCurve>::BaseField::from_str(
        "7648216166271091756697000850759109818942352153393449549967097850294823322486",
    )
    .unwrap();

    let proof_state_polys_3_y = <G1Point as AffineCurve>::BaseField::from_str(
        "13841059918140042479305358189720506803328611470904137853333589893028890921956",
    )
    .unwrap();

    let proof_state_polys_3 = G1Projective::new(
        proof_state_polys_3_x,
        proof_state_polys_3_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let proof_state_polys_3_opening_at_z_omega_slot = Fr::from_str(
        "15977681115418510430689616723041331137718448474191693270665710012377948663376",
    )
    .unwrap();

    fn update_aggregation_challenge_second(
        queries_commitment_pt: GroupAffine<Parameters>,
        value_at_zomega: Fr,
        prev_coeff: Fr,
        curr_aggregation_challenge: Fr,
        current_aggregated_opening_z_omega: Fr,
        state_v_slot: Fr,
        state_u_slot: Fr,
        aggregated_at_z_omega: GroupAffine<Parameters>,
    ) -> (Fr, GroupAffine<Parameters>, Fr) {
        let new_aggregation_challenge = curr_aggregation_challenge.mul(state_v_slot);
        let final_coeff = new_aggregation_challenge.mul(state_u_slot).add(prev_coeff);
        let new_aggregated_at_z_omega = queries_commitment_pt
            .mul(final_coeff)
            .into_affine()
            .add(aggregated_at_z_omega);
        let new_aggregated_opening_at_z_omega = new_aggregation_challenge
            .mul(value_at_zomega)
            .add(current_aggregated_opening_z_omega);
        (
            new_aggregation_challenge,
            new_aggregated_at_z_omega,
            new_aggregated_opening_at_z_omega,
        )
    }

    update_agg_challenge = update_aggregation_challenge_second(
        proof_state_polys_3,
        proof_state_polys_3_opening_at_z_omega_slot,
        first_d_coeff,
        aggregation_challenge,
        aggregated_opening_z_omega,
        state_v_slot,
        state_u,
        aggregated_z_omega,
    );

    aggregated_z_omega = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_z_omega = update_agg_challenge.2;

    println!("Aggregated at z omega 1 {:?}", aggregated_z_omega.x.to_string());
    println!("Aggregation Challenge 1 {:?}", aggregation_challenge.to_string());

    let proof_lookup_s_poly_x = <G1Point as AffineCurve>::BaseField::from_str(
        "20887469144570360598226846219688412569127314117060464745189593667525340515656",
    )
    .unwrap();

    let proof_lookup_s_poly_y = <G1Point as AffineCurve>::BaseField::from_str(
        "17016442743265291319847312885025674149359385754888666855828695845548134601930",
    )
    .unwrap();

    let proof_lookup_s_poly = G1Projective::new(
        proof_lookup_s_poly_x,
        proof_lookup_s_poly_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    let proof_lookup_s_poly_opening_at_z_omega = Fr::from_str(
        "7036240067875131759268503442624403515627271384033836780470587737696909190933",
    )
    .unwrap();

    let proof_lookup_grand_product_x = <G1Point as AffineCurve>::BaseField::from_str(
        "9589178903221618453208009241401184562093337063441620358881756562676120576984",
    )
    .unwrap();

    let proof_lookup_grand_product_y = <G1Point as AffineCurve>::BaseField::from_str(
        "13587607855302777394786571902811537225748207835844766425168460163223723298480",
    )
    .unwrap();

    let proof_lookup_grand_product_affine = G1Projective::new(
        proof_lookup_grand_product_x,
        proof_lookup_grand_product_y,
        <G1Projective as ProjectiveCurve>::BaseField::one(),
    )
    .into_affine();

    update_agg_challenge = update_aggregation_challenge_second(
        proof_lookup_s_poly,
        proof_lookup_s_poly_opening_at_z_omega,
        lookup_s_first_aggregated_commitment_coeff,
        aggregation_challenge,
        aggregated_opening_z_omega,
        state_v_slot,
        state_u,
        aggregated_z_omega,
    );

    aggregated_z_omega = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_z_omega = update_agg_challenge.2;

    println!("Aggregated at z omega 2 {:?}", aggregated_z_omega.x.to_string());
    println!("Aggregation Challenge 2 {:?}", aggregation_challenge.to_string());

    let proof_lookup_grand_product_opening_at_z_omega = Fr::from_str(
        "15834657814168463130145202123584569486416145351650914790360391211128804599867",
    )
    .unwrap();

    let proof_lookup_t_poly_opening_at_z_omega = Fr::from_str(
        "1526611985826438991010848350624117895374304477623813636492366499941649169423",
    )
    .unwrap();

    update_agg_challenge = update_aggregation_challenge_second(
        proof_lookup_grand_product_affine,
        proof_lookup_grand_product_opening_at_z_omega,
        lookup_grand_product_first_aggregated_commitment_coeff,
        aggregation_challenge,
        aggregated_opening_z_omega,
        state_v_slot,
        state_u,
        aggregated_z_omega,
    );

    aggregated_z_omega = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_z_omega = update_agg_challenge.2;

    println!("kdfghfgh {:?}", lookup_grand_product_first_aggregated_commitment_coeff.to_string());

    println!("Aggregated at z omega 3 {:?}", aggregated_z_omega.x.to_string());
    println!("Aggregation Challenge 3 {:?}", aggregation_challenge.to_string());

    update_agg_challenge = update_aggregation_challenge_second(
        queries_t_poly_aggregated,
        proof_lookup_t_poly_opening_at_z_omega,
        first_t_coeff,
        aggregation_challenge,
        aggregated_opening_z_omega,
        state_v_slot,
        state_u,
        aggregated_z_omega,
    );

    aggregated_z_omega = update_agg_challenge.1;
    aggregation_challenge = update_agg_challenge.0;
    aggregated_opening_z_omega = update_agg_challenge.2;

    println!("Aggregated at z omega 4 {:?}", aggregated_z_omega.x.to_string());
    println!("Aggregation Challenge 4 {:?}", aggregation_challenge.to_string());

    // store aggregated_opening_z_omega somewhere and return it as it might be used somewhere else

    println!(
        "Aggregated at z x Slot: {:?}",
        aggregated_at_z.x.to_string()
    );

    println!(
        "Aggregated Z Omega x Slot: {:?}",
        aggregated_z_omega.x.to_string()
    );

    let pairing_pair_with_generator = aggregated_at_z.add(aggregated_z_omega);

    println!(
        "Pairing Pair with Generator x Slot: {:?}",
        pairing_pair_with_generator.x.to_string()
    );

    let aggregated_value = aggregated_opening_z_omega
        .mul(state_u)
        .add(aggregated_opening_at_z);

    println!(
        "Aggregated Value x Slot: {:?}",
        aggregated_value.to_string()
    );

    // mstore(PAIRING_BUFFER_POINT_X_SLOT, 1)
    //             mstore(PAIRING_BUFFER_POINT_Y_SLOT, 2)
    // pointMulIntoDest(PAIRING_BUFFER_POINT_X_SLOT, aggregatedValue, PAIRING_BUFFER_POINT_X_SLOT)
}

// PROOF_QUOTIENT_POLY_OPENING_AT_Z_SLOT_term
// PROOF_LINEARISATION_POLY_OPENING_AT_Z_SLOT_term
// PROOF_STATE_POLYS_0_X_SLOT
// PROOF_STATE_POLYS_1_X_SLOT
// PROOF_STATE_POLYS_2_X_SLOT

// }

// PROOF_QUOTIENT_POLY_PARTS_1_X_SLOT_term
// QUERIES_AT_Z_0_X_SLOT_term
// QUERIES_AT_Z_0_X_SLOT_y_term
