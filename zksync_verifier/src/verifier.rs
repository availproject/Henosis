pub use crate::utils::{get_domain_size, get_omegas, get_proof, get_pubSignals, Omegas, Proof, ProofWithPubSignal};
use ark_bn254::{
    g1, g1::Parameters, Bn254, Fq, FqParameters, Fr, FrParameters, G1Projective, G2Projective,
};
use ark_bn254::{g2, Fq2, Fq2Parameters, G2Affine};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ec::*;
use ark_ff::{
    field_new, BigInteger, Field, Fp256, Fp256Parameters, Fp2ParamsWrapper, One, PrimeField, QuadExtField, UniformRand, Zero
};
use ark_poly::{domain, Polynomial};
use core::num;
use std::fmt::{format, Debug, DebugMap, Display};
use std::hash::Hash;
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};
use std::str::FromStr;
use std::vec;
use crate::utils::{get_proog_bigint, get_verification_key, PartialVerifierState};
use num_bigint::*;

use tiny_keccak::{Hasher, Keccak};
use num_bigint::BigUint;


pub type G1Point = <Bn254 as PairingEngine>::G1Affine;
pub type G2Point = <Bn254 as PairingEngine>::G2Affine;

pub struct Transcript {
    // uint256 constant FR_MASK = 0x1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff;

    // uint32 constant DST_0 = 0;
    // uint32 constant DST_1 = 1;
    // uint32 constant DST_CHALLENGE = 2;
    state_0: [u8; 32], // bytes32 in Solidity is equivalent to an array of 32 bytes in Rust
    state_1: [u8; 32], // Similarly, bytes32 translates to [u8; 32] in Rust
    challenge_counter: u32, // uint32 in Solidity is equivalent to u32 in Rust
    FR_MASK: Fp256<FrParameters>,
    DST_0: u32,
    DST_1: u32,
    DST_CHALLENGE: u32,
}




impl Transcript {
    fn new_transcript() -> Self {
        Transcript {
            state_0: [0; 32], // Initializes state_0 with 32 bytes of zeros
            state_1: [0; 32], // Initializes state_1 with 32 bytes of zeros
            challenge_counter: 0, // Initializes challenge_counter to 0
            FR_MASK: Fr::from_str("14474011154664524427946373126085988481658748083205070504932198000989141204991").unwrap(),
            DST_0: 0,
            DST_1: 1,
            DST_CHALLENGE: 2,
        }
    }
    pub fn update_transcript(&mut self, value: &[u8]) {
        // Assuming TRANSCRIPT_BEGIN_SLOT is an initial part of the transcript
        // and it's somehow represented or stored. For this example, let's just use
        // a vector to simulate the whole transcript for simplicity.
        let mut transcript = Keccak::v256();

        // Simulate DST_0 and DST_1 as part of the transcript. In a real scenario,
        // these would be properly defined and included as per your protocol's design.
        let dst_0: u8 = 0;
        let dst_1: u8 = 1;

        // Update the transcript with DST_0 and the value, then hash it for newState0
        let val_beg = padd_bytes3(0u8.to_be_bytes().to_vec());
        // println!("val_beg: {:?}", val_beg);
        let val_dst = (dst_0.to_be_bytes().to_vec()); 
        // println!("val_dst: {:?}", val_dst);
        let val_s0 = padd_bytes32(self.state_0.to_vec());
        // println!("val_s0: {:?}", val_s0);
        let val_s1 = padd_bytes32(self.state_1.to_vec());
        // println!("val_s1: {:?}", val_s1);
        let val_chall = padd_bytes32(value.to_vec());
        // println!("val_chall: {:?}", val_chall);
        
        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&val_beg);
        concatenated.extend_from_slice(&val_dst);
        concatenated.extend_from_slice(&val_s0);
        concatenated.extend_from_slice(&val_s1);
        concatenated.extend_from_slice(&val_chall);
        transcript.update(&concatenated);
        let mut out = [0u8; 32];
        transcript.finalize(&mut out);
        let newState0 = out;

        let newState0val = BigInt::from_bytes_be(Sign::Plus, &newState0);
        // println!("newState0: {:?}", newState0val);

        // Reset the transcript for the next state, then update with DST_1 and hash for newState1
        // transcript.clear();
        // transcript.push(dst_1);
        // transcript.extend_from_slice(value);
        // let newState1 = Keccak256::digest(&transcript);

        transcript = Keccak::v256();
        
        let val_beg = padd_bytes3(0u8.to_be_bytes().to_vec());
        // println!("2 val_beg: {:?}", val_beg);
        let val_dst1 = (dst_1.to_be_bytes().to_vec()); 
        // println!("2 val_dst1: {:?}", val_dst1);
        let val_s0 = padd_bytes32(self.state_0.to_vec());
        // println!("2 val_s0: {:?}", val_s0);
        let val_s1 = padd_bytes32(self.state_1.to_vec());
        // println!("2 val_s1: {:?}", val_s1);
        let val_chall = padd_bytes32(value.to_vec());
        // println!("2 val_chall: {:?}", val_chall);

        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&val_beg);
        concatenated.extend_from_slice(&val_dst1);
        concatenated.extend_from_slice(&val_s0);
        concatenated.extend_from_slice(&val_s1);
        concatenated.extend_from_slice(&val_chall);
        transcript.update(&concatenated);

        let mut out = [0u8; 32];
        transcript.finalize(&mut out);
        let newState1 = out;
        let newState1val = BigInt::from_bytes_be(Sign::Plus, &out);
        // println!("newState1: {:?}", newState1val);

        // Update the state fields with the new hashed states
        self.state_0.copy_from_slice(&newState0);
        self.state_1.copy_from_slice(&newState1);
    }


    pub fn get_transcript_challenge(&mut self, number_of_challenge: u32) -> [u8; 32] {

        let mut transcript = Keccak::v256();

        
        let val_beg = padd_bytes3(0u8.to_be_bytes().to_vec());
        let val_dst2 = 2u8.to_be_bytes().to_vec();
        let val_s0 = self.state_0.to_vec();
        let val_s1 = self.state_1.to_vec();
        // chall
        let temp_chall = BigInt::from(number_of_challenge).mul(BigInt::from(2).pow(224));
        let mut val_chall = padd_bytes32(temp_chall.to_bytes_be().1);
        let final_val_chall = &val_chall[0..4];

        // println!("final_val_chall: {:?}", final_val_chall);


        let mut concatenated = Vec::new();
        concatenated.extend_from_slice(&val_beg);
        concatenated.extend_from_slice(&val_dst2);
        concatenated.extend_from_slice(&val_s0);
        concatenated.extend_from_slice(&val_s1);
        concatenated.extend_from_slice(&final_val_chall);
        transcript.update(&concatenated);


        let mut out = [0u8; 32];
        transcript.finalize(&mut out);
        // let res = out;
        let res = BigInt::from_bytes_be(Sign::Plus, &out);
        // println!("res: {:?}", res);


        const FR_MASK: [u8; 32] = [
    0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];
        let mut res_fr = [0u8; 32];

        for i in 0..32 {
            res_fr[i] = out[i] & FR_MASK[i];
        }

        // println!("res_fr: {:?}", BigInt::from_bytes_be(Sign::Plus, &res_fr));

        res_fr
    }
}



pub fn updateTranscript() {
    
}


pub fn getTransciptChallenge() {

}

pub fn getPublicInputs() -> Fp256<FrParameters>{
    let ttt = get_fr_mask().into_repr().0[0] & get_fr_mask().into_repr().0[1];
    let pi = Fr::from_str("1481927715054811733804695304084001679108833716381348939730805268145753672319").unwrap();
    let mut res = [0u64; 4];
    for i in 0..4{
        res[i] = get_fr_mask().into_repr().0[i] & pi.into_repr().0[i];
    }
    let final_val: Fp256<FrParameters> = Fp256::from_repr(ark_ff::BigInteger256(res)).unwrap();
    // println!("ttt: {}", ttt);
    println!("final_val: {}", get_bigint_from_fr(final_val));
    Fr::from_str("7930533175376274174682760122775727104792125867965765072731098693082").unwrap()
}

pub fn get_fr_mask() -> Fp256<FrParameters>{
    Fr::from_str("14474011154664524427946373126085988481658748083205070504932198000989141204991").unwrap()
}

pub fn getDomainSize() -> u64 {
    16777216
}

pub fn getScalarField() -> Fp256<FrParameters> {
    Fr::from_str("21888242871839275222246405745257275088548364400416034343698204186575808495617").unwrap()
}

// pub fn inittializeTranscript() {
//     let mut transcript = Transcript::new_transcript();
//     update_with_u256(&mut transcript, getPublicInputs())
// }

pub fn getOmega() -> Fp256<FrParameters> {
    Fr::from_str("11451405578697956743456240853980216273390554734748796433026540431386972584651").unwrap()
}

pub fn evaluateLagrangePolyOutOfDomain(polyNum: u64 ,at: Fp256<FrParameters>) -> Fp256<FrParameters>{
    let mut omegaPower = Fr::from_str("1").unwrap();
    if polyNum > 0 {
        omegaPower = getOmega().pow(&[polyNum as u64]);
    }
    println!("omegaPower: {}", omegaPower);
    let mut res = at.pow(&[getDomainSize()]).add(getScalarField().sub(Fr::from_str("1").unwrap()));
    assert_ne!(res, Fp256::zero());

    res = res.mul(omegaPower);
    // println!("res: {}", res);

    let mut denominator = at.add(getScalarField().sub((Fr::from(omegaPower))));
    denominator = denominator.mul(Fr::from(getDomainSize()));
    

    // let mut q_mius_2 = BigInt::from_str(&getScalarField().sub(Fr::from_str("2").unwrap()).to_string()).unwrap();
    denominator = denominator.inverse().unwrap();
    // println!("denominator: {}", denominator);
    res = res.mul(denominator);
    // println!("res: {}", res);
    res


}


pub fn permutationQuotientContribution(pvs: &mut PartialVerifierState, l0AtZ: Fp256<FrParameters>) -> Fp256<FrParameters>{
    let mut res = pvs.power_of_alpha_4.mul(get_proof().copy_permutation_grand_product_opening_at_z_omega);
    let mut factorMultiplier;

    factorMultiplier = get_proof().copy_permutation_polys_0_opening_at_z.mul(pvs.beta);
    // println!("factorMultiplier: {}", factorMultiplier);
    factorMultiplier = factorMultiplier.add(pvs.gamma);
    factorMultiplier = factorMultiplier.add(get_proof().state_poly_0_opening_at_z);
    res = res.mul(factorMultiplier);

    // println!("res: {}", res);
    factorMultiplier = get_proof().copy_permutation_polys_1_opening_at_z.mul(pvs.beta);
    factorMultiplier = factorMultiplier.add(pvs.gamma);
    factorMultiplier = factorMultiplier.add(get_proof().state_poly_1_opening_at_z);
    res = res.mul(factorMultiplier);

    factorMultiplier = get_proof().copy_permutation_polys_2_opening_at_z.mul(pvs.beta);
    factorMultiplier = factorMultiplier.add(pvs.gamma);
    factorMultiplier = factorMultiplier.add(get_proof().state_poly_2_opening_at_z);
    res = res.mul(factorMultiplier);


    // println!("get_proof().state_poly_3_opening_at_z_omega: {}", get_bigint_from_fr(get_proof().state_poly_3_opening_at_z_omega));
    res = res.mul(get_proof().state_poly_3_opening_at_z.add(pvs.gamma));

    // println!("res: {}", get_bigint_from_fr(res));


    res = getScalarField().sub(res);

    let mut temp_l0atz = l0AtZ.clone();

    temp_l0atz = temp_l0atz.mul(pvs.power_of_alpha_5);

    res = res.add(temp_l0atz.neg());
    // println!("res: {}", get_bigint_from_fr(res));

    res
}


pub fn lookupQuotientContribution(pvs: &mut PartialVerifierState) -> Fp256<FrParameters>{

    let betaplusone = pvs.beta_lookup.add(Fr::from_str("1").unwrap());
    let betaGamma = betaplusone.mul(pvs.gamma_lookup);

    let mut res = get_proof().lookup_s_poly_opening_at_z_omega.mul(pvs.beta_lookup);
    res = res.add(betaGamma);
    res = res.mul(get_proof().lookup_grand_product_opening_at_z_omega);
    res = res.mul(pvs.power_of_alpha_6);

    // println!("res: {}", get_bigint_from_fr(res));
    let mut lastOmega = getOmega().pow([getDomainSize()-1]);
    println!("lastOmega: {}", get_bigint_from_fr(lastOmega));
    let zMinusLastOmega = pvs.z.add(lastOmega.neg());
    res = res.mul(zMinusLastOmega);
    

    let intermediateValue = pvs.l_0_at_z.mul(pvs.power_of_alpha_7);
    res = res.add(intermediateValue.neg());

    let betaGammaPowered = betaGamma.pow([getDomainSize()-1]);
    let subtrahend = pvs.power_of_alpha_8.mul(pvs.l_n_minus_one_at_z.mul(betaGammaPowered));
    res = res.add(subtrahend.neg());
    println!("res: {}", get_bigint_from_fr(res));
    res



}

pub fn verifyQuotientEvaluation(mut pvs: PartialVerifierState) {

    let alpha_2 = pvs.alpha.mul(pvs.alpha);
    let alpha_3 = pvs.power_of_alpha_3;
    let alpha_4 = pvs.power_of_alpha_4;
    let alpha_5 = pvs.power_of_alpha_5;
    let alpha_6 = pvs.power_of_alpha_6;
    let alpha_7 = pvs.power_of_alpha_7;
    let alpha_8 = pvs.power_of_alpha_8;


    let l0atz= evaluateLagrangePolyOutOfDomain(0, pvs.z);

    let lnmius1atZ = evaluateLagrangePolyOutOfDomain(getDomainSize()-1, pvs.z);

    pvs.l_0_at_z = l0atz;
    pvs.l_n_minus_one_at_z = lnmius1atZ;

    // let mut pvs = PartialVerifierState{
    //     alpha,
    //     beta: Fr::from_str("12819959800729781851236209017775043683910680801328587115581833969386363164195").unwrap(),
    //     gamma: Fr::from_str("11403742565483582924983523425979943864732047046431924490681313122123733997653").unwrap(),
    //     power_of_alpha_2: alpha_2,
    //     power_of_alpha_3: alpha_3,
    //     power_of_alpha_4: alpha_4,
    //     power_of_alpha_5: alpha_5,
    //     power_of_alpha_6: alpha_6,
    //     power_of_alpha_7: alpha_7,
    //     power_of_alpha_8: alpha_8,
    //     eta: Fr::from_str("13927658615988103753598521980340228631453479498558491767944846275014039690937").unwrap(),
    //     beta_lookup: Fr::from_str("11528514326249514252855703437809342841453735434183305817156029513988866631298").unwrap(),
    //     gamma_lookup: Fr::from_str("10143450367578341384865650570084054672128122620763568488049428709968718700978").unwrap(),
    //     beta_plus_one: Fr::from_str("1481927715054811733804695304084001679108833716381348939730805268145753672319").unwrap(),
    //     beta_gamma_plus_gamma: Fr::from_str("1481927715054811733804695304084001679108833716381348939730805268145753672319").unwrap(),
    //     v: Fr::from_str("13330004428861975879381254388579709216101551406414154978351365682885384794150").unwrap(), 
    //     u: Fr::from_str("1288818797502384203299534503559211197379962355037926217584736460242183741135").unwrap(),
    //     z: Fr::from_str("2401351998492944598364033620572509016859399460686508186648075303585158829617").unwrap(),
    //     z_minus_last_omega: Fr::from_str("1481927715054811733804695304084001679108833716381348939730805268145753672319").unwrap(),
    //     l_0_at_z: l0atz,
    //     l_n_minus_one_at_z: lnmius1atZ,
    //     z_in_domain_size: Fr::from_str("8306037114154435423292901166608307526952350843292506299851821833617177949622").unwrap(),

    // };


    let stateT = l0atz.mul(getPublicInputs());
    // println!("stateT: {}", get_bigint_from_fr(stateT));

    let mut result = stateT.mul(get_proof().gate_selectors_0_opening_at_z);
    

    result = result.add(permutationQuotientContribution(&mut pvs, l0atz));
    // println!("result: {}", get_bigint_from_fr(result));

    result = result.add(lookupQuotientContribution(&mut pvs));

    result = result.add(get_proof().linearisation_poly_opening_at_z);

    // println!("result: {}", get_bigint_from_fr(result));

    let vanishing = pvs.z_in_domain_size.add(Fr::from_str("1").unwrap().neg());

    
    let lhs = get_proof().quotient_poly_opening_at_z.mul(vanishing);
   
    assert_eq!(lhs, result);
}


pub fn get_challenges(pvs: &mut PartialVerifierState) {
    let mut transcript = Transcript::new_transcript();

    transcript.update_transcript(&get_u8arr_from_fr(getPublicInputs()));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().state_poly_0.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().state_poly_0.y));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().state_poly_1.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().state_poly_1.y));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().state_poly_2.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().state_poly_2.y));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().state_poly_3.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().state_poly_3.y));

    let etaaa = transcript.get_transcript_challenge(0);
    println!("etaaa: {}", BigInt::from_bytes_be(Sign::Plus, &etaaa));
    
    //round 1.5
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().lookup_s_poly.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().lookup_s_poly.y));

    let betaa = transcript.get_transcript_challenge(1);
    let gammma = transcript.get_transcript_challenge(2);
    println!("betaa: {}", BigInt::from_bytes_be(Sign::Plus, &betaa));
    println!("gammma: {}", BigInt::from_bytes_be(Sign::Plus, &gammma));

    //round 2

    transcript.update_transcript(&get_u8arr_from_fq(get_proof().copy_permutation_grand_product.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().copy_permutation_grand_product.y));

    let beta_lookuppp = transcript.get_transcript_challenge(3);
    let gamma_lookuppp = transcript.get_transcript_challenge(4);
    println!("beta_lookuppp: {}", BigInt::from_bytes_be(Sign::Plus, &beta_lookuppp));
    println!("gamma_lookuppp: {}", BigInt::from_bytes_be(Sign::Plus, &gamma_lookuppp));

    //round 2.5

    transcript.update_transcript(&get_u8arr_from_fq(get_proof().lookup_grand_product.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().lookup_grand_product.y));

    let alphaaa = transcript.get_transcript_challenge(5);
    println!("alphaaa: {}", BigInt::from_bytes_be(Sign::Plus, &alphaaa));


    //round 3

    transcript.update_transcript(&get_u8arr_from_fq(get_proof().quotient_poly_parts_0.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().quotient_poly_parts_0.y));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().quotient_poly_parts_1.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().quotient_poly_parts_1.y));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().quotient_poly_parts_2.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().quotient_poly_parts_2.y));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().quotient_poly_parts_3.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().quotient_poly_parts_3.y));

    let zz = transcript.get_transcript_challenge(6);
    let zz_in_domain_size = get_fr_from_u8arr(zz.to_vec()).pow([getDomainSize()]);
    println!("zz: {}", BigInt::from_bytes_be(Sign::Plus, &zz));
    println!("zz_in_domain_size: {}", get_bigint_from_fr(zz_in_domain_size));


    //round 4

    transcript.update_transcript(&get_u8arr_from_fr(get_proof().quotient_poly_opening_at_z));

    transcript.update_transcript(&get_u8arr_from_fr(get_proof().state_poly_0_opening_at_z));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().state_poly_1_opening_at_z));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().state_poly_2_opening_at_z));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().state_poly_3_opening_at_z));

    transcript.update_transcript(&get_u8arr_from_fr(get_proof().state_poly_3_opening_at_z_omega));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().gate_selectors_0_opening_at_z));

    transcript.update_transcript(&get_u8arr_from_fr(get_proof().copy_permutation_polys_0_opening_at_z));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().copy_permutation_polys_1_opening_at_z));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().copy_permutation_polys_2_opening_at_z));

    transcript.update_transcript(&get_u8arr_from_fr(get_proof().copy_permutation_grand_product_opening_at_z_omega));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().lookup_t_poly_opening_at_z));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().lookup_selector_poly_opening_at_z));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().lookup_table_type_poly_opening_at_z));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().lookup_s_poly_opening_at_z_omega));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().lookup_grand_product_opening_at_z_omega));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().lookup_t_poly_opening_at_z_omega));
    transcript.update_transcript(&get_u8arr_from_fr(get_proof().linearisation_poly_opening_at_z));

    let vv = transcript.get_transcript_challenge(7);

    println!("vv: {}", BigInt::from_bytes_be(Sign::Plus, &vv));


    // round 5

    transcript.update_transcript(&get_u8arr_from_fq(get_proof().opening_proof_at_z.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().opening_proof_at_z.y));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().opening_proof_at_z_omega.x));
    transcript.update_transcript(&get_u8arr_from_fq(get_proof().opening_proof_at_z_omega.y));

    let uu = transcript.get_transcript_challenge(8);
    println!("uu: {}", BigInt::from_bytes_be(Sign::Plus, &uu));

    let power_of_alpha_1 =  get_fr_from_u8arr(alphaaa.to_vec());
    let power_of_alpha_2 = power_of_alpha_1.mul(power_of_alpha_1);
    let power_of_alpha_3 = power_of_alpha_2.mul(power_of_alpha_1);
    let power_of_alpha_4 = power_of_alpha_3.mul(power_of_alpha_1);
    let power_of_alpha_5 = power_of_alpha_4.mul(power_of_alpha_1);
    let power_of_alpha_6 = power_of_alpha_5.mul(power_of_alpha_1);
    let power_of_alpha_7 = power_of_alpha_6.mul(power_of_alpha_1);
    let power_of_alpha_8 = power_of_alpha_7.mul(power_of_alpha_1);

    pvs.alpha = power_of_alpha_1;
    pvs.beta = get_fr_from_u8arr(betaa.to_vec());
    pvs.gamma = get_fr_from_u8arr(gammma.to_vec());
    pvs.power_of_alpha_2 = power_of_alpha_2;
    pvs.power_of_alpha_3 = power_of_alpha_3;
    pvs.power_of_alpha_4 = power_of_alpha_4;
    pvs.power_of_alpha_5 = power_of_alpha_5;
    pvs.power_of_alpha_6 = power_of_alpha_6;
    pvs.power_of_alpha_7 = power_of_alpha_7;
    pvs.power_of_alpha_8 = power_of_alpha_8;
    pvs.eta = get_fr_from_u8arr(etaaa.to_vec());
    pvs.beta_lookup = get_fr_from_u8arr(beta_lookuppp.to_vec());
    pvs.gamma_lookup = get_fr_from_u8arr(gamma_lookuppp.to_vec());
    pvs.beta_plus_one = pvs.beta.add(Fr::from_str("1").unwrap());
    pvs.beta_gamma_plus_gamma = pvs.beta.mul(pvs.gamma).add(pvs.gamma);
    pvs.v = get_fr_from_u8arr(vv.to_vec());
    pvs.u = get_fr_from_u8arr(uu.to_vec());
    pvs.z = get_fr_from_u8arr(zz.to_vec());
    pvs.z_minus_last_omega = pvs.z.add(getOmega().pow([getDomainSize()-1]).neg());
    pvs.z_in_domain_size = zz_in_domain_size;

}

pub fn verify(){

    let alpha = Fr::from_str("2283206971795773822103810506163842486205626492327489207776386690517719211772").unwrap();
    
    let z = Fr::from_str("2401351998492944598364033620572509016859399460686508186648075303585158829617").unwrap();
    println!("Verifying....");

    let mut pvs = PartialVerifierState::new();
    get_challenges(&mut pvs);
    verifyQuotientEvaluation(pvs);
    println!("Verified....");

}


// pub fn get_proof() -> Proof{


// }

pub fn get_u8arr_from_fq(fq: Fp256<FqParameters>) -> Vec<u8> {
    let mut st = fq.to_string();
    let temp = &st[8..8+64];
    BigInt::parse_bytes(temp.as_bytes(), 16).unwrap().to_bytes_be().1
}

pub fn get_u8arr_from_fr(fr: Fp256<FrParameters>) -> Vec<u8> {
    get_bigint_from_fr(fr).to_bytes_be().1
}

pub fn get_fr_from_u8arr(arr: Vec<u8>) -> Fp256<FrParameters> {
    let temp = BigInt::from_bytes_be(Sign::Plus, &arr);
    Fr::from_str(&temp.to_string()).unwrap()
}

pub fn get_bigint_from_fr(fr: Fp256<FrParameters>) -> BigInt {
    let mut st = fr.to_string();
    let temp = &st[8..8+64];
    BigInt::parse_bytes(temp.as_bytes(), 16).unwrap()
}


pub fn padd_bytes32(input: Vec<u8>) -> Vec<u8> {
    let mut result = input.clone();
    let mut padding = vec![0; 32 - input.len()];
    padding.append(&mut result);
    // result.append(&mut padding);
    padding
}


pub fn padd_bytes3(input: Vec<u8>) -> Vec<u8> {
    let mut result = input.clone();
    let mut padding = vec![0; 3 - input.len()];
    padding.append(&mut result);
    // result.append(&mut padding);
    padding
}