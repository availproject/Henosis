use std::{
    fs::{self, File},
    io::{BufRead, BufReader},
    marker::PhantomData,
    ops::{Add, Mul, Neg},
};

use ark_ff::{fp, fp2, BigInt, BigInteger, Fp256};
// use super::*;
use halo2_ecc::{
    bigint::{self, big_is_zero::crt, check_carry_mod_to_zero, ProperCrtUint},
    bn254::{self, pairing::PairingChip, Fp12Chip, Fp2Chip, FpChip, FpPoint},
    ecc::{self, ec_add_unequal, ec_double, scalar_multiply, EcPoint, EccChip},
    fields::FieldChip,
    halo2_base,
};
use halo2_ecc::{
    // fields::FpStrategy
    fields::FpStrategy,
    // halo2_proofs::halo2curves::bn256::G2Affine
};

use std::time::{Duration, Instant};

use halo2_base::{
    gates::{
        circuit::{
            builder::{self, BaseCircuitBuilder, RangeCircuitBuilder},
            CircuitBuilderStage,
        },
        RangeChip,
    },
    halo2_proofs::halo2curves::bn256::{self, Fr},
    halo2_proofs::{
        dev::{metadata::Column, MockProver},
        halo2curves::bn256::{pairing, G1Affine, G2Affine, G1},
        plonk::{Advice, Selector},
        poly::commitment::Prover,
    },
    utils::{testing::gen_proof, BigPrimeField, CurveAffineExt, ScalarField},
    Context,
};

use halo2curves::{
    ff::{BitViewSized, PrimeField},
    group::Curve,
    CurveAffine,
};
use num_bigint::U64Digits;
// use halo2curves::bn256::Fr;
// use halo2curves::bn256::pairing;
use rand::rngs::StdRng;
use rand_core::{Error, SeedableRng};
use serde::{Deserialize, Serialize};

mod utils;
mod utils2;

use utils::*;
use utils2::*;

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
struct PairingCircuitParams {
    strategy: FpStrategy,
    degree: u32,
    num_advice: usize,
    num_lookup_advice: usize,
    num_fixed: usize,
    lookup_bits: usize,
    limb_bits: usize,
    num_limbs: usize,
}

#[derive(Clone, Debug)]
pub struct TestCircuit<F: BigPrimeField> {
    _f: PhantomData<F>,
}

impl<F: BigPrimeField> TestCircuit<F> {
    pub fn new() -> Self {
        Self { _f: PhantomData }
    }

    pub fn synthesize(
        builder: &mut BaseCircuitBuilder<F>,
        fp_chip: &FpChip<F>,
    ) -> Result<(), Error> {
        let ctx = builder.main(0);
        let pairing_chip = PairingChip::new(fp_chip);
        // let verif_key = get_verification_key();
        let verif_key = get_verification_key2();
        let alpha1_assigned = pairing_chip.load_private_g1_unchecked(ctx, verif_key.alpha1);
        let beta2_assigned = pairing_chip.load_private_g2_unchecked(ctx, verif_key.beta2);
        let gamma2_assigned = pairing_chip.load_private_g2_unchecked(ctx, verif_key.gamma2);
        let delta2_assigned = pairing_chip.load_private_g2_unchecked(ctx, verif_key.delta2);
        let ic_assigned = verif_key
            .ic
            .iter()
            .map(|ic| pairing_chip.load_private_g1_unchecked(ctx, *ic))
            .collect::<Vec<_>>();

        // println!("ic_assigned: {:?}", ic_assigned);

        // // let dummy_proof = get_dummy_proof();
        let dummy_proof = get_dummy_proof2();

        //declare our chips for performing the ecc operations
        let fp2_chip = Fp2Chip::<F>::new(fp_chip);
        let g2_chip = EccChip::new(&fp2_chip);

        //extract the points of proof and public inputs
        let a_neg = dummy_proof.a.neg();
        let neg_a_assigned = pairing_chip.load_private_g1_unchecked(ctx, a_neg);
        let b_assigned = pairing_chip.load_private_g2_unchecked(ctx, dummy_proof.b);
        let c_assigned = pairing_chip.load_private_g1_unchecked(ctx, dummy_proof.c);
        let public_inputs = dummy_proof.public_inputs;

        // Implement vk_x = vk.ic[0];
        let mut vk_x_assigned = &ic_assigned[0].clone();
        let mut temp;
        for i in 0..public_inputs.len() {
            //second different approach
            let public_value =
                fp_chip.load_constant(ctx, bn256::Fq::from_str_vartime(&public_inputs[i]).unwrap());
            let base_chip = g2_chip.field_chip;
            let vk_x_i_plus_1 = ic_assigned[i + 1].clone();

            let vk_x_mul_input = scalar_multiply::<F, _, G1Affine>(
                base_chip.fp_chip(),
                ctx,
                vk_x_i_plus_1.clone(),
                public_value.limbs().to_vec(),
                g2_chip.field_chip.fp_chip().limb_bits,
                4,
            );

            temp = ec_add_unequal(
                base_chip.fp_chip(),
                ctx,
                vk_x_mul_input.clone(),
                vk_x_assigned.clone(),
                true,
            );

            vk_x_assigned = &temp;
        }

        let p1 = pairing_chip.pairing(ctx, &b_assigned, &neg_a_assigned);
        let p2 = pairing_chip.pairing(ctx, &beta2_assigned, &alpha1_assigned);
        let p3 = pairing_chip.pairing(ctx, &gamma2_assigned, &vk_x_assigned);
        let p4 = pairing_chip.pairing(ctx, &delta2_assigned, &c_assigned);

        let fp12_chip = Fp12Chip::<F>::new(fp_chip);

        let p1_p2 = fp12_chip.mul(ctx, &p1, &p2);

        let p3_p4 = fp12_chip.mul(ctx, &p3, &p4);

        let p1_p2_p3_p4 = fp12_chip.mul(ctx, &p1_p2, &p3_p4);

        println!(
            "p1_p2_p3_p4 {:?}",
            fp12_chip.get_assigned_value(&p1_p2_p3_p4.into())
        );

        let p12 = pairing_chip.pairing(ctx, &b_assigned, &neg_a_assigned);
        let p22 = pairing_chip.pairing(ctx, &beta2_assigned, &alpha1_assigned);
        let p32 = pairing_chip.pairing(ctx, &gamma2_assigned, &vk_x_assigned);
        let p42 = pairing_chip.pairing(ctx, &delta2_assigned, &c_assigned);

        let fp12_chip2 = Fp12Chip::<F>::new(fp_chip);

        let p1_p22 = fp12_chip.mul(ctx, &p12, &p22);

        let p3_p42 = fp12_chip.mul(ctx, &p32, &p42);

        let p1_p2_p3_p42 = fp12_chip.mul(ctx, &p1_p22, &p3_p42);
        Ok(())
    }
}

pub trait AppCircuit<F: BigPrimeField> {
    fn create_circuit(
        stage: CircuitBuilderStage,
        params: PairingCircuitParams,
        P: G1Affine,
        Q: G2Affine,
    ) -> Result<BaseCircuitBuilder<F>, Error>;
}

impl<F: BigPrimeField> AppCircuit<F> for TestCircuit<F> {
    fn create_circuit(
        stage: CircuitBuilderStage,
        params: PairingCircuitParams,
        P: G1Affine,
        Q: G2Affine,
    ) -> Result<BaseCircuitBuilder<F>, Error> {
        let k = params.degree as usize;

        let mut builder = BaseCircuitBuilder::<F>::from_stage(stage).use_k(params.degree as usize);
        // builder.use_k(params.degree as usize);
        // builder.set_lookup_bits(params.lookup_bits);
        // MockProver::run(9, &builder, vec![]).unwrap().assert_satisfied();
        // if let Some(lb) = params.lookup_bits {
        // builder.set_lookup_bits(params.lookup_bits);
        // }
        let range = RangeChip::new(params.lookup_bits, builder.lookup_manager().clone());

        let ctx = builder.main(0);
        // // run the function, mutating `builder`

        let fp_chip = FpChip::new(&range, params.limb_bits, params.num_limbs);
        let res1 = Self::synthesize(&mut builder, &fp_chip);
        // let res = pairing_test(ctx, &range, params, P, Q);

        // // helper check: if your function didn't use lookups, turn lookup table "off"
        let t_cells_lookup = builder
            .lookup_manager()
            .iter()
            .map(|lm| lm.total_rows())
            .sum::<usize>();
        let lookup_bits = if t_cells_lookup == 0 {
            None
        } else {
            std::option::Option::Some(params.lookup_bits)
        };
        builder.set_lookup_bits(params.lookup_bits);

        // // // configure the circuit shape, 9 blinding rows seems enough
        builder.calculate_params(Some(9));

        Ok((builder))
    }
}

#[test]
fn test_pairing_circuit() {
    // let a  = vec![
    //     29, 81, 12, 222, 49, 79, 63, 66, 226, 208, 219, 255, 73, 50, 241, 196, 116,
    //     140, 85, 176, 155, 85, 9, 6, 32, 28, 107, 25, 85, 36, 145, 178
    // ];

    // BigInt::from_bits_be(a);

    // let concatenated_string: String = a.iter().map(|&x| x.to_string()).collect();

    // let b = concatenated_string.as_bytes();

    // Parse the concatenated string into a BigInt
    // let big_int_value = BigInt::from_bits_le(concatenated_string.as_bytes()).unwrap();

    // println!("BigInt value: {}", big_int_value);

    // let path = "/Users/rishabh/projects/blockchain/avail-project/halo2-aggregation/src/configs/bn254/pairing_circuit.config";
    let params: PairingCircuitParams = PairingCircuitParams {
        strategy: FpStrategy::Simple,
        degree: 19,
        num_advice: 6,
        num_lookup_advice: 1,
        num_fixed: 1,
        lookup_bits: 18,
        limb_bits: 90,
        num_limbs: 3,
    };

    let mut rng = StdRng::seed_from_u64(0);
    let P = G1Affine::random(&mut rng);
    let Q = G2Affine::random(&mut rng);
    let circuit =
        TestCircuit::<Fr>::create_circuit(CircuitBuilderStage::Mock, params, P, Q).unwrap();

    let start_time = Instant::now();
    MockProver::run(params.degree, &circuit, vec![])
        .unwrap()
        .assert_satisfied();
    let end_time = Instant::now();
    let elapsed_time = end_time.duration_since(start_time);

    println!("Elapsed time in proof generation: {:?}", elapsed_time);
    // let prover = MockProver::<Fr>::run(9, &circuit, vec![]).unwrap();
}

fn main() {
    println!("Hello, world!");
}
