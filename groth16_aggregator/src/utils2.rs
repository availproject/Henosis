// EcPoint<F, FqPoint<F>>
use std::{
    fs::{self, File}, io::{BufRead, BufReader}, marker::PhantomData
};

// use super::*;
use halo2_ecc::{
    bn254::{self, pairing::{PairingChip}, Fp12Chip, FpChip, FpPoint, FqPoint}, ecc::EcPoint, fields::FieldChip, halo2_base};
use halo2_ecc::{
    // fields::FpStrategy
    fields::FpStrategy, 
    // halo2_proofs::halo2curves::bn256::G2Affine
};

use ark_ff::{MontFp, QuadExtConfig, Fp};


use halo2_base::{
    gates::{
        circuit::{
            builder::{
                self, BaseCircuitBuilder, RangeCircuitBuilder
            }, 
            CircuitBuilderStage
        }, 
        RangeChip
    }, 
    utils::{
        BigPrimeField, testing::gen_proof
    }, 
    Context, halo2_proofs::{
        dev::{
            metadata::Column, MockProver
        }, halo2curves::{
            bn256::{
                pairing, Fq2, G1Affine, G2Affine
            }, grumpkin::{Fq, Fr}
        }, plonk::{
            Selector, Advice
        }, poly::commitment::Prover
    },
    halo2_proofs::halo2curves::bn256::{self}
};

use halo2curves::{ff::PrimeField, CurveAffine};
// use halo2curves::bn256::Fr;
// use halo2curves::bn256::pairing;
use rand::rngs::StdRng;
use rand_core::{Error, SeedableRng};
use serde::{Deserialize, Serialize};



pub struct VerificationKey {
    pub alpha1: G1Affine,
    pub beta2: G2Affine,
    pub gamma2: G2Affine,
    pub delta2: G2Affine,
    pub ic: Vec<G1Affine>,

}



pub struct Proof {
    pub a: G1Affine,
    pub b: G2Affine,
    pub c: G1Affine,
    pub public_inputs: Vec<String>
}


pub fn get_dummy_proof2() -> Proof {
    // [13260276032418998651443538824193049589123114956926792946594134764022000816562, 5167640230539274142304274045727640058373784936329623387968009881859270794902]
    // [[10567087324407133650922565101452207841667968057317044436605321405883373098510, 7757803224683569033741736680656787451157316953083975465016761210409447042085], [457572965494851714920701078104055244867150196245707373658530988008746205753, 4154698842299342687716733663963774183350245344082643024876568733757548954572]]
    // [912029144283342253430074020875773320940610572316000372447554232903960396096, 18905415622575708886101027892832048186612990562549466021443631829394831237150]
    // [91039097843120449453449593822342807849, 24946934259622365010039737625873252857, 112589930430490045473610947510778658730, 251605118307091288206921779862202882788]
    Proof {
        a: G1Affine{
            x: bn256::Fq::from_str_vartime("13260276032418998651443538824193049589123114956926792946594134764022000816562").unwrap(),
            y: bn256::Fq::from_str_vartime("5167640230539274142304274045727640058373784936329623387968009881859270794902").unwrap()
        }, 
        b: G2Affine{
            x: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("7757803224683569033741736680656787451157316953083975465016761210409447042085").unwrap(),
                bn256::Fq::from_str_vartime("10567087324407133650922565101452207841667968057317044436605321405883373098510").unwrap()
            ), 
            y: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("4154698842299342687716733663963774183350245344082643024876568733757548954572").unwrap(),
                bn256::Fq::from_str_vartime("457572965494851714920701078104055244867150196245707373658530988008746205753").unwrap()
            )
        },
        c: G1Affine{
            x: bn256::Fq::from_str_vartime("912029144283342253430074020875773320940610572316000372447554232903960396096").unwrap(),
            y: bn256::Fq::from_str_vartime("18905415622575708886101027892832048186612990562549466021443631829394831237150").unwrap()
        },
        public_inputs: [String::from("91039097843120449453449593822342807849"), String::from("24946934259622365010039737625873252857"), String::from("112589930430490045473610947510778658730"), String::from("251605118307091288206921779862202882788")].to_vec()

    }
}



pub fn get_verification_key2() -> VerificationKey {
    VerificationKey {

        alpha1: G1Affine{
            x: bn256::Fq::from_str_vartime("20491192805390485299153009773594534940189261866228447918068658471970481763042").unwrap(),
            y: bn256::Fq::from_str_vartime("9383485363053290200918347156157836566562967994039712273449902621266178545958").unwrap()
        },
        beta2: G2Affine{
            x: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("6375614351688725206403948262868962793625744043794305715222011528459656738731").unwrap(),

                bn256::Fq::from_str_vartime("4252822878758300859123897981450591353533073413197771768651442665752259397132").unwrap(),
            ), 
            y: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("10505242626370262277552901082094356697409835680220590971873171140371331206856").unwrap(),

                bn256::Fq::from_str_vartime("21847035105528745403288232691147584728191162732299865338377159692350059136679").unwrap(),
            )
        },
        gamma2: G2Affine{
            x: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("10857046999023057135944570762232829481370756359578518086990519993285655852781").unwrap(),

                bn256::Fq::from_str_vartime("11559732032986387107991004021392285783925812861821192530917403151452391805634").unwrap(),
            ), 
            y: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("8495653923123431417604973247489272438418190587263600148770280649306958101930").unwrap(),

                bn256::Fq::from_str_vartime("4082367875863433681332203403145435568316851327593401208105741076214120093531").unwrap(),
            )
        },
        delta2: G2Affine{
            x: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("9492326610711013918333865133991413442330971822743127449106067493230447878125").unwrap(),

                bn256::Fq::from_str_vartime("18518940221910320856687047018635785128750837022059566906616608708313475199865").unwrap(),
            ), 
            y: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("21375251776817431660251933179512026180139877181625068362970095925425149918084").unwrap(),

                bn256::Fq::from_str_vartime("19483644759748826533215810634368877792922012485854314246298395665859158607201").unwrap(),
            )
        },
        ic: vec![
            G1Affine{
                x: bn256::Fq::from_str_vartime("5283414572476013565779278723585415063371186194506872223482170607932178811733").unwrap(),
                y: bn256::Fq::from_str_vartime("18704069070102836155408936676819275373965966640372164023392964533091458933020").unwrap()
            },
            G1Affine{
                x: bn256::Fq::from_str_vartime("4204832149120840018317309580010992142700029278901617154852760187580780425598").unwrap(),
                y: bn256::Fq::from_str_vartime("12454324579480242399557363837918019584959512625719173397955145140913291575910").unwrap()
            },
            G1Affine{
                x: bn256::Fq::from_str_vartime("14956117485756386823219519866025248834283088288522682527835557402788427995664").unwrap(),
                y: bn256::Fq::from_str_vartime("6968527870554016879785099818512699922114301060378071349626144898778340839382").unwrap()
            },
            G1Affine{
                x: bn256::Fq::from_str_vartime("6512168907754184210144919576616764035747139382744482291187821746087116094329").unwrap(),
                y: bn256::Fq::from_str_vartime("17156131719875889332084290091263207055049222677188492681713268727972722760739").unwrap()
            },
            G1Affine{
                x: bn256::Fq::from_str_vartime("5195346330747727606774560791771406703229046454464300598774280139349802276261").unwrap(),
                y: bn256::Fq::from_str_vartime("16279160127031959334335024858510026085227931356896384961436876214395869945425").unwrap()
            }
        ],
    }
}



#[test]

fn test_proof() {
    println!("{:?}", get_dummy_proof2().a.is_on_curve());
    println!("{:?}", get_dummy_proof2().b.is_on_curve());
    println!("{:?}", get_dummy_proof2().c.is_on_curve());
}

#[test]
fn test_verification_key() {
    println!("{:?}", get_verification_key2().alpha1.is_on_curve());
    println!("{:?}", get_verification_key2().beta2.is_on_curve());
    println!("{:?}", get_verification_key2().gamma2.is_on_curve());
    println!("{:?}", get_verification_key2().delta2.is_on_curve());
    println!("{:?}", get_verification_key2().ic[0].is_on_curve());
    println!("{:?}", get_verification_key2().ic[1].is_on_curve());
}

