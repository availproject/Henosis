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
    pub public_inputs: Vec<u64>
}


pub fn get_dummy_proof() -> Proof {
    Proof {
        a: G1Affine{
            x: bn256::Fq::from_str_vartime("12887163950774589848429612384269252267879103641214292968732875014481055665029").unwrap(),
            y: bn256::Fq::from_str_vartime("21622722808554299809135926587843590844306004439941801858752721909447067565676").unwrap()
        }, 
        b: G2Affine{
            x: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("19252399014017622041717411504172796635144662505041726695471440307521907621323").unwrap(),
                bn256::Fq::from_str_vartime("11302764088468560462334032644947221757922107890363805071604206102241252698616").unwrap()
            ), 
            y: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("226455389767104611295930017850538586277567900474601688185243021343711813551").unwrap(),
                bn256::Fq::from_str_vartime("18768786825809469978354139019891648686066930676359588724933329715343055477839").unwrap()
            )
        },
        c: G1Affine{
            x: bn256::Fq::from_str_vartime("16716067220884575876883941674457042090348240918922797664931133638121340220774").unwrap(),
            y: bn256::Fq::from_str_vartime("19465170897811434280250972276398658394224541760713812318242639282725837098749").unwrap()
        },
        public_inputs: vec![20]
    }
}



pub fn get_verification_key() -> VerificationKey {
    VerificationKey {

        alpha1: G1Affine{
            x: bn256::Fq::from_str_vartime("6763126530687886999315782887200758703366235230289874831627658839515656330867").unwrap(),
            y: bn256::Fq::from_str_vartime("12297948670392550312636836114470404429657568989657927437959695771502446445179").unwrap()
        },
        beta2: G2Affine{
            x: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("15362786867599176251482538547160991918100063526460909721657878971551583339657").unwrap(),
                bn256::Fq::from_str_vartime("3804423004921008809819632629079723167970572551072432396497601916259815496626").unwrap()
            ), 
            y: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("21885719103633717693283841528133243510750001708857084897139570082577218850374").unwrap(),
                bn256::Fq::from_str_vartime("2076817281717432063622727433912740683541778328445173073030513609350245776784").unwrap()
            )
        },
        gamma2: G2Affine{
            x: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("1505558511994093266228972967760414664043255115544025409518939393775943607863").unwrap(),
                bn256::Fq::from_str_vartime("21131173266568468249589649137903719095480044620502529067534622738225157042304").unwrap()
            ), 
            y: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("4008759115482693545406793535591568078300615151288108694080317738431649117177").unwrap(),
                bn256::Fq::from_str_vartime("18835856718271757625037377080288624550370480296914695806777038708085497610013").unwrap()
            )
        },
        delta2: G2Affine{
            x: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("1497911744463986566314308077983046202449361313910668647770797503379177516252").unwrap(),
                bn256::Fq::from_str_vartime("10829154948357654897792444316512827659620136273388886760324770466776134105520").unwrap()
            ), 
            y: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("10850392992008761830625471778404650447428083833210258292805429019728339148884").unwrap(),
                bn256::Fq::from_str_vartime("12593805385728178657844996215584371401133999503150901444097670307277076679963").unwrap()
            )
        },
        ic: vec![
            G1Affine{
                x: bn256::Fq::from_str_vartime("20417302999686518463947604254824206482787540497747166602791183033521164889663").unwrap(),
                y: bn256::Fq::from_str_vartime("13070739245581256634078674103787887995405997871287223137308760941168103411852").unwrap()
            },
            G1Affine{
                x: bn256::Fq::from_str_vartime("7134628694475811382742267026042639323743922548568185680200196927023443639137").unwrap(),
                y: bn256::Fq::from_str_vartime("9624761392337090719715532152667200620426657721236517270124636244477804835035").unwrap()
            }
        ],
    }
}


pub fn get_r0_proof() -> Proof {
    Proof {
        a: G1Affine{
            x: bn256::Fq::from_str_vartime("13260276032418998651443538824193049589123114956926792946594134764022000816562").unwrap(),
            y: bn256::Fq::from_str_vartime("5167640230539274142304274045727640058373784936329623387968009881859270794902").unwrap()
        }, 
        b: G2Affine{
            x: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("7757803224683569033741736680656787451157316953083975465016761210409447042085").unwrap(),

                bn256::Fq::from_str_vartime("10567087324407133650922565101452207841667968057317044436605321405883373098510").unwrap(),
            ), 
            y: bn256::Fq2::new(
                bn256::Fq::from_str_vartime("4154698842299342687716733663963774183350245344082643024876568733757548954572").unwrap(),

                bn256::Fq::from_str_vartime("457572965494851714920701078104055244867150196245707373658530988008746205753").unwrap(),
            )
        },
        c: G1Affine{
            x: bn256::Fq::from_str_vartime("912029144283342253430074020875773320940610572316000372447554232903960396096").unwrap(),
            y: bn256::Fq::from_str_vartime("18905415622575708886101027892832048186612990562549466021443631829394831237150").unwrap()
        },
        public_inputs: vec![20]
    }
}


#[test]

fn test_proof() {
    println!("{:?}", get_dummy_proof().a.is_on_curve());
    println!("{:?}", get_dummy_proof().b.is_on_curve());
    println!("{:?}", get_dummy_proof().c.is_on_curve());
}

#[test]
fn test_verification_key() {
    println!("{:?}", get_verification_key().alpha1.is_on_curve());
    println!("{:?}", get_verification_key().beta2.is_on_curve());
    println!("{:?}", get_verification_key().gamma2.is_on_curve());
    println!("{:?}", get_verification_key().delta2.is_on_curve());
    println!("{:?}", get_verification_key().ic[0].is_on_curve());
    println!("{:?}", get_verification_key().ic[1].is_on_curve());
}

#[test]
fn test_r0_proof() {
    println!("{:?}", get_r0_proof().a.is_on_curve());
    println!("{:?}", get_r0_proof().b.is_on_curve());
    println!("{:?}", get_r0_proof().c.is_on_curve());
}