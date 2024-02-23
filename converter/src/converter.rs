use ark_ec::{AffineCurve, ProjectiveCurve};
// These constants represent the RISC-V ELF and the image ID generated by risc0-build.
// The ELF is used for proving and the ID is used for verification.
use anyhow::Result;
use ark_bn254::{g1, g1::Parameters, Bn254, FqParameters, Fr, FrParameters, G1Projective};
use ark_ec::short_weierstrass_jacobian::GroupAffine;
use ark_ff::{Field, Fp256, Fp256Parameters, One, PrimeField, UniformRand, Zero};
use bincode;
use ::bonsai_sdk::alpha::responses::SnarkReceipt;
use bonsai_sdk::alpha as bonsai_sdk;
use fflonk_verifier::utils::{G1Point, Proof};
use hex;
use methods::{VERIFIER_ELF, VERIFIER_ID};
use risc0_zkvm::{compute_image_id, serde::to_vec, Receipt, ExecutorEnv, default_prover};
use std::fmt::{Debug, DebugMap, Display};
use std::marker::PhantomData;
use std::ops::{Add, Mul, Neg, Sub};
use std::str::FromStr;
use std::time::{Duration, Instant};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct ProofInput {
    input: [Vec<String>; 2],
    signal: [String; 2]
}


pub fn converter_fflonk_to_groth16(pr_updated: [Vec<String>; 2], signal: [String; 2]) -> SnarkReceipt {
    println!("Converter: {:?}", pr_updated);
    // let pr = vec![
    //     "12195165594784431822497303968938621279445690754376121387655513728730220550454",
    //     "19482351300768228183728567743975524187837254971200066453308487514712354412818",
    //     "270049702185508019342640204324826241417613526941291105097079886683911146886",
    //     "8044577183782099118358991257374623532841698893838076750142877485824795072127",
    //     "18899554350581376849619715242908819289791150067233598694602356239698407061017",
    //     "868483199604273061042760252576862685842931472081080113229115026384087738503",
    //     "15400234196629481957150851143665757067987965100904384175896686561307554593394",
    //     "1972554287366869807517068788787992038621302618305780153544292964897315682091",
    //     "13012702442141574024514112866712813523553321876510290446303561347565844930654",
    //     "6363613431504422665441435540021253583148414748729550612486380209002057984394",
    //     "16057866832337652851142304414708366836077577338023656646690877057031251541947",
    //     "12177497208173170035464583425607209406245985123797536695060336171641250404407",
    //     "1606928575748882874942488864331180511279674792603033713048693169239812670017",
    //     "12502690277925689095499239281542937835831064619179570213662273016815222024218",
    //     "21714950310348017755786780913378098925832975432250486683702036755613488957178",
    //     "7373645520955771058170141217317033724805640797155623483741097103589211150628",
    //     "10624974841759884514517518996672059640247361745924203600968035963539096078745",
    //     "12590031312322329503809710776715067780944838760473156014126576247831324341903",
    //     "17676078410435205056317710999346173532618821076911845052950090109177062725036",
    //     "13810130824095164415807955516712763121131180676617650812233616232528698737619",
    //     "9567903658565551430748252507556148460902008866092926659415720362326593620836",
    //     "17398514793767712415669438995039049448391479578008786242788501594157890722459",
    //     "11804645688707233673914574834599506530652461017683048951953032091830492459803",
    //     "6378827379501409574366452872421073840754012879130221505294134572417254316105",
    // ];

    // let pr_updated = pr.iter().map(|x| x.to_string()).collect::<Vec<String>>();

    let proof_input = ProofInput {
        input: pr_updated,
        signal
    };

    // for running prover locally

    // let env = ExecutorEnv::builder()
    //     .write(&proof_input)
    //     .unwrap()
    //     .build()
    //     .unwrap();

    // // Obtain the default prover.
    // let prover = default_prover();

    // // Produce a receipt by proving the specified ELF binary.
    // let receipt = prover.prove(env, VERIFIER_ELF).unwrap();

    // // TODO: Implement code for retrieving receipt journal here.

    // let _output: bool = receipt.journal.decode().unwrap();

    // println!("Output: {}", _output);

    // // The receipt was verified at the end of proving, but the below code is an
    // // example of how someone else could verify this receipt.
    // receipt.verify(VERIFIER_ID).unwrap();

    // config for using bonsai for proving

    let url = "https://api.bonsai.xyz/".to_string();
    let api_key = "JdRSXY9tV47TkxmQr8Rje9efJT0WWxLG1Q3yMYFc".to_string();
    let client = bonsai_sdk::Client::from_parts(url, api_key, risc0_zkvm::VERSION)
        .expect("Failed to construct sdk client");
    println!("Reached here");

    let image_id = hex::encode(compute_image_id(VERIFIER_ELF).unwrap());
    println!("Image ID done: {}", image_id);
    client.upload_img(&image_id, VERIFIER_ELF.to_vec()).unwrap();

    println!("Image ID: {}", image_id);

    // Prepare input data and upload it.
    let input_data = to_vec(&proof_input).unwrap();
    let input_data = bytemuck::cast_slice(&input_data).to_vec();
    let input_id = client.upload_input(input_data).unwrap();

    // Add a list of assumptions
    let assumptions: Vec<String> = vec![];

    let proving_and_conversion_start_time = Instant::now();
    // Start a session running the prover
    let session = client.create_session(image_id, input_id, assumptions).unwrap();
    loop {
        let res = session.status(&client).unwrap();
        if res.status == "RUNNING" {
            eprintln!(
                "Current status: {} - state: {} - continue polling...",
                res.status,
                res.state.unwrap_or_default()
            );
            std::thread::sleep(Duration::from_secs(15));
            continue;
        }
        if res.status == "SUCCEEDED" {
            // Download the receipt, containing the output
            let receipt_url = res
                .receipt_url
                .expect("API error, missing receipt on completed session");

            let receipt_buf = client.download(&receipt_url).unwrap();
            let receipt: Receipt = bincode::deserialize(&receipt_buf).unwrap();
            receipt
                .verify(VERIFIER_ID)
                .expect("Receipt verification failed");
        } else {
            panic!(
                "Workflow exited: {} - | err: {}",
                res.status,
                res.error_msg.unwrap_or_default()
            );
        }

        break;
    }

    let snark_session = client.create_snark(session.uuid).unwrap();
    eprintln!("Created snark session: {}", snark_session.uuid);

    let mut receipt_resp: SnarkReceipt;
    loop {
        let res = snark_session.status(&client).unwrap();
        match res.status.as_str() {
            "RUNNING" => {
                eprintln!("Current status: {} - continue polling...", res.status,);
                std::thread::sleep(Duration::from_secs(15));
                continue;
            }
            "SUCCEEDED" => {
                let snark_receipt = res.output;
                eprintln!("Snark proof!: {snark_receipt:?}");
                receipt_resp = snark_receipt.unwrap();
                // return snark_receipt?;
                break;
            }
            _ => {
                panic!(
                    "Workflow exited: {} err: {}",
                    res.status,
                    res.error_msg.unwrap_or_default()
                );
            }
        }
    }

    let proving_and_conversion_end_time = Instant::now();
    let elapsed_time = proving_and_conversion_end_time.duration_since(proving_and_conversion_start_time);
    println!(
        "Time Taken {:?}",
        elapsed_time.as_secs_f64()
    );

    receipt_resp
}