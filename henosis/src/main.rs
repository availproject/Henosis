use ark_bn254::Fr;
use converter::converter::converter_fflonk_to_groth16;
use ethabi::{ParamType, Token};
use ethers::contract::{abigen, Contract};
use ethers::prelude::*;
use ethers::utils::hex;
use fflonk_verifier::utils::ProofWithPubSignal;
use groth16_aggregator::verifier::run;
pub use henosis::fetcher::{fetch_proof_and_pub_signal, ProofValue};
use num_bigint::*;
use queues::*;
use sha256::digest;
use std::convert::{self, TryFrom};
use std::str::FromStr;
use std::sync::Arc;
use std::{thread::sleep, time};
use tokio;
use tokio::runtime::Runtime;
use tokio::task;

// #[tokio::main]
fn main() {
    let rt = Runtime::new().unwrap();

    let POLYGON_ZKEVM_PROXY: Address = "0x5132A183E9F3CB7C848b0AAC5Ae0c4f0491B7aB2"
        .parse()
        .expect("Invalid contract address");

    let provider = rt.block_on(async {
        let provider = Provider::<Ws>::connect(
            "wss://eth-mainnet.ws.alchemyapi.io/v2/nrzrNIfp7oG61YHAmoPAICuibjwqeHmN",
        )
        .await
        .unwrap();
        provider
    });

    let http_provider = Provider::<Http>::try_from(
        "https://eth-mainnet.ws.alchemyapi.io/v2/nrzrNIfp7oG61YHAmoPAICuibjwqeHmN",
    )
    .unwrap();

    let mut proof_queues: Queue<ProofValue> = queue![];

    let filter = Filter::new().address(vec![POLYGON_ZKEVM_PROXY]);

    let mut logs = rt.block_on(async {
        let log = provider.subscribe_logs(&filter).await.unwrap();
        log
    });

    println!("Henosis Proof Aggregator Listening for Proofs!!");

    // while let Some(mut txn_hash) = rt.block_on(async {
    //     let hash = logs.next().await.unwrap().transaction_hash;
    //     hash
    // }) {
        // println!("Transaction Hash: {:?}", txn_hash);
        let sample_hash =
            H256::from_str("0xed0c28abb022be570305ae3cd454c5c3bb027ede55cfdefe6744bc1b5af90d8a")
                .unwrap();
        let txn_hash = sample_hash;
        // let get_txn_handle = tokio::spawn(http_provider.clone().get_transaction(sample_hash));

        // let tx: Transaction = get_txn_handle.await.unwrap().unwrap().unwrap();
        let tx: Transaction = rt.block_on(async {
            let tx: Transaction = http_provider
                .get_transaction(txn_hash)
                .await
                .unwrap()
                .unwrap();
            tx
        });

        // console.log(tx);
        if tx.to.unwrap() == POLYGON_ZKEVM_PROXY {
            // let _fetch_handle = tokio::spawn(fetch_proof_and_pub_signal(sample_hash));

            // let _proof = _fetch_handle.await.unwrap();

            let _proof = rt.block_on(async {
                let proof = fetch_proof_and_pub_signal(txn_hash).await;
                proof
            });

            // let _proof = fetch_proof_and_pub_signal(sample_hash).await;
            println!("Proof: {:?}", _proof);
            let _ = proof_queues.add(ProofValue {
                proof: _proof.0,
                pub_signal: _proof.1,
            });
            println!("Transaction: {:?}", tx);

            if proof_queues.size() == 1 {
                // perform aggregation
                println!("Inside queue !!");
                let proof = proof_queues.peek().unwrap();
                println!("Proof sinside quque !!: {:?}", proof);

                let receipt = rt.block_on(async {
                    let receipt = task::spawn_blocking(|| {
                        let receipt = converter_fflonk_to_groth16(
                            [proof.clone().proof, proof.clone().proof],
                            [proof.clone().pub_signal, proof.pub_signal],
                        );
                        // println!("Receipt: {:?}", receipt);
                        receipt
                    })
                    .await
                    .unwrap();

                    receipt
                });

                println!("Receipt: {:?}", receipt);
                // let receipt =
                let a = receipt.snark.a;
                let b = receipt.snark.b;
                let c = receipt.snark.c;
                let public = receipt.snark.public;

                let a_0_bigint = U256::from_big_endian(&a[0]);
                let a_1_bigint = U256::from_big_endian(&a[1]);
                let b_0_0_bigint = U256::from_big_endian(&b[0][0]);
                let b_0_1_bigint = U256::from_big_endian(&b[0][1]);
                let b_1_0_bigint = U256::from_big_endian(&b[1][0]);
                let b_1_1_bigint = U256::from_big_endian(&b[1][1]);
                let c_0_bigint = U256::from_big_endian(&c[0]);
                let c_1_bigint = U256::from_big_endian(&c[1]);
                let public_0_bigint = U256::from_big_endian(&public[0]);
                let public_1_bigint = U256::from_big_endian(&public[1]);
                let public_2_bigint = U256::from_big_endian(&public[2]);
                let public_3_bigint = U256::from_big_endian(&public[3]);

                let a_0_bigint_string = a_0_bigint.to_string();
                let a_1_bigint_string = a_1_bigint.to_string();
                let b_0_0_bigint_string = b_0_0_bigint.to_string();
                let b_0_1_bigint_string = b_0_1_bigint.to_string();
                let b_1_0_bigint_string = b_1_0_bigint.to_string();
                let b_1_1_bigint_string = b_1_1_bigint.to_string();
                let c_0_bigint_string = c_0_bigint.to_string();
                let c_1_bigint_string = c_1_bigint.to_string();
                let public_0_bigint_string = public_0_bigint.to_string();
                let public_1_bigint_string = public_1_bigint.to_string();
                let public_2_bigint_string = public_2_bigint.to_string();
                let public_3_bigint_string = public_3_bigint.to_string();

                let _ = run(
                    a_0_bigint_string,
                    a_1_bigint_string,
                    b_0_0_bigint_string,
                    b_0_1_bigint_string,
                    b_1_0_bigint_string,
                    b_1_1_bigint_string,
                    c_0_bigint_string,
                    c_1_bigint_string,
                    public_0_bigint_string,
                    public_1_bigint_string,
                    public_2_bigint_string,
                    public_3_bigint_string,
                );

                // println!("a 0 {:?}", a_0_bigint);
                println!("Aggregated proof");

                println!("Proofs: {:?}", proof_queues);
                let _ = proof_queues.remove();
                // let _ = proof_queues.remove();
            }
        }
    // }
}
