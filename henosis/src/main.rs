use ark_bn254::Fr;
use converter::converter::{convert_fflonk_to_stark, convert_mplonk_to_stark};
use ethabi::{ParamType, Token};
use ethers::contract::{abigen, Contract};
use ethers::prelude::*;
use ethers::utils::hex;
use fflonk_verifier::utils::ProofWithPubSignal;
use agghost::aggregator::aggregate_stark_receipts;
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

    let polygon_zkevm_proxy: Address = "0x5132A183E9F3CB7C848b0AAC5Ae0c4f0491B7aB2"
        .parse()
        .expect("Invalid contract address");

    let eth_mainnet_rpc = "https://eth-mainnet.ws.alchemyapi.io/v2/nrzrNIfp7oG61YHAmoPAICuibjwqeHmN";
    let eth_mainnet_wss = "wss://eth-mainnet.ws.alchemyapi.io/v2/nrzrNIfp7oG61YHAmoPAICuibjwqeHmN";

    let provider = rt.block_on(async {
        let provider = Provider::<Ws>::connect(
            eth_mainnet_wss,
        )
        .await
        .unwrap();
        provider
    });

    let http_provider = Provider::<Http>::try_from(
        eth_mainnet_rpc,
    )
    .unwrap();

    let mut proof_queues: Queue<ProofValue> = queue![];

    let filter = Filter::new().address(vec![polygon_zkevm_proxy]);

    let mut logs = rt.block_on(async {
        let log = provider.subscribe_logs(&filter).await.unwrap();
        log
    });

    println!("Henosis Proof Aggregator Listening for Proofs!!");

    // uncomment it to start fetching Polygon zkevm proof
    // while let Some(mut txn_hash) = rt.block_on(async {
    //     let hash = logs.next().await.unwrap().transaction_hash;
    //     hash
    // })
    
    loop {
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

        if tx.to.unwrap() == polygon_zkevm_proxy {

            let _proof = rt.block_on(async {
                let proof = fetch_proof_and_pub_signal(txn_hash).await;
                proof
            });

            println!("Proof: {:?}", _proof);
            
            let _ = proof_queues.add(ProofValue {
                proof: _proof.0,
                pub_signal: _proof.1,
            });
            println!("Transaction: {:?}", tx);

            // Performing Aggregation
            if proof_queues.size() == 1 { // since for now we are only fetching 1 proof from polygon zkevm and for zksync we hardcoded for now
                println!("Inside queue !!");
                let proof1 = proof_queues.peek().unwrap();
                let _ = proof_queues.remove();

                println!("Recursively verifying zkevm proof");

                let zkevm_stark_receipt = rt.block_on(async {
                    let receipt = task::spawn_blocking(|| {
                        let receipt = convert_fflonk_to_stark(
                            [proof1.proof],
                            [proof1.pub_signal],
                        );
                        receipt
                    })
                    .await
                    .unwrap();

                    receipt
                });

                // println!("Recursively verifying zksync proof");

                // let zksync_stark_receipt = rt.block_on(async {
                //     let receipt = task::spawn_blocking(|| {
                //         let receipt = convert_mplonk_to_stark();
                //         receipt
                //     })
                //     .await
                //     .unwrap();

                //     receipt
                // });

                // uncomment it for receipt aggregation
                // let final_agg_receipt = aggregate_stark_receipts([zkevm_stark_receipt, zksync_stark_receipt]);
                // println!("Final Aggregated Receipt: {:?}", final_agg_receipt);

            }
        }
    }
}
