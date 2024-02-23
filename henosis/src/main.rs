use ark_bn254::Fr;
use ethabi::{ParamType, Token};
use ethers::contract::{abigen, Contract};
use ethers::prelude::*;
use ethers::utils::hex;
use num_bigint::*;
use queues::*;
use sha256::digest;
use std::convert::TryFrom;
use std::str::FromStr;
use std::sync::Arc;
pub use henosis::fetcher::fetch_proof_and_pub_signal;
use fflonk_verifier::utils::ProofWithPubSignal;
use std::{thread, time};
use converter::converter;

#[derive(Debug, Clone)]
struct ProofValue {
    proof: Vec<String>,
    pub_signal: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {    

    let POLYGON_ZKEVM_PROXY: Address = "0x5132A183E9F3CB7C848b0AAC5Ae0c4f0491B7aB2"
    .parse()
    .expect("Invalid contract address");

    let provider = Provider::<Ws>::connect(
        "wss://eth-mainnet.ws.alchemyapi.io/v2/nrzrNIfp7oG61YHAmoPAICuibjwqeHmN",
    )
    .await
    .unwrap();

    let http_provider = Provider::<Http>::try_from(
        "https://eth-mainnet.ws.alchemyapi.io/v2/nrzrNIfp7oG61YHAmoPAICuibjwqeHmN",
    )
    .unwrap();
    
    let mut proof_queues: Queue<ProofValue> = queue![];

    let filter = Filter::new().address(vec![POLYGON_ZKEVM_PROXY]);

    let mut logs = provider.subscribe_logs(&filter).await?;

    println!("Henosis Proof Aggregator Listening for Proofs!!");

    while let Some(txn_hash) = logs.next().await.unwrap().transaction_hash {
        println!("Listened Hash: {:?}", txn_hash);

        let tx: Transaction = http_provider.get_transaction(txn_hash).await.unwrap().unwrap();
        // console.log(tx);
        println!("Transaction: {:?}", tx);
        if tx.to.unwrap() == POLYGON_ZKEVM_PROXY {
            let proof = fetch_proof_and_pub_signal(txn_hash).await;
            let _ = proof_queues.add(ProofValue {
                proof: proof.0,
                pub_signal: proof.1,
            });

            if proof_queues.size() == 1 {
                // perform aggregation
                let proof = proof_queues.peek().unwrap();
                let receipt = converter(proof.0, proof.1).await.unwrap();
                println!("Proofs: {:?}", proof_queues);
                let _ = proof_queues.remove();
                let _ = proof_queues.remove();
            }
        } 
    }

    // let sleep_duration = time::Duration::from_secs(1);

    // thread::spawn(move || loop {
    //     println!("Hello from a thread!");
    //     // repeated_function(); // Call the function you want to repeat
    //     thread::sleep(sleep_duration); // Wait for 10 seconds
    // });

    // loop {
    //     thread::sleep(time::Duration::from_secs(60)); // Example: main thread does something else or just waits
    // }

    Ok(())
}
