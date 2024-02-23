use ark_bn254::Fr;
use ethabi::{ParamType, Token};
use ethers::contract::{abigen, Contract};
use ethers::prelude::*;
use ethers::utils::hex;
use num_bigint::*;
use queues::*;
use sha256::digest;
use std::convert::TryFrom;
use std::fmt::format;
use std::io::Read;
use std::str::FromStr;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let provider = Provider::<Ws>::connect(
        "wss://eth-mainnet.ws.alchemyapi.io/v2/nrzrNIfp7oG61YHAmoPAICuibjwqeHmN",
    )
    .await
    .unwrap();

    let http_provider = Provider::<Http>::try_from(
        "https://eth-mainnet.ws.alchemyapi.io/v2/nrzrNIfp7oG61YHAmoPAICuibjwqeHmN",
    )
    .unwrap();

    abigen!(
        PolygonZkevmRollupManagerContract,
        r#"[
            {
                "type": "function",
                "name": "getInputSnarkBytes",
                "inputs": [
                    {
                        "name": "rollupID",
                        "type": "uint32"
                    },
                    {
                        "name": "initNumBatch",
                        "type": "uint64"
                    },
                    {
                        "name": "finalNewBatch",
                        "type": "uint64"
                    },
                    {
                        "name": "newLocalExitRoot",
                        "type": "bytes32"
                    },
                    {
                        "name": "oldStateRoot",
                        "type": "bytes32"
                    },
                    {
                        "name": "newStateRoot",
                        "type": "bytes32"
                    }
                ],
                "outputs": [
                    {
                        "name": "",
                        "type": "bytes"
                    }
                ]
            },
            {
                "type": "function",
                "name": "getRollupBatchNumToStateRoot",
                "inputs": [
                    {
                        "name": "rollupID",
                        "type": "uint32"
                    },
                    {
                        "name": "batchNum",
                        "type": "uint64"
                    }
                ],
                "outputs": [
                    {
                        "name": "",
                        "type": "bytes32"
                    }
                ]
            }
        ]"#,
    );

    let POLYGON_ZKEVM_PROXY: Address = "0x5132A183E9F3CB7C848b0AAC5Ae0c4f0491B7aB2"
        .parse()
        .expect("Invalid contract address");

    let POLYGON_ROLLUP_MANAGER: Address = "0x3b82Da772c825283d85d5d6717A77C6Ff582053b"
        .parse()
        .expect("Invalid contract address");

    let contract = PolygonZkevmRollupManagerContract::new(
        POLYGON_ZKEVM_PROXY,
        Arc::new(http_provider.clone()),
    );

    let filter = Filter::new().address(vec![POLYGON_ZKEVM_PROXY]);

    let mut logs = provider.subscribe_logs(&filter).await?;

    println!("Listening for the proofs...");

    let temp_log = "0x189fa096b7f006f7034bc0ceed63d3fe02c4324a9800e076d847e67ca72fee1b";
    let tx_hash = H256::from_str(temp_log)?;

    let tx: Transaction = http_provider
        .get_transaction(tx_hash)
        .await
        .unwrap()
        .unwrap();
    // console.log(tx);
    println!("Transaction to : {:?}", tx.to);
    println!("Transaction data: {:?}", tx.input);

    // let _bytes = tx.input.to_string(); // convert this into u8 array
    // println!("Transaction data: {:?}", _bytes);

    let mut txn_call_data = tx.input.to_string();
    // slice first 9 element of txn_call_data string
    txn_call_data = txn_call_data[10..].to_string(); // slice method id
                                                     // let txn_byte = hex::decode(txn_call_data).unwrap();

    let chunks: Vec<String> = txn_call_data
        .as_bytes()
        .chunks(64)
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect();

    // Display the resulting array of strings
    for chunk in chunks.iter() {
        println!("{}", chunk);
    }

    let rollup_id = chunks[0].parse::<u32>().unwrap();
    let pending_state_num = chunks[1].parse::<u64>().unwrap();
    let init_num_batch = u64::from_str_radix(&chunks[2].trim_start_matches('0'), 16).unwrap();
    let final_new_batch = u64::from_str_radix(&chunks[3].trim_start_matches('0'), 16).unwrap();

    // let new_local_exit_root = H256::from_str(&chunks[4]).unwrap();
    // let new_state_root = H256::from_str(&chunks[6]).unwrap();
    // let beneficiary = H160::from_str(&chunks[6]).unwrap();
    let mut beneficiary = chunks[6].to_string();
    beneficiary = beneficiary[24..].to_string();
    // println!("bene ID: {:?}", beneficiary);
    // let beneficiary = chunks[7]

    println!("Rollup ID: {:?}", rollup_id);
    println!("Pending State Num: {:?}", pending_state_num);
    println!("Init Num Batch: {:?}", init_num_batch);
    println!("Final New Batch: {:?}", final_new_batch);
    // println!("New Local Exit Root: {:?}", new_local_exit_root);
    // println!("New State Root: {:?}", new_state_root);
    // println!("Beneficiary: {:?}", beneficiary);

    let resp_old_state_root = contract
        .get_rollup_batch_num_to_state_root(rollup_id, init_num_batch)
        .await
        .unwrap();
    // println!("Response: {:?}", resp);
    // convert u8 to string
    let mut old_state_root = hex::encode(&resp_old_state_root);
    println!("State Root: {:?}", old_state_root);

    //add "0x"
    old_state_root = format!("0x{}", old_state_root).to_string();

    // rest are proof chunks

    let new_local_exist_root = hex::decode(chunks[4].clone()).unwrap();
    let new_state_root = hex::decode(chunks[5].clone()).unwrap();
    // println!("New Local Exist Root: {:?}", new_local_exist_root);

    let nle: [u8; 32] = new_local_exist_root.try_into().unwrap();
    let nsr: [u8; 32] = new_state_root.try_into().unwrap();

    let snark_hash_bytes: Bytes = contract
        .get_input_snark_bytes(
            rollup_id,
            init_num_batch,
            final_new_batch,
            nle,
            resp_old_state_root,
            nsr,
        )
        .await
        .unwrap();

    // getting the pub signal
    println!("Pub Signal: {:?}", snark_hash_bytes);

    let mut snark_hash_string = snark_hash_bytes.to_string();
    snark_hash_string = snark_hash_string[42..].to_string();

    // concat hash string with beneficairy string
    snark_hash_string = format!("{}{}", beneficiary, snark_hash_string);
    // snark_hash_string = format!("{}{}", "0x", snark_hash_string);

    println!("Snark Hash String: {:?}", snark_hash_string);

    let val = digest(hex::decode(snark_hash_string).unwrap());
    println!("Sha256: {:?}", val);

    let u256_value = U256::from_str(val.as_str()).expect("Invalid hex value");
    println!("U256 value: {}", u256_value);

    let str_u256 = u256_value.to_string();
    let signal = Fr::from_str(str_u256.as_str()).unwrap();

    // 6459263671091144893360818939496021755924342661647071879304955224473619266150

    println!("Signal: {:?}", signal.to_string());

    let mut proof_queues: Queue<isize> = queue![];

    while let Some(log) = logs.next().await.unwrap().transaction_hash {
        println!("Received log: {:?}", log);
        let temp_log = "0x9403918367f33721588a6f8bc19a427e2182149b923249cb0c5b3c8f440b8ef0";
        let tx_hash = H256::from_str(temp_log)?;

        let tx = http_provider.get_transaction(tx_hash).await.unwrap();
        // console.log(tx);
        println!("Transaction: {:?}", tx);
    }

    Ok(())
}
