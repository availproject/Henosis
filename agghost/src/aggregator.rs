use aggregator::{AGGREGATOR_ELF, AGGREGATOR_ID};
use risc0_zkvm::{compute_image_id, default_prover, serde::to_vec, ExecutorEnv, Receipt};
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub fn aggregate_stark_receipts(stark_receipts: [Receipt; 2]) -> Receipt {
    let env = ExecutorEnv::builder()
        .add_assumption(stark_receipts[0].clone()) // zkevm stark receipt
        .add_assumption(stark_receipts[1].clone()) // zksync stark receipt
        .write(&(true))
        .unwrap()
        .build()
        .unwrap();

    let receipt = default_prover().prove(env, AGGREGATOR_ELF).unwrap();
    receipt.verify(AGGREGATOR_ID).unwrap();
    receipt
}
