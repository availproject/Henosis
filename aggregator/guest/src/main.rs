#![no_main]
use risc0_zkvm::{guest::env, serde};

// use serde::{Deserialize, Serialize};
use std::str::FromStr;

risc0_zkvm::guest::entry!(main);
use zkevmguest::VERIFIER_ID;
use zksyncguest::ZKSYNCGUEST_ID;

fn main() {
    let isProofVerified: bool = env::read();

    env::verify(VERIFIER_ID, &serde::to_vec(&isProofVerified).unwrap()).unwrap();
    env::verify(ZKSYNCGUEST_ID, &serde::to_vec(&isProofVerified).unwrap()).unwrap();
}
