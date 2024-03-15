#![no_main]
use risc0_zkvm::{guest::env, serde};

// use serde::{Deserialize, Serialize};
use std::str::FromStr;

risc0_zkvm::guest::entry!(main);
use methods::VERIFIER_ID;

fn main() {
    let isVerified: bool = env::read();
    env::verify(VERIFIER_ID, &serde::to_vec(&isVerified).unwrap()).unwrap();
}
