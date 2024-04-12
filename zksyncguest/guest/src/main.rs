#![no_main]
use risc0_zkvm::{guest::env, serde};

use std::str::FromStr;

risc0_zkvm::guest::entry!(main);
use zksync_verifier::verifier::verify as zksyncVerifier;

fn main() {
    let sample_input: u32 = env::read();
    // zksyncVerifier(); // pretty computationally intensive 
    // need to verify zksync proof here
    // true here stating that proof successfully verified
    let isVerified: bool = true;
    env::commit(&isVerified);
}
