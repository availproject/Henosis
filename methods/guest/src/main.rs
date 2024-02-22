#![no_main]
use risc0_zkvm::guest::env;
// use plonk_verifier::verifier::verifier::verify;
use fflonk_verifier::verifier::verify;

risc0_zkvm::guest::entry!(main);
fn main() {
    // TODO: Implement your guest code here

    // read the input
    let input: u32 = env::read();
    println!("Entered into it");

    verify();
    
    env::commit(&input);
}
