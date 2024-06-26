# Henosis: Aggregation of State Validity Proofs for ZK-EVMs and ZKsync
<div align="center">
  <img src="https://github.com/Banana-Wallet/Henosis/blob/main/agg_imp.webp" width="512" height="350">
</div>

### How does it works
Henosis is a proof aggregation service which currently works with Polygon zkevm and Zksync. It fetches the state validity proofs for these rollups from their L1 contract along with public signals. Once fetched since the proofs generated by these rollups follows different proving methods (FFlonk by Polygon zkevm and some modified Plonk by Zksync). These proofs are then converted to starks proofs by recursively verifying this proofs inside zkVM and then the STARK proofs gets aggregated using Risc0 composition.

### Setup and Usage
- Clone the repo and change directory to `cd henosis/henosis`
- Build the project with `cargo build`
- Set up Bonsai API key `let api_key = "API_KEY".to_string();` change [here](https://github.com/RizeLabs/Henosis/blob/4c0b7e4ab92aed18b11e343ea50c2d94954ac021/converter/src/converter.rs#L53C5-L53C41) And if you don't have one you can request one on Risc0 discord.
- Run henosis with `cargo run`

PS: Currently Henosis only fetches and convert Polygon zkevm proofs since conversion of ZKsync proofs takes a lots of cycles in the crude implementation

### Project Structure 

**Prologue:** A typical Risc0 project consist of two components `host` and `guest`. `Host` component is sort of like a driver component which runs the proving with appropriate inputs and implements necessary covering logic your app needs, On the other hand `guest` component on a highlevel contains code which needs to be provable internally it compiles down the rust program into RiscV executable which then helps in generating starks proofs out of the obtained execution trace.

`/agghost`: It's a Risc0 driver component for aggregator, and facilitates aggregation of stark proofs via aggregator guest.

`/aggregator`: It's a Risc0 guest component connected with the `agghost` drive and contains the STARK proof composition logic.

`/converter`: Contains methods for converting fflonk or modified plonk proofs to groth16 or STARKs proofs.

`/fflonk_verifier`: It's a crates library which contain fflonk verifier implementation using ark_works library. Corresponding to their onchain solidity [verifier](https://github.com/0xPolygonHermez/zkevm-contracts/blob/main/contracts/verifiers/FflonkVerifier.sol).

`/plonk_verifier`: It's a crates library which contain Plonk verifier implementation using ark_works library. Corresponding to their onchain solidity verifier.

`/zksync_verifier`: It's a crates library which contain Modified Plonk verifier implementation using ark_works library. Corresponding to their onchain solidity [verifier](https://etherscan.io/address/0x3390051435ecb25a9610a1cf17d1ba0a228a0560#code).

`zksyncguest`: It imports `zksync_verifier` and enable recursive verification of zksync modified plonk proofs. To get final STARK of Groth16 (using [stark to snark conversion](https://www.risczero.com/blog/on-chain-verification)) proofs.

`zkevmguest`: It imports `fflonk_verifier` and enable recursive verification of zkevm fflonk proofs. To get final STARK of Groth16 (using stark to snark converter) proofs.

**IMPORTANT:** The project is not production ready yet and should not be used in production environment.


