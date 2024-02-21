// [   "0x1af638185408dfa5b1470887ab5bf38a7363f6c26479828ab16eb45219715936", 
//   "0x2b129ebcbf22e11bb2442800922bf1c9979bb7a6c895e17411325e6a1c195912",  
//    "0x0098d7bc29d322c680263a7dba99490333dd42aeafc4ca99f870288f1052cd86",
//       "0x11c911bfb298b409c74838c0a3c16f7171dac07cddaba283e36090eef091d67f",  
//        "0x29c8c4c86c9d63a57e65dcef548f50c06ce41ffcaadf21f279f66a9f6b59f619",  
//         "0x01eb8b4841e587df317141dd2c198d0160eb974c34dd303f75b27cdac46ce887",  
//          "0x220c39420aa977359e2f2fb3c5d7b9b28a23a7f0c78d6b215d4178d3f2b1ba72", 
//            "0x045c6d18f3e18cc4aac314316a47f0010ba8b1035b7dab678933e5bcd248f72b",
//               "0x1cc4edb75ac4f07466f70f097d263bad6ca1e1e506bccbccd7de94b39dd3a05e",
//                  "0x0e11ad74cead5ed3d142083b8ad873acf20cb6e39059d88e61a84982386a698a", 
//                    "0x23806e3836d9fb0467b1ade5a51564aeda10cc9b97f596456cafa149f6c9bfbb", 
//                      "0x1aec381b720257b672376b5ccbd1fe787247e3cc7b2c6ec2d171be1c5c1a5837", 
//                        "0x038d7d45919eee4e6c7e47c586b1d55e32d102e56d64513575d94a9aeba30241", 
//                          "0x1ba4459cca4bb8b75808d4f38598e4b6cf6a8577f7294def8e85b5955abc681a", 
//                            "0x300239f087b7a581948dc4b14cdc9d5ae13ba8a9cbf56998f764ba13549ac6fa", 
//                              "0x104d55e131742e10144e0c9023635ee7e000de29d76c05ad56f6a74e40ac9924", 
//                                "0x177d85cc56ecaac98dc3c835668105f9ff8311a73767f7ba145d443af8d00999", 
//                                  "0x1bd5b487cf64d1973cdfbcf8587319d681ab87e595ef347d68067418cca5368f", 
//                                    "0x27144e4b99a6508fecc7b0fdc1a64d4be4760a1035730e29a907dd091c6b95ac",  
//                                     "0x1e8841cdf20050bfe02cbeb022b26960e8b544774112e09a21a440c8bba503d3",  
//                                      "0x15273dd6fecfedef5adde005a7ab5ee48a7eefdaa85ef4e356d0f3dcd92bcb64", 
//                                        "0x267735dcdbd34c8c5f8cf864f3990e078d26a928a54c27485133b6d0678cda9b", 
//                                          "0x1a193153f3cf956d68aab8afe447f0f6ba985f40edba7d9375b9368f1c55f31b", 
//                                            "0x0e1a49d180902645b8954552c99af04aed9315725b32ac2623965f887a7a5849" ]

use ethers::types::U256;
use std::str::FromStr;

fn main() {
    let hex_value = "0x045c6d18f3e18cc4aac314316a47f0010ba8b1035b7dab678933e5bcd248f72b"; // Your hex value
    let u256_value = U256::from_str(hex_value).expect("Invalid hex value");

    println!("U256 value: {}", u256_value);

    let hex_value = "0x1cc4edb75ac4f07466f70f097d263bad6ca1e1e506bccbccd7de94b39dd3a05e"; // Your hex value
    let u256_value = U256::from_str(hex_value).expect("Invalid hex value");

    println!("U256 value: {}", u256_value);

    let hex_value = "0x0e11ad74cead5ed3d142083b8ad873acf20cb6e39059d88e61a84982386a698a"; // Your hex value
    let u256_value = U256::from_str(hex_value).expect("Invalid hex value");

    println!("U256 value: {}", u256_value);

    let hex_value = "0x23806e3836d9fb0467b1ade5a51564aeda10cc9b97f596456cafa149f6c9bfbb"; // Your hex value
    let u256_value = U256::from_str(hex_value).expect("Invalid hex value");

    println!("U256 value: {}", u256_value);

    let hex_value = "0x1aec381b720257b672376b5ccbd1fe787247e3cc7b2c6ec2d171be1c5c1a5837"; // Your hex value
    let u256_value = U256::from_str(hex_value).expect("Invalid hex value");

    println!("U256 value: {}", u256_value);

    let hex_value = "0x038d7d45919eee4e6c7e47c586b1d55e32d102e56d64513575d94a9aeba30241"; // Your hex value
    let u256_value = U256::from_str(hex_value).expect("Invalid hex value");

    println!("U256 value: {}", u256_value);


    let hex_value = "0x1ba4459cca4bb8b75808d4f38598e4b6cf6a8577f7294def8e85b5955abc681a"; // Your hex value

    let u256_value = U256::from_str(hex_value).expect("Invalid hex value");

    println!("U256 value: {}", u256_value);

    let hex_value = "0x300239f087b7a581948dc4b14cdc9d5ae13ba8a9cbf56998f764ba13549ac6fa"; // Your hex value

    let u256_value = U256::from_str(hex_value).expect("Invalid hex value");

    println!("U256 value: {}", u256_value);
}


