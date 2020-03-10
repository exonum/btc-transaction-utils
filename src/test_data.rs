// Copyright 2018 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A set of helpers for testing.

use bitcoin::{
    blockdata::transaction::Transaction,
    consensus, Network, {PrivateKey, PublicKey},
};
use rand::Rng;
use secp256k1::{Secp256k1, SecretKey};

/// Computes a bitcoin private key and a corresponding public key using a
/// given pseudo-random number generator.
pub fn secp_gen_keypair_with_rng<R: Rng + ?Sized>(
    rng: &mut R,
    network: Network,
) -> (PublicKey, PrivateKey) {
    let context = Secp256k1::new();
    let sk = PrivateKey {
        network,
        compressed: true,
        key: SecretKey::new(rng),
    };
    let pk = PublicKey::from_private_key(&context, &sk);
    (pk, sk)
}

/// Generates a bitcoin private key and a corresponding public key using a cryptographically
/// secure pseudo-random number generator.
pub fn secp_gen_keypair(network: Network) -> (PublicKey, PrivateKey) {
    let mut rng = rand::thread_rng();
    secp_gen_keypair_with_rng(&mut rng, network)
}

/// Decodes a Bitcoin transaction from the given hex string.
///
/// # Panics
///
/// - If the given hex string can't be decoded as a Bitcoin transaction.
pub fn btc_tx_from_hex(s: &str) -> Transaction {
    let bytes = hex::decode(s).unwrap();
    consensus::deserialize(&bytes).unwrap()
}

/// Parses WIF encoded private key and creates a public key from this private key.
pub fn keypair_from_wif(wif: &str) -> (PublicKey, PrivateKey) {
    let ctx = Secp256k1::signing_only();

    let sk = PrivateKey::from_wif(wif).unwrap();
    let pk = sk.public_key(&ctx);
    (pk, sk)
}
