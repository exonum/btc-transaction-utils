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
    consensus, {PrivateKey, PublicKey},
};
use secp256k1::Secp256k1;

/// Decodes a Bitcoin transaction from the given hex string.
///
/// # Panics
///
/// - If the given hex string can't be decoded as a Bitcoin transaction.
pub fn btc_tx_from_hex(s: &str) -> Transaction {
    let bytes = bitcoin::util::misc::hex_bytes(s).unwrap();
    consensus::deserialize(&bytes).unwrap()
}

/// Parses WIF encoded private key and creates a public key from this private key.
pub fn keypair_from_wif(wif: &str) -> (PublicKey, PrivateKey) {
    let ctx = Secp256k1::signing_only();

    let sk = PrivateKey::from_wif(wif).unwrap();
    let pk = sk.public_key(&ctx);
    (pk, sk)
}
