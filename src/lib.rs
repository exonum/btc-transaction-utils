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

//! BTC transaction utils is a small library that will help to create multisig addresses
//! and sign a some types of segwit transactions.
//!
//! By using this library you can make the following things:
//!
//! - [Create][redeem-script] a redeem script and a corresponding multisig address (3 of 4).
//! - [Sign][p2wpk] the `P2WPK` inputs.
//! - [Sign][p2wsh] the `P2WSH` inputs.
//!
//! # Examples
//!
//! ## Create a redeem script and a corresponding multisig address (3 of 4).
//!
//! ```
//! extern crate bitcoin;
//! extern crate btc_transaction_utils;
//!
//! use bitcoin::network::constants::Network;
//! use btc_transaction_utils::multisig::RedeemScriptBuilder;
//! use btc_transaction_utils::test_data::secp_gen_keypair;
//! use btc_transaction_utils::p2wsh;
//!
//! fn main() {
//!     // Generate four key pairs.
//!     let keypairs = (0..4)
//!         .map(|_| secp_gen_keypair())
//!         .collect::<Vec<_>>();
//!     // Create a corresponding redeem script.
//!     let public_keys = keypairs.iter().map(|keypair| keypair.0);
//!     let script = RedeemScriptBuilder::with_public_keys(public_keys)
//!         .quorum(3)
//!         .to_script()
//!         .unwrap();
//!     // Create a corresponding testnet address for the given redeem script.
//!     let address = p2wsh::address(&script, Network::Testnet);
//!     println!("{}", address.to_string());
//! }
//! ```
//!
//! ## Sign P2WPK input
//!
//! ```
//! extern crate bitcoin;
//! extern crate btc_transaction_utils;
//! extern crate rand;
//!
//! use bitcoin::blockdata::opcodes::All;
//! use bitcoin::blockdata::script::{Builder, Script};
//! use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
//! use bitcoin::network::constants::Network;
//! use btc_transaction_utils::p2wpk;
//! use btc_transaction_utils::test_data::{secp_gen_keypair_with_rng, btc_tx_from_hex};
//! use btc_transaction_utils::TxInRef;
//! use rand::{SeedableRng, StdRng};
//!
//! fn main() {
//!     // Take a transaction with the unspent P2WPK output.
//!     let prev_tx = btc_tx_from_hex(
//!         "02000000000101beccab33bc72bfc81b63fdec8a4a9a4719e4418bdb7b20e47b0\
//!          2074dc42f2d800000000017160014f3b1b3819c1290cd5d675c1319dc7d9d98d5\
//!          71bcfeffffff02dceffa0200000000160014368c6b7c38f0ff0839bf78d77544d\
//!          a96cb685bf28096980000000000160014284175e336fa10865fb4d1351c9e18e7\
//!          30f5d6f90247304402207c893c85d75e2230dde04f5a1e2c83c4f0b7d93213372\
//!          746eb2227b068260d840220705484b6ec70a8fc0d1f80c3a98079602595351b7a\
//!          9bca7caddb9a6adb0a3440012103150514f05f3e3f40c7b404b16f8a09c2c71ba\
//!          d3ba8da5dd1e411a7069cc080a004b91300",
//!     );
//!     // Take the corresponding key pair.
//!     let mut rng: StdRng = SeedableRng::from_seed([1, 2, 3, 4].as_ref());
//!     let keypair = secp_gen_keypair_with_rng(&mut rng);
//!     // Create an unsigned transaction
//!     let mut transaction = Transaction {
//!         version: 2,
//!         lock_time: 0,
//!         input: vec![
//!             TxIn {
//!                 prev_hash: prev_tx.txid(),
//!                 prev_index: 1,
//!                 script_sig: Script::default(),
//!                 sequence: 0xFFFFFFFF,
//!                 witness: Vec::default(),
//!             },
//!         ],
//!         output: vec![
//!             TxOut {
//!                 value: 0,
//!                 script_pubkey: Builder::new()
//!                     .push_opcode(All::OP_RETURN)
//!                     .push_slice(b"Hello Exonum!")
//!                     .into_script(),
//!             },
//!         ],
//!     };
//!     // Create a signature for the given input.
//!     let mut signer = p2wpk::InputSigner::new(keypair.0, Network::Testnet);
//!     let signature = signer
//!         .sign_input(TxInRef::new(&transaction, 0), &prev_tx, &keypair.1)
//!         .unwrap();
//!     // Finalize the transaction.
//!     signer.spend_input(&mut transaction.input[0], signature);
//! }
//! ```
//!
//! ## Sign P2WSH input
//!
//! ```
//! extern crate bitcoin;
//! extern crate btc_transaction_utils;
//! extern crate rand;
//!
//! use bitcoin::blockdata::opcodes::All;
//! use bitcoin::blockdata::script::{Builder, Script};
//! use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
//! use bitcoin::network::constants::Network;
//! use btc_transaction_utils::multisig::RedeemScriptBuilder;
//! use btc_transaction_utils::p2wsh;
//! use btc_transaction_utils::test_data::{secp_gen_keypair_with_rng, btc_tx_from_hex};
//! use btc_transaction_utils::TxInRef;
//! use rand::{SeedableRng, StdRng};
//!
//! fn main() {
//!     // Take a transaction with the unspent P2WSH output.
//!     let prev_tx = btc_tx_from_hex(
//!         "02000000000101f8c16000cc59f9505046303944d42a6c264a322f80b46bb4361\
//!          15b6e306ba9950000000000feffffff02f07dc81600000000160014f65eb9d72a\
//!          8475dd8e26f4fa748796e211aa8869102700000000000022002001fb25c3db04c\
//!          a5580da43a7d38dd994650d9aa6d6ee075b4578388deed338ed0247304402206b\
//!          5f211cd7f9b89e80c734b61113c33f437ba153e7ba6bc275eed857e54fcb26022\
//!          0038562e88b805f0cdfd4873ab3579d52268babe6af9c49086c00343187cdf28a\
//!          012103979dff5cd9045f4b6fa454d2bc5357586a85d4789123df45f83522963d9\
//!          4e3217fb91300",
//!     );
//!     // Take the corresponding key pairs and the redeem script.
//!     let total_count = 18;
//!     let quorum = 12;
//!
//!     let mut rng: StdRng = SeedableRng::from_seed([1, 2, 3, 4].as_ref());
//!     let keypairs = (0..total_count)
//!         .into_iter()
//!         .map(|_| secp_gen_keypair_with_rng(&mut rng))
//!         .collect::<Vec<_>>();
//!     let public_keys = keypairs.iter().map(|keypair| keypair.0);
//!     let redeem_script = RedeemScriptBuilder::with_public_keys(public_keys)
//!         .quorum(quorum)
//!         .to_script()
//!         .unwrap();
//!     // Create an unsigned transaction.
//!     let mut transaction = Transaction {
//!         version: 2,
//!         lock_time: 0,
//!         input: vec![
//!             TxIn {
//!                 prev_hash: prev_tx.txid(),
//!                 prev_index: 1,
//!                 script_sig: Script::default(),
//!                 sequence: 0xFFFFFFFF,
//!                 witness: Vec::default(),
//!             },
//!         ],
//!         output: vec![
//!             TxOut {
//!                 value: 0,
//!                 script_pubkey: Builder::new()
//!                     .push_opcode(All::OP_RETURN)
//!                     .push_slice(b"Hello Exonum with multisig!")
//!                     .into_script(),
//!             },
//!         ],
//!     };
//!     // Create signatures for the given input.
//!     let mut signer = p2wsh::InputSigner::new(redeem_script.clone());
//!     let signatures = keypairs[0..quorum]
//!         .iter()
//!         .map(|keypair| {
//!             let txin = TxInRef::new(&transaction, 0);
//!             signer.sign_input(txin, &prev_tx, &keypair.1).unwrap()
//!         })
//!         .collect::<Vec<_>>();
//!     // Finalize the transaction.
//!     signer.spend_input(&mut transaction.input[0], signatures);
//! }
//! ```
//!
//! [redeem-script]: #create-a-redeem-script-and-a-corresponding-multisig-address-3-of-4
//! [p2wpk]: #sign-p2wpk-input
//! [p2wsh]: #sign-p2wsh-input

#![deny(missing_docs, missing_debug_implementations)]

extern crate bitcoin;
#[macro_use]
extern crate display_derive;
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate hex;
#[cfg(test)]
#[macro_use]
extern crate pretty_assertions;
extern crate rand;
extern crate secp256k1;
extern crate serde;
extern crate serde_str;

#[macro_use]
mod macros;
pub mod multisig;
pub mod p2wpk;
pub mod p2wsh;
mod sign;
pub mod test_data;

use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
pub use sign::{InputSignature, InputSignatureRef};

/// A borrowed reference to a transaction input.
#[derive(Debug, Copy, Clone)]
pub struct TxInRef<'a> {
    transaction: &'a Transaction,
    index: usize,
}

impl<'a> TxInRef<'a> {
    /// Constructs a reference to the input with the given index of the given transaction.
    pub fn new(transaction: &'a Transaction, index: usize) -> TxInRef<'a> {
        assert!(transaction.input.len() > index);
        TxInRef { transaction, index }
    }

    /// Returns a reference to the borrowed transaction.
    pub fn transaction(&self) -> &Transaction {
        self.transaction
    }

    /// Returns a reference to the input.
    pub fn input(&self) -> &TxIn {
        &self.transaction.input[self.index]
    }

    /// Returns the index of input.
    pub fn index(&self) -> usize {
        self.index
    }
}

impl<'a> AsRef<TxIn> for TxInRef<'a> {
    fn as_ref(&self) -> &TxIn {
        self.input()
    }
}

/// An auxiliary enumeration that helps to get the balance of the previous transaction output.
#[derive(Debug, Copy, Clone)]
pub enum TxOutValue<'a> {
    /// The output balance.
    Amount(u64),
    /// A reference to the transaction with the required output.
    PrevTx(&'a Transaction),
    /// A reference to the transaction output to be spent.
    PrevOut(&'a TxOut),
}

impl<'a> TxOutValue<'a> {
    /// Returns the output balance value.
    pub fn amount(self, txin: TxInRef) -> u64 {
        match self {
            TxOutValue::Amount(value) => value,
            TxOutValue::PrevTx(prev_tx) => prev_tx.output[txin.input().prev_index as usize].value,
            TxOutValue::PrevOut(out) => out.value,
        }
    }
}

impl<'a> From<u64> for TxOutValue<'a> {
    fn from(amount: u64) -> TxOutValue<'a> {
        TxOutValue::Amount(amount)
    }
}

impl<'a> From<&'a Transaction> for TxOutValue<'a> {
    fn from(tx_ref: &'a Transaction) -> TxOutValue {
        TxOutValue::PrevTx(tx_ref)
    }
}

impl<'a> From<&'a TxOut> for TxOutValue<'a> {
    fn from(tx_out: &'a TxOut) -> TxOutValue<'a> {
        TxOutValue::PrevOut(tx_out)
    }
}
