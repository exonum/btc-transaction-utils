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
mod sign;
pub mod p2wsh;
pub mod p2wpk;
pub mod multisig;
pub mod test_data;

use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
pub use sign::InputSignature;

#[derive(Debug, Copy, Clone)]
pub struct TxInRef<'a> {
    transaction: &'a Transaction,
    index: usize,
}

impl<'a> TxInRef<'a> {
    pub fn new(transaction: &'a Transaction, index: usize) -> TxInRef<'a> {
        assert!(transaction.input.len() > index);
        TxInRef { transaction, index }
    }

    pub fn transaction(&self) -> &Transaction {
        self.transaction
    }

    pub fn input(&self) -> &TxIn {
        &self.transaction.input[self.index]
    }

    pub fn index(&self) -> usize {
        self.index
    }
}

impl<'a> AsRef<TxIn> for TxInRef<'a> {
    fn as_ref(&self) -> &TxIn {
        self.input()
    }
}

#[derive(Debug, Copy, Clone)]
pub enum TxOutValue<'a> {
    Amount(u64),
    PrevTx(&'a Transaction),
    PrevOut(&'a TxOut),
}

impl<'a> TxOutValue<'a> {
    fn amount(self, txin: TxInRef) -> u64 {
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
