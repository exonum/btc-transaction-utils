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
pub mod p2wsh;
pub mod p2wpk;
pub mod multisig;
pub mod test_data;

use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};

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

#[derive(Debug, Copy, Clone)]
pub enum TxOutValue<'a> {
    Amount(u64),
    PrevTx(&'a Transaction),
    PrevOut(&'a TxOut),
}

impl<'a> TxOutValue<'a> {
    fn amount<'b>(self, txin: TxInRef<'b>) -> u64 {
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