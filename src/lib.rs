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

use bitcoin::blockdata::transaction::{Transaction, TxIn};

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
