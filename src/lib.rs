extern crate bitcoin;
#[macro_use]
extern crate display_derive;
extern crate failure;
#[macro_use]
extern crate failure_derive;
extern crate hex;
extern crate rand;
extern crate secp256k1;

#[macro_use]
mod macros;
pub mod p2wsh;
pub mod multisig;
pub mod test_data;

use bitcoin::blockdata::transaction::{Transaction, TxIn};

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

    pub(crate) fn index(&self) -> usize {
        self.index
    }
}
