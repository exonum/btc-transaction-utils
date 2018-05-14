# btc-transaction-utils

[![Travis Build Status](https://img.shields.io/travis/exonum/btc-transaction-utils/master.svg?label=Linux)](https://travis-ci.org/exonum/btc-transaction-utils)
[![Appveyor Build Status](https://img.shields.io/appveyor/ci/exonum-org/btc-transaction-utils/master.svg?label=Windows)](https://ci.appveyor.com/project/exonum-org/btc-transaction-utils)
[![dependency status](https://deps.rs/repo/github/exonum/btc-transaction-utils/status.svg)](https://deps.rs/repo/github/exonum/btc-transaction-utils)
[![Docs.rs](https://docs.rs/btc-transaction-utils/badge.svg)](https://docs.rs/btc-transaction-utils)
![rust 1.23+ required](https://img.shields.io/badge/rust-1.23+-blue.svg?label=Required%20Rust)

BTC transaction utils is a small library that helps to create multisig addresses
and to swiftly sign some types of segwit transactions as well as to check the
existing signatures, if required.

Manipulations with segwit transactions are quite intricated, so the main goal
is to provide a simple and clear solution for the most common operations
as mentioned above.

## Features

- Creation of the redeem script, which is used in the multisignature transactions.
- Creation and checking of the applied signatures of the `p2wsh` inputs.
- Creation and checking of the applied signatures of the `p2wpk` inputs.

**Note: This library supports only the `SIGHASH_ALL` type of signatures.**

## TODO

Some features are not implemented at the moment, but are desired in future releases.
Any help in implementation of the below listed items is welcome.

- Implement support for `P2SH-P2WPKH` and `P2SHP2WSH` inputs.
- Implement `TransactionBuilder` which helps to create unsigned transactions.
- Implement support for legacy inputs.
- Implement universal transaction signer which can automatically detect the kind of output
  for the corresponding input.

## License

Licensed under the Apache License (Version 2.0). See [LICENSE](LICENSE) for details.
