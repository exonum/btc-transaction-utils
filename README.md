# btc-transaction-utils

[![Travis Build Status](https://img.shields.io/travis/exonum/btc-transaction-utils/master.svg?label=Linux)](https://travis-ci.org/exonum/btc-transaction-utils)
[![Appveyor Build Status](https://img.shields.io/appveyor/ci/exonum-org/btc-transaction-utils/master.svg?label=Windows)](https://ci.appveyor.com/project/exonum-org/btc-transaction-utils)
[![dependency status](https://deps.rs/repo/github/exonum/btc-transaction-utils/status.svg)](https://deps.rs/repo/github/exonum/btc-transaction-utils)
[![Docs.rs](https://docs.rs/btc-transaction-utils/badge.svg)](https://docs.rs/btc-transaction-utils)
![rust 1.23+ required](https://img.shields.io/badge/rust-1.23+-blue.svg?label=Required%20Rust)

BTC transaction utils is a small library that helps to create multisig addresses
and to sign some types of segwit transactions.

Manipulations with segwit transactions are not considered trivial, so the main goal
is to provide simple and clear solution for the most common cases.

## Features

- Creation of the redeem script, which is used in the multisignature transactions.
- Signing and verification of the `p2wsh` inputs.
- Signing and verification of the `p2wpk` inputs.

**Note: This library supports only the `SIGHASH_ALL` type of signatures.**

## TODO

Some features are not implemented at the moment, but are desired in future releases. So any help
in their implementation is welcomed.

- Implement support for `P2SH-P2WPKH` and `P2SHP2WSH` inputs.
- Implement `TransactionBuilder` which helps to create unsigned transactions.
- Implement support for legacy inputs.
- Implement universal transaction signer which can automatically detect kind of output
  for the corresponding input.

## License

Licensed under the Apache License (Version 2.0). See [LICENSE](LICENSE) for details.
