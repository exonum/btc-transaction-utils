# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## 0.7.0 - 2019-09-13

### Breaking changes

- `bitcoin` dependency has been updated to the new major release `0.20`. (#10)

## 0.6.0 - 2019-03-30

### Breaking changes

- `bitcoin` dependency has been updated to the new major release `0.18`. (#10)

## 0.5.0 - 2019-03-14

### Breaking changes

- `bitcoin` dependency has been updated to the new major release `0.17`. (#9)

  - Methods `secp_gen_keypair_with_rng` and `secp_gen_keypair` now require
    bitcoin network type and return `PrivateKey` key instead of `SecretKey`.
  - Several methods no longer require `Secp256k1` context.
  - `secp256k1::PublicKey` replaced by the `bitcoin::PublicKey`.

## 0.4.0 - 2018-11-22

### Breaking changes

- `bitcoin` dependency has been updated to the new major release `0.15.1`. (#8)

## 0.3.1 - 2018-08-31

### Improvements

- Requirements for dependencies have been relaxed. (#6)

## 0.3 - 2018-08-31

### Breaking changes

- `bitcoin` dependency has been updated to the new major release `0.14.1`. (#5)

## 0.2 - 2018-05-24

### New features

- Added blank constructor to the `RedeemScriptBuilder`. (#3)
- Implemented script pubkey creation in `p2wsh` and `p2pk` modules. (#3)

### Breaking changes

- Method `verify_signature` of the `InputSigner` in `p2wsh` and `p2wpk` modules was changed to accept
 `Into<InputSignatureRef>` instead of raw bytes. This change made signature verification stricter
 than before. (#4)

## 0.1 - 2018-05-16

The first release of BTC transaction utils crate.
