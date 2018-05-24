# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### New features

- Added blank constructor to the `RedeemScriptBuilder`. (#3)
- Implemented script pubkey creation in `p2wsh` and `p2pk` modules. (#3)

### Breaking changes

- Method `verify_signature` of the `InputSigner` in `p2wsh` and `p2wpk` modules was changed to accept
 `Into<InputSignatureRef>` instead of raw bytes. This change made signature verification stricter
 than before. (#4)

## 0.1 - 2018-05-16

The first release of BTC transaction utils crate.