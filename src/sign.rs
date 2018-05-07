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

//! Helper functions to create and verify segwit input signatures with the sighash all type.

use std::borrow::ToOwned;

use bitcoin::blockdata::transaction::SigHashType;
use bitcoin::blockdata::script::Script;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::util::hash::Sha256dHash;
use secp256k1::{self, Message, PublicKey, Secp256k1, SecretKey, Signature};

use {TxInRef, TxOutValue};

/// A signature data with the embedded sighash type byte.
#[derive(Debug, Clone, PartialEq)]
pub struct InputSignature(Vec<u8>);

impl InputSignature {
    /// Constructs input signature from the given signature data and the given sighash type.
    pub fn new(mut inner: Vec<u8>, sighash_type: SigHashType) -> InputSignature {
        inner.push(sighash_type as u8);
        InputSignature(inner)
    }

    /// Returns the signature content in canonical form.
    pub fn content(&self) -> &[u8] {
        self.0.split_last().unwrap().1
    }

    /// Returns a sighash type of the given input signature.
    pub fn sighash_type(&self) -> SigHashType {
        let byte = *self.0.last().unwrap();
        SigHashType::from_u32(u32::from(byte))
    }
}

/// A borrowed equivalent of the `InputSignature` data type.
/// It can be useful for checking incoming signatures from the unauthorized sources.
/// 
/// # Examples
/// 
/// ```
/// extern crate btc_transaction_utils;
/// extern crate hex;
/// extern crate secp256k1;
/// 
/// use secp256k1::Secp256k1;
/// use btc_transaction_utils::InputSignatureRef;
/// 
/// fn main() {
///     // Get a signature from the unknown source.
///     let bytes = hex::decode(
///         "304402201538279618a4626653775069b43d4315c7d2ff3000\
///          8d339d0ed31ff41e628e71022028f3182fc39df28201ca4d7d\
///          489aece7bc5bc6bfe05b09b6a9d3b70bf5f3743101",
///     ).unwrap();
///     // Try to decode it.
///     let ctx = Secp256k1::without_caps();
///     let signature = InputSignatureRef::from_bytes(&ctx, &bytes)
///         .expect("Signature should be correct");
/// }
/// ```
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct InputSignatureRef<'a>(&'a [u8]);

impl<'a> InputSignatureRef<'a> {
    /// Tries to construct input signature from the raw bytes.
    pub fn from_bytes(
        ctx: &Secp256k1,
        bytes: &'a [u8],
    ) -> Result<InputSignatureRef<'a>, secp256k1::Error> {
        let (_sighash_type, content) = bytes
            .split_last()
            .ok_or_else(|| secp256k1::Error::InvalidMessage)?;
        Signature::from_der(ctx, content)?;
        Ok(InputSignatureRef(bytes))
    }

    /// Returns the signature content in canonical form.
    pub fn content(&self) -> &[u8] {
        self.0.split_last().unwrap().1
    }

    /// Returns a sighash type of the given input signature.
    pub fn sighash_type(&self) -> SigHashType {
        let byte = *self.0.last().unwrap();
        SigHashType::from_u32(u32::from(byte))
    }
}

impl From<InputSignature> for Vec<u8> {
    fn from(s: InputSignature) -> Self {
        s.0
    }
}

impl AsRef<[u8]> for InputSignature {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl<'a> AsRef<[u8]> for InputSignatureRef<'a> {
    fn as_ref(&self) -> &[u8] {
        self.0
    }
}

impl<'a> From<&'a InputSignature> for InputSignatureRef<'a> {
    fn from(s: &'a InputSignature) -> InputSignatureRef {
        InputSignatureRef(s.0.as_ref())
    }
}

impl<'a> From<InputSignatureRef<'a>> for Vec<u8> {
    fn from(s: InputSignatureRef<'a>) -> Vec<u8> {
        s.0.to_owned()
    }
}

impl<'a> From<InputSignatureRef<'a>> for InputSignature {
    fn from(s: InputSignatureRef<'a>) -> InputSignature {
        InputSignature(s.0.to_owned())
    }
}

/// Computes the [`BIP-143`][bip-143] compliant sighash for a [`SIGHASH_ALL`][sighash_all]
/// signature for the given input.
///
/// [bip-143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
/// [sighash_all]: https://bitcoin.org/en/developer-guide#signature-hash-types
pub fn signature_hash<'a, 'b, V: Into<TxOutValue<'b>>>(
    txin: TxInRef<'a>,
    script: &Script,
    value: V,
) -> Sha256dHash {
    let value = value.into().amount(txin);
    SighashComponents::new(txin.transaction()).sighash_all(txin.as_ref(), script, value)
}

/// Computes the [`BIP-143`][bip-143] compliant signature for the given input.
/// [Read more...][signature-hash]
///
/// [bip-143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
/// [signature-hash]: fn.signature_hash.html
pub fn sign_input<'a, 'b, V: Into<TxOutValue<'b>>>(
    context: &mut Secp256k1,
    txin: TxInRef<'a>,
    script: &Script,
    value: V,
    secret_key: &SecretKey,
) -> Result<InputSignature, secp256k1::Error> {
    // compute sighash
    let sighash = signature_hash(txin, script, value);
    // Make signature
    let msg = Message::from_slice(&sighash[..])?;
    let signature = context.sign(&msg, secret_key)?.serialize_der(context);
    Ok(InputSignature::new(signature, SigHashType::All))
}

/// Checks correctness of the signature for the given input.
/// [Read more...][signature-hash]
///
/// [signature-hash]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
pub fn verify_input_signature<'a, 'b, V>(
    context: &Secp256k1,
    txin: TxInRef<'a>,
    script: &Script,
    value: V,
    public_key: &PublicKey,
    signature: &[u8],
) -> Result<(), secp256k1::Error>
where
    V: Into<TxOutValue<'b>>,
{
    // compute sighash
    let sighash = signature_hash(txin, script, value);
    // Verify signature
    let msg = Message::from_slice(&sighash[..])?;
    let sign = Signature::from_der(context, signature)?;
    context.verify(&msg, &sign, public_key)
}

#[test]
fn test_input_signature_ref_incorrect() {
    let ctx = Secp256k1::without_caps();
    let bytes = b"abacaba";
    InputSignatureRef::from_bytes(&ctx, bytes).expect_err("Signature should be incorrect");
}

#[test]
fn test_input_signature_ref_correct() {
    let ctx = Secp256k1::without_caps();
    let bytes = ::hex::decode(
        "304402201538279618a4626653775069b43d4315c7d2ff30008d339d0ed31ff41e628e71022028f3182fc39df\
         28201ca4d7d489aece7bc5bc6bfe05b09b6a9d3b70bf5f3743101",
    ).unwrap();
    InputSignatureRef::from_bytes(&ctx, &bytes).expect("Signature should be correct");
}
