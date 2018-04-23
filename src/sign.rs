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

use bitcoin::blockdata::transaction::SigHashType;
use bitcoin::blockdata::script::Script;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::util::hash::Sha256dHash;
use secp256k1::{self, Message, PublicKey, Secp256k1, SecretKey, Signature};

use {TxInRef, TxOutValue};

pub struct InputSignature(Vec<u8>);

impl InputSignature {
    pub fn new(mut inner: Vec<u8>, sighash_type: SigHashType) -> InputSignature {
        inner.push(sighash_type as u8);
        InputSignature(inner)
    }

    pub fn content(&self) -> &[u8] {
        &self.0.split_last().unwrap().1
    }

    pub fn sighash_type(&self) -> SigHashType {
        let byte = *self.0.last().unwrap();
        SigHashType::from_u32(byte as u32)
    }
}

impl From<InputSignature> for Vec<u8> {
    fn from(s: InputSignature) -> Self {
        s.0
    }
}

pub fn signature_hash<'a, 'b, V: Into<TxOutValue<'b>>>(
    script: &Script,
    txin: TxInRef<'a>,
    value: V,
) -> Sha256dHash {
    let value = value.into().amount(txin);
    SighashComponents::new(txin.transaction()).sighash_all(txin.as_ref(), &script, value)
}

pub fn sign_input<'a, 'b, V: Into<TxOutValue<'b>>>(
    context: &mut Secp256k1,
    script: &Script,
    txin: TxInRef<'a>,
    value: V,
    secret_key: &SecretKey,
) -> Result<InputSignature, secp256k1::Error> {
    // compute sighash
    let sighash = signature_hash(script, txin, value);
    // Make signature
    let msg = Message::from_slice(&sighash[..])?;
    let signature = context.sign(&msg, secret_key)?.serialize_der(&context);
    Ok(InputSignature::new(signature, SigHashType::All))
}

pub fn verify_input_signature<'a, 'b, V: Into<TxOutValue<'b>>>(
    context: &Secp256k1,
    script: &Script,
    txin: TxInRef<'a>,
    value: V,
    public_key: &PublicKey,
    signature: &[u8],
) -> Result<(), secp256k1::Error> {
    // compute sighash
    let sighash = signature_hash(script, txin, value);
    // Verify signature
    let msg = Message::from_slice(&sighash[..])?;
    let sign = Signature::from_der(&context, signature)?;
    context.verify(&msg, &sign, public_key)
}
