use bitcoin::blockdata::transaction::SigHashType;
use bitcoin::blockdata::script::Script;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::util::hash::Sha256dHash;
use secp256k1::{self, Message, PublicKey, Secp256k1, SecretKey, Signature};

use {TxInRef, TxOutValue};

// Helper functions to create and verify segwit input signatures with the sighash all type.

pub fn signature_hash<'a, 'b, V: Into<TxOutValue<'b>>>(
    script: &Script,
    txin: TxInRef<'a>,
    value: V,
) -> Sha256dHash {
    let tx = txin.transaction();
    let idx = txin.index();
    let value = value.into().amount(txin);
    SighashComponents::new(tx).sighash_all(tx, idx, &script, value)
}

pub fn sign_input<'a, 'b, V: Into<TxOutValue<'b>>>(
    context: &mut Secp256k1,
    script: &Script,
    txin: TxInRef<'a>,
    value: V,
    secret_key: &SecretKey,
) -> Result<Vec<u8>, secp256k1::Error> {
    // compute sighash
    let sighash = signature_hash(script, txin, value);
    // Make signature
    let msg = Message::from_slice(&sighash[..])?;
    let mut signature = context.sign(&msg, secret_key)?.serialize_der(&context);
    signature.push(SigHashType::All as u8);
    Ok(signature)
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
