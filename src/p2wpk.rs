use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::SigHashType;
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::bip143::SighashComponents;
use secp256k1::{self, Message, PublicKey, Secp256k1, SecretKey};

use TxInRef;

pub fn address(pk: &PublicKey, network: Network) -> Address {
    Address::p2wpkh(pk, network)
}

pub fn witness_script(pk: &PublicKey, network: Network) -> Script {
    Address::p2pkh(&pk, network).script_pubkey()
}

pub fn sign_input<'a>(
    context: &mut Secp256k1,
    witness_script: &Script,
    txin: TxInRef<'a>,
    value: u64,
    secret_key: &SecretKey,
) -> Result<Vec<u8>, secp256k1::Error> {
    // compute sighash
    let sighash = SighashComponents::new(txin.transaction()).sighash_all(
        txin.transaction(),
        txin.index(),
        &witness_script,
        value,
    );
    // Make signature
    let msg = Message::from_slice(&sighash[..])?;
    let mut signature = context.sign(&msg, secret_key)?.serialize_der(context);
    signature.push(SigHashType::All as u8);
    Ok(signature)
}

pub fn witness_stack(pk: &PublicKey, signature: Vec<u8>) -> Vec<Vec<u8>> {
    vec![signature, pk.serialize().to_vec()]
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::script::{Builder, Script};
    use bitcoin::blockdata::opcodes::All;
    use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
    use bitcoin::network::constants::Network;
    use rand::{SeedableRng, StdRng};
    use secp256k1::Secp256k1;

    use TxInRef;
    use p2wpk;
    use test_data::{secp_gen_keypair_with_rng, tx_from_hex};

    #[test]
    fn test_native_segwit() {
        let mut rng: StdRng = SeedableRng::from_seed([1, 2, 3, 4].as_ref());
        let (pk, sk) = secp_gen_keypair_with_rng(&mut rng);

        let prev_tx = tx_from_hex(
            "02000000000101beccab33bc72bfc81b63fdec8a4a9a4719e4418bdb7b20e47b02074dc42f2d800000000\
             017160014f3b1b3819c1290cd5d675c1319dc7d9d98d571bcfeffffff02dceffa0200000000160014368c\
             6b7c38f0ff0839bf78d77544da96cb685bf28096980000000000160014284175e336fa10865fb4d1351c9\
             e18e730f5d6f90247304402207c893c85d75e2230dde04f5a1e2c83c4f0b7d93213372746eb2227b06826\
             0d840220705484b6ec70a8fc0d1f80c3a98079602595351b7a9bca7caddb9a6adb0a3440012103150514f\
             05f3e3f40c7b404b16f8a09c2c71bad3ba8da5dd1e411a7069cc080a004b91300",
        );
        assert_eq!(
            prev_tx.output[1].script_pubkey,
            p2wpk::address(&pk, Network::Testnet).script_pubkey()
        );

        // Unsigned transaction
        let mut transaction = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![
                TxIn {
                    prev_hash: prev_tx.txid(),
                    prev_index: 1,
                    script_sig: Script::default(),
                    sequence: 0xFFFFFFFF,
                },
            ],
            output: vec![
                TxOut {
                    value: 0,
                    script_pubkey: Builder::new()
                        .push_opcode(All::OP_RETURN)
                        .push_slice(b"Hello Exonum!")
                        .into_script(),
                },
            ],
            witness: Vec::default(),
        };

        let witness_script = p2wpk::witness_script(&pk, Network::Testnet);
        let mut context = Secp256k1::new();
        let signature = p2wpk::sign_input(
            &mut context,
            &witness_script,
            TxInRef::new(&transaction, 0),
            10000000,
            &sk,
        ).unwrap();
        let witness_stack = p2wpk::witness_stack(&pk, signature);
        // Signed transaction
        transaction.witness.push(witness_stack);
        // Check output
        let expected_tx = tx_from_hex(
            "0200000000010145f4a039a4bd6cc753ec02a22498b98427c6c288244340fff9d2abb5c63e48390100000\
             000ffffffff0100000000000000000f6a0d48656c6c6f2045786f6e756d2102483045022100bdc1be9286\
             2281061a14f7153dd57b7b3befa2b98fe85ae5d427d3921fe165ca02202f259a63f965f6d7f0503584b46\
             3ce4b67c09b5a2e99c27f236f7a986743a94a0121031cf96b4fef362af7d86ee6c7159fa89485730dac8e\
             3090163dd0c282dbc84f2200000000",
        );
        assert_eq!(transaction, expected_tx);
    }
}
