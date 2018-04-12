use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::transaction::SigHashType;
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::bip143::SighashComponents;
use secp256k1::{self, Message, Secp256k1, SecretKey, Signature};

use multisig::RedeemScript;
use TxInRef;

pub fn script_sig(redeem_script: &RedeemScript) -> Script {
    redeem_script.0.to_v0_p2wsh()
}

pub fn address(redeem_script: &RedeemScript, network: Network) -> Address {
    Address::p2shwsh(&script_sig(redeem_script), network)
}

pub fn sign_input<'a>(
    context: &mut Secp256k1,
    redeem_script: &Script,
    txin: TxInRef<'a>,
    value: u64,
    secret_key: &SecretKey,
) -> Result<Vec<u8>, secp256k1::Error> {
    // compute sighash
    let sighash = SighashComponents::new(txin.transaction()).sighash_all(
        txin.transaction(),
        txin.index(),
        &redeem_script,
        value,
    );
    // Make signature
    let msg = Message::from_slice(&sighash[..])?;
    let mut signature = context.sign(&msg, secret_key)?.serialize_der(context);
    signature.push(SigHashType::All as u8);
    Ok(signature)
}

pub fn witness_stack<I: IntoIterator<Item = Signature>>(
    redeem_script: &RedeemScript,
    context: &Secp256k1,
    signatures: I,
) -> Vec<Vec<u8>> {
    let mut witness_stack = vec![Builder::new().push_int(0).into_script().into_vec()];

    witness_stack = signatures
        .into_iter()
        .fold(witness_stack, |mut witness_stack, signature| {
            witness_stack.push(signature.serialize_der(context));
            witness_stack
        });
    witness_stack.push(redeem_script.0.clone().into_vec());
    witness_stack
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::script::{Script, Builder};
    use bitcoin::blockdata::opcodes::All;
    use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
    use bitcoin::network::constants::Network;
    use bitcoin::util::address::Address;
    use rand::{SeedableRng, StdRng};
    use secp256k1::Secp256k1;

    use p2wsh;
    use test_data::secp_gen_keypair_with_rng;
    use TxInRef;

    fn tx_from_hex(s: &str) -> Transaction {
        let bytes = ::bitcoin::util::misc::hex_bytes(s).unwrap();
        ::bitcoin::network::serialize::deserialize(&bytes).unwrap()
    }

    #[allow(unused)]
    fn tx_to_hex(tx: &Transaction) -> String {
        let bytes = ::bitcoin::network::serialize::serialize(tx).unwrap();
        ::hex::encode(bytes)
    }

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
                    script_pubkey: Builder::new().push_opcode(All::OP_RETURN).push_slice(b"Hello Exonum!").into_script(),
                },
            ],
            witness: Vec::default(),
        };

        let witness_script = Address::p2pkh(&pk, Network::Testnet).script_pubkey();
        let mut context = Secp256k1::new();
        let signature = p2wsh::sign_input(
            &mut context,
            &witness_script,
            TxInRef::new(&transaction, 0),
            10000000,
            &sk,
        ).unwrap();
        let witness_stack = vec![signature, pk.serialize().to_vec()];
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

    // #[test]
    // fn test_multisig() {
    //     let mut rng: StdRng = SeedableRng::from_seed([1, 2, 3, 4].as_ref());
    //     let keypairs = (0..4)
    //         .into_iter()
    //         .map(|_| secp_gen_keypair_with_rng(&mut rng))
    //         .collect::<Vec<_>>();

    //     let redeem_script = RedeemScriptBuilder::with_public_keys(keypairs.iter().map(|x| x.0))
    //         .quorum(3)
    //         .to_script()
    //         .unwrap();
    //     let address = p2wsh::address(&redeem_script, Network::Testnet);
    //     let script_pubkey = address.script_pubkey();
    //     let script_sig = p2wsh::script_sig(&redeem_script);

    //     println!("redeem_script: {:?}", redeem_script);
    //     println!("address: {}", address.to_string());
    //     println!("script_pubkey: {:?}", script_pubkey);

    //     let prev_tx = tx_from_hex("02000000000101b98f01c859d40306de4886e7401e82da3c9f5e335586c34774899d3c3ae57240000000001716001408b46a89c9fe84dfc18e15980f7724bc0eab04d5feffffff02e8dd6e080000000017a914994de8f0b83934b536e56e775e7e734bbfed482187809698000000000017a914d681e43db8357b6e269e761c7de1d98693de6a0f8702483045022100ec2a2810c6b05e4d201791f46ba19e07b0016c5dc8012cc5a400340a303e084102201b21dea75d5808ebad7c522afe88befccf32a438dd8970b14f31eb0ea60f00520121032f394bbec7015628886576f75c59a53668bf8fc6cc6f0258516a987df517b9db1eb71300");
    //     assert_eq!(prev_tx.output[1].script_pubkey, address.script_pubkey());

    //     println!("prev_tx: {:#?}", prev_tx);

    //     // Unsigned transaction
    //     let mut transaction = Transaction {
    //         version: 1,
    //         lock_time: 0,
    //         input: vec![
    //             TxIn {
    //                 prev_hash: prev_tx.txid(),
    //                 prev_index: 1,
    //                 script_sig: Script::default(),
    //                 sequence: 0xFFFFFFFE,
    //             },
    //         ],
    //         output: vec![
    //             TxOut {
    //                 value: 1000,
    //                 script_pubkey: script_sig,
    //             },
    //         ],
    //         witness: Vec::default(),
    //     };
    //     let mut context = Secp256k1::new();

    //     let witness_stack = {
    //         let signatures = keypairs[0..3].iter().map(|keypair| {
    //             p2wsh::sign_input(
    //                 &mut context,
    //                 &redeem_script.0,
    //                 TxInRef::new(&transaction, 0),
    //                 10000000,
    //                 &keypair.1,
    //             ).unwrap()
    //         });
    //         p2wsh::witness_stack(&redeem_script, &Secp256k1::new(), signatures)
    //     };

    //     println!("witness_stack: {:?}", witness_stack);

    //     transaction.witness.push(witness_stack);

    //     println!("txdata: {:#?}", transaction);
    //     println!("txhex: {}", tx_to_hex(&transaction));
    //     let mut inputs = ::std::collections::HashMap::new();
    //     inputs.insert(prev_tx.txid(), prev_tx.clone());
    //     let res = transaction.verify(&inputs);
    //     if let Err(e) = res {
    //         panic!("{}", e);
    //     }
    // }
}
