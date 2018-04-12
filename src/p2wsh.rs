use bitcoin::blockdata::script::{Builder, Script};
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
) -> Result<Signature, secp256k1::Error> {
    // compute sighash
    let sighash = SighashComponents::new(txin.transaction()).sighash_all(
        txin.transaction(),
        txin.index(),
        &redeem_script,
        value,
    );
    // Make signature
    let msg = Message::from_slice(&sighash[..])?;
    context.sign(&msg, secret_key)
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
    use bitcoin::blockdata::opcodes::All;
    use bitcoin::blockdata::script::Builder;
    use bitcoin::blockdata::script::Script;
    use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
    use bitcoin::network::constants::Network;
    use bitcoin::util::address::{Address, Payload};
    use bitcoin::util::hash::Hash160;
    use rand::{Rng, SeedableRng, StdRng};
    use secp256k1::{PublicKey, Secp256k1, SecretKey};
    use std::collections::HashMap;

    use multisig::RedeemScriptBuilder;
    use p2wsh;
    use test_data::secp_gen_keypair_with_rng;
    use TxInRef;

    fn tx_from_hex(s: &str) -> Transaction {
        let bytes = ::bitcoin::util::misc::hex_bytes(s).unwrap();
        ::bitcoin::network::serialize::deserialize(&bytes).unwrap()
    }

    fn tx_to_hex(tx: &Transaction) -> String {
        let bytes = ::bitcoin::network::serialize::serialize(tx).unwrap();
        ::hex::encode(bytes)
    }

    // #[test]
    // fn test_legacy_segwit() {
    //     let mut rng: StdRng = SeedableRng::from_seed([1, 2, 3, 4].as_ref());
    //     let keypair = secp_gen_keypair_with_rng(&mut rng);

    //     let address = Address::p2shwpkh(&keypair.0, Network::Testnet);
    //     println!("address: {}", address.to_string());
    //     let prev_tx = tx_from_hex("02000000012a9c06311b42d79f664881b90913158b6c49509fffe107bd60953b59b846b8b0000000006b483045022100cbe673458173fa3d420a6b27c2a11cda7c48f7e9f68d2fed60bda8faed22ee8d022075c052315d093972809adb449e689cf4b3ed1e2980d4a7fc8f06b0fa1ec0a554012103c40b9af598e607124d6ac9b2922ceff74ec47a11b43f3fe6c45f3e1ab78005e0feffffff028717d1b6650000001976a9142c56deb115ef56c38b08262d6f7abcff56a911a788acb64432030000000017a914572252f3aa0556db8ade2cb90076ad3d7b504eb9872fb81300");
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
    //                 script_pubkey: address.script_pubkey(),
    //             },
    //         ],
    //         witness: Vec::default(),
    //     };
    //     println!("unsigned_tx: {:#?}", transaction);

    //     let mut context = Secp256k1::new();
    //     let pubkey_hash = {
    //         println!("{:?}", address.payload);
    //         if let Payload::ScriptHash(hash) = address.payload {
    //             hash
    //         } else {
    //             panic!("Wrong key type");
    //         }
    //     };
    //     let script_sig = Builder::new().push_slice(&pubkey_hash[..]).into_script().to_v0_p2wsh();
    //     let signature = p2wsh::sign_input(
    //         &mut context,
    //         &script_sig,
    //         TxInRef::new(&transaction, 0),
    //         53626038,
    //         &keypair.1,
    //     ).unwrap();
    //     println!("{:?}", script_sig);
    //     let witness_stack = vec![
    //         pubkey_hash[..].to_vec(),
    //         signature.serialize_der(&context),
    //     ];
    //     transaction.input[0].script_sig = script_sig;
    //     transaction.witness.push(witness_stack);
    //     println!("{:#?}", transaction);
    //     println!("txhex: {}", tx_to_hex(&transaction));
    //     let mut inputs = HashMap::new();
    //     inputs.insert(prev_tx.txid(), prev_tx.clone());
    //     let res = transaction.verify(&inputs);
    //     if let Err(e) = res {
    //         panic!("{}", e);
    //     }
    // }

    #[test]
    fn test_native_segwit() {
        let mut rng: StdRng = SeedableRng::from_seed([1, 2, 3, 4].as_ref());
        let (pk, sk) = secp_gen_keypair_with_rng(&mut rng);

        let address = Address::p2wpkh(&pk, Network::Testnet);
        println!("address: {}", address.to_string());

        let prev_tx = tx_from_hex("020000000001014498f274352cf04cf14cfdc248cf8c1830f6df4d340165a9b604fa1bd8413c6f0100000017160014eee79f335a7bd918e246c8aac27373382fc3d09dfeffffff02b4603c00000000001600144ac4d24af78ef7040738f0dc53f6b59b950fe4be8096980000000000160014284175e336fa10865fb4d1351c9e18e730f5d6f90248304502210092ada6b22b0282dfc51e8732982989160cfa69855917c93d24a1a6b15917e1eb022052f07b6847d03f27840ae4dc0ec7f6f4632103da1766a23be4419069381d8e45012102380804b400e930ed7011f9fa3a47a8dd914cd4dff89f5ac43f848a434e30317ceeb81300");
        println!("prev_tx: {:#?}", prev_tx);

        let pubkey_hash = Hash160::from_data(&pk.serialize());
        let lock_script = Builder::new()
            .push_opcode(All::OP_PUSHBYTES_0)
            .push_slice(&pubkey_hash[..])
            .into_script();
        // Unsigned transaction
        let mut transaction = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![
                TxIn {
                    prev_hash: prev_tx.txid(),
                    prev_index: 1,
                    script_sig: Script::default(),
                    sequence: 0xFFFFFFFE,
                },
            ],
            output: vec![
                TxOut {
                    value: 1000,
                    script_pubkey: lock_script.clone(),
                },
            ],
            witness: Vec::default(),
        };

        let mut context = Secp256k1::new();
        let signature = p2wsh::sign_input(
            &mut context,
            &lock_script,
            TxInRef::new(&transaction, 0),
            10000000,
            &sk,
        ).unwrap();
        let witness_stack = vec![pk.serialize().to_vec(), signature.serialize_der(&context)];
        // Signed transaction
        transaction.witness.push(witness_stack);

        println!("txdata: {:#?}", transaction);
        println!("txhex: {}", tx_to_hex(&transaction));

        let mut inputs = ::std::collections::HashMap::new();
        inputs.insert(prev_tx.txid(), prev_tx.clone());
        let res = transaction.verify(&inputs);
        if let Err(e) = res {
            panic!("{}", e);
        }
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
