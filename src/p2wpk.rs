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

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::TxIn;
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::hash::Sha256dHash;
use secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use {InputSignature, TxInRef, TxOutValue};
use sign;

#[derive(Debug)]
pub struct InputSigner {
    context: Secp256k1,
    public_key: PublicKey,
    network: Network,
}

impl InputSigner {
    pub fn new(public_key: PublicKey, network: Network) -> InputSigner {
        InputSigner {
            context: Secp256k1::new(),
            public_key,
            network,
        }
    }

    pub fn signature_hash<'a, 'b, V: Into<TxOutValue<'b>>>(
        &mut self,
        txin: TxInRef<'a>,
        value: V,
    ) -> Sha256dHash {
        sign::signature_hash(txin, &self.witness_script(), value)
    }

    pub fn sign_input<'a, 'b, V: Into<TxOutValue<'b>>>(
        &mut self,
        txin: TxInRef<'a>,
        value: V,
        secret_key: &SecretKey,
    ) -> Result<InputSignature, secp256k1::Error> {
        let script = self.witness_script();
        sign::sign_input(&mut self.context, txin, &script, value, secret_key)
    }

    pub fn verify_input<'a, 'b, V, S>(
        &self,
        txin: TxInRef<'a>,
        value: V,
        public_key: &PublicKey,
        signature: S,
    ) -> Result<(), secp256k1::Error>
    where
        V: Into<TxOutValue<'b>>,
        S: AsRef<[u8]>,
    {
        sign::verify_input_signature(
            &self.context,
            txin,
            &self.witness_script(),
            value,
            public_key,
            signature.as_ref(),
        )
    }

    pub fn spend_input(&self, input: &mut TxIn, signature: InputSignature) {
        input.witness = self.witness_data(signature.into());
    }

    pub fn witness_data(&self, signature: Vec<u8>) -> Vec<Vec<u8>> {
        vec![signature, self.public_key.serialize().to_vec()]
    }

    fn witness_script(&self) -> Script {
        Address::p2pkh(&self.public_key, self.network).script_pubkey()
    }
}

pub fn address(pk: &PublicKey, network: Network) -> Address {
    Address::p2wpkh(pk, network)
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::opcodes::All;
    use bitcoin::blockdata::script::{Builder, Script};
    use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
    use bitcoin::network::constants::Network;
    use rand::{SeedableRng, StdRng};

    use p2wpk;
    use test_data::{secp_gen_keypair_with_rng, tx_from_hex};
    use TxInRef;

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
                    witness: Vec::default(),
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
        };
        // Make signature
        let mut signer = p2wpk::InputSigner::new(pk, Network::Testnet);
        let signature = signer
            .sign_input(TxInRef::new(&transaction, 0), &prev_tx, &sk)
            .unwrap();
        // Verify signature
        signer
            .verify_input(
                TxInRef::new(&transaction, 0),
                &prev_tx,
                &pk,
                signature.content(),
            )
            .expect("Signature should be correct");
        // Signed transaction
        signer.spend_input(&mut transaction.input[0], signature);
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
