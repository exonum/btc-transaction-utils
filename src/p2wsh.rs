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

//! A native `P2WSH` input signer.

use bitcoin::blockdata::transaction::TxIn;
use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::hash::Sha256dHash;
use secp256k1::{self, PublicKey, Secp256k1, SecretKey};

use multisig::RedeemScript;
use sign;
use {InputSignature, TxInRef, UnspentTxOutValue};

/// Creates a bitcoin address for the corresponding redeem script and the bitcoin network.
pub fn address(redeem_script: &RedeemScript, network: Network) -> Address {
    Address::p2wsh(&redeem_script.0, network)
}

/// An input signer.
#[derive(Debug)]
pub struct InputSigner {
    context: Secp256k1,
    script: RedeemScript,
}

impl InputSigner {
    /// Creates an input signer for the given redeem script.
    pub fn new(script: RedeemScript) -> InputSigner {
        InputSigner {
            context: Secp256k1::new(),
            script,
        }
    }

    /// Computes the [`BIP-143`][bip-143] compliant sighash for a [`SIGHASH_ALL`][sighash_all]
    /// signature for the given input.
    ///
    /// [bip-143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    /// [sighash_all]: https://bitcoin.org/en/developer-guide#signature-hash-types
    pub fn signature_hash<'a, 'b, V: Into<UnspentTxOutValue<'b>>>(
        &mut self,
        txin: TxInRef<'a>,
        value: V,
    ) -> Sha256dHash {
        sign::signature_hash(txin, &self.script.0, value)
    }

    /// Computes the [`BIP-143`][bip-143] compliant signature for the given input.
    /// Under the hood this method signs [`sighash`][signature-hash] for the given input by the
    /// given secret key.
    ///
    /// [bip-143]: https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki
    /// [signature-hash]: struct.InputSigner.html#signature_hash
    pub fn sign_input<'a, 'b, V: Into<UnspentTxOutValue<'b>>>(
        &mut self,
        txin: TxInRef<'a>,
        value: V,
        secret_key: &SecretKey,
    ) -> Result<InputSignature, secp256k1::Error> {
        sign::sign_input(&mut self.context, txin, &self.script.0, value, secret_key)
    }

    /// Checks correctness of the signature for the given input.
    pub fn verify_input<'a, 'b, V, S>(
        &self,
        txin: TxInRef<'a>,
        value: V,
        public_key: &PublicKey,
        signature: S,
    ) -> Result<(), secp256k1::Error>
    where
        V: Into<UnspentTxOutValue<'b>>,
        S: AsRef<[u8]>,
    {
        sign::verify_input_signature(
            &self.context,
            txin,
            &self.script.0,
            value,
            public_key,
            signature.as_ref(),
        )
    }

    /// Collects the given input signatures into the witness data for the given transaction input. Thus, the input becomes spent.
    pub fn spend_input<I: IntoIterator<Item = InputSignature>>(
        &self,
        input: &mut TxIn,
        signatures: I,
    ) {
        input.witness = self.witness_data(signatures.into_iter().map(Into::into));
    }

    fn witness_data<I: IntoIterator<Item = Vec<u8>>>(&self, signatures: I) -> Vec<Vec<u8>> {
        let mut witness_stack = vec![Vec::default()];
        witness_stack.extend(signatures);
        witness_stack.push(self.script.0.clone().into_vec());
        witness_stack
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::blockdata::opcodes::All;
    use bitcoin::blockdata::script::{Builder, Script};
    use bitcoin::blockdata::transaction::{Transaction, TxIn, TxOut};
    use bitcoin::network::constants::Network;
    use rand::{SeedableRng, StdRng};

    use TxInRef;
    use multisig::RedeemScriptBuilder;
    use p2wsh;
    use test_data::{btc_tx_from_hex, secp_gen_keypair_with_rng};

    #[test]
    fn test_multisig_native_segwit() {
        let total_count = 18;
        let quorum = 12;

        let mut rng: StdRng = SeedableRng::from_seed([1, 2, 3, 4].as_ref());
        let keypairs = (0..total_count)
            .into_iter()
            .map(|_| secp_gen_keypair_with_rng(&mut rng))
            .collect::<Vec<_>>();

        let redeem_script = RedeemScriptBuilder::with_public_keys(keypairs.iter().map(|x| x.0))
            .quorum(quorum)
            .to_script()
            .unwrap();

        let prev_tx = btc_tx_from_hex(
            "02000000000101f8c16000cc59f9505046303944d42a6c264a322f80b46bb436115b6e306ba9950000000\
             000feffffff02f07dc81600000000160014f65eb9d72a8475dd8e26f4fa748796e211aa88691027000000\
             00000022002001fb25c3db04ca5580da43a7d38dd994650d9aa6d6ee075b4578388deed338ed024730440\
             2206b5f211cd7f9b89e80c734b61113c33f437ba153e7ba6bc275eed857e54fcb260220038562e88b805f\
             0cdfd4873ab3579d52268babe6af9c49086c00343187cdf28a012103979dff5cd9045f4b6fa454d2bc535\
             7586a85d4789123df45f83522963d94e3217fb91300",
        );
        assert_eq!(
            prev_tx.output[1].script_pubkey,
            p2wsh::address(&redeem_script, Network::Testnet).script_pubkey()
        );

        // Unsigned transaction.
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
                        .push_slice(b"Hello Exonum with multisig!")
                        .into_script(),
                },
            ],
        };

        // Signs transaction.
        let mut signer = p2wsh::InputSigner::new(redeem_script.clone());
        let signatures = keypairs[0..quorum]
            .iter()
            .map(|keypair| {
                let txin = TxInRef::new(&transaction, 0);
                let signature = signer.sign_input(txin, &prev_tx, &keypair.1).unwrap();
                signer
                    .verify_input(txin, &prev_tx, &keypair.0, signature.content())
                    .unwrap();
                signature
            })
            .collect::<Vec<_>>();
        signer.spend_input(&mut transaction.input[0], signatures);
        // Checks output.
        assert_eq!(
            transaction,
            btc_tx_from_hex(
                "02000000000101c4eb8102889b009f55cca8a1a07f3ea388843d6afa4bd77990d2190bb9248f92010\
                 0000000ffffffff0100000000000000001d6a1b48656c6c6f2045786f6e756d2077697468206d756c\
                 7469736967210e0047304402200fbebae9eabf9b2c33bb6112a821317e0f676c44aa7814d145bb604\
                 5bfb77bce022044df3307ce0a1a70d1d0b62432dba42d7e4aeaabe0290f5474509658a1196e330147\
                 30440220494baff1971f5a9b3ec63015466551a0acc185de8fc44228e3c4726550749abe02203d72b\
                 5032b8b88d3294b547b7bfe4e82f75d4e8268e64f5751b65ba0cc66efbb01473044022058eee8c7fb\
                 b81a471e4c71f7722e933297dfeaccc9fa86cac2a3aa7f0a78c17b022050fd3566953cb433471284c\
                 061285f51a118c51a46d62d92fe7c7d89434dc8f30147304402203c1e6392beda5bd01cf3ce8e4b78\
                 f6e21687113137a791739f53ba5459171d5302200362ee0d9981797b89133c5ade65f9bcb46af169a\
                 fea15d303d1b55eabbdedfb01483045022100f4be0af94fb9fa74893439378e836b3e4b81aeb0edd4\
                 7769d0177c1db6f37fdb02202652bcea0a3e0b2df754354c45d4fe349c5fd44e47e98daec9202d8dd\
                 2bb89490147304402204238210b1719108ea514ed59d3a56136ddb1cd3c99227156db45aa583881b2\
                 c3022039cfc5801d9b785ea544651dcf22e39c2ed6f3f4b3f5bda4858236404934285a01473044022\
                 02741c8bbffb09432276d80fcfafb6e3c294a635fb09f27002084a1086fab19e202203bdaec272515\
                 9c9d9a7126525345ae51838d0052acdba6b070fba096aa46680e01473044022032894b2a78f9f0cd9\
                 5543f9d56a233a469ce2448f994bd966ca0ff38b18eac880220101689725199b25946f19eed1437d4\
                 8f6f6714c062c22ce94a6e222e4fe01b6c01483045022100acee27e70ac1dbd4fb07e25bb3095cba8\
                 58c2cee8169ac55d4ee8da10a00742b02200b5a6ecdf5d375d561a53862e792136c10ed0287ffc9a8\
                 de52f45ab1fc3dbf770147304402204f3778dae6b8166bd667a59c8d30b9eb3b8572a2aa3c1197873\
                 94ce4bbb58ae5022064b4df41b2de281082fde6b2d1a4e25212c10f6011bbb048d1c54ddb91e33dfa\
                 01473044022060873642a76f8dfc36afcb5bd15a07da341ab0407f880e6a99d9ece22bca825902207\
                 cfb5ce2fea244355d0c9e589e91f626b1ba90ebfe5eff33a2e8e5706f5f36970147304402201ffe90\
                 90290e0a1a3cad7bc276a35da219528dd1b82c25b1a9ed190453925a59022004caee4a37ffe322fd5\
                 e45f25d42c65565be70a326edb38ba6d6f1a60332154e01fd68025c21031cf96b4fef362af7d86ee6\
                 c7159fa89485730dac8e3090163dd0c282dbc84f2221028839757bba9bdf46ae553c124479e5c3ded\
                 609495f3e93e88ab23c0f559e8be521035c70ffb21d1b454ec650e511e76f6bd3fe76f49c471522ee\
                 187abac8d0131a18210234acd7dee22bc23688beed0c7e42c0930cfe024204b7298b0b59d0e76a464\
                 76521033897e8dd88ee04cb42b69838c3167471880da23944c10eb9f67de2b5ca32a9d121027a715c\
                 f0aeec55482c1d42bfeb75c8f54348ec8b0ca0f9b535ed50a739b8ad632103a2be0380e248ec36401\
                 e99680e0fb4f8c03a0a5e00d5dda107aee6cba77b639521038bdb47da82981776e8b0e5d4175f2793\
                 0339a32e77ee7052ec51a1f2f0a46e88210312c4fb516caeb5eaec8ffdeecd4a507b69d6808651ae0\
                 2a4a61165cc56bfe55121039e021ca4d7969e5db181e0905b9baab2afe395e84587b588a6b039207c\
                 911355210259c9f752846c7bd514a042d53ea305f2d4ca7873cb21937dc6b5e82afbb8fb922102c52\
                 c3dc6e080ea4e74ba2e6797548bd79a692a01baeba1c757a18fd0ef519fb42102f5010ab66dd7a8dc\
                 06caefeceb9bb7e6e42c5d4afdab527a2f02d87b758920612103efbcec8bcc6ea4e58b44214b14eae\
                 2677399c28df8bb81fcd120cb4c88ce3bd92103e88aa50f0d7f43cb3171a69675385f130c6abafaca\
                 dde87fc84d5a194da5ad9c21025ed88603b59882c3ec6ef43c0b33ac9db315ecca8e7073e60d9b561\
                 45fc0efa02103643277862c4a8ab27913e3d2bcea109b6637c7454a03410aac8ccad445e81a502103\
                 380785c3e1c105e366ff445227cdde68e6a6461d6793a1437db847ecd04129dc0112ae00000000"
            )
        );
        // Verifies first signature.
        let public_key = redeem_script.content().public_keys[0];
        let signature = &transaction.input[0].witness[1];
        let signer = p2wsh::InputSigner::new(redeem_script);
        signer
            .verify_input(
                TxInRef::new(&transaction, 0),
                &prev_tx,
                &public_key,
                &signature.split_last().unwrap().1,
            )
            .expect("Signature should be correct");
    }
}
