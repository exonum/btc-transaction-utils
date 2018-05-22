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

//! Helpers for manipulating with the redeem scripts which used in multisignature transactions.
//!
//! For a more detailed explanation, please visit the official [glossary][glossary].
//!
//! [glossary]: https://bitcoin.org/en/glossary/redeem-script

use std::fmt;
use std::str::FromStr;

use bitcoin::blockdata::opcodes::{All, Class};
use bitcoin::blockdata::script::{read_uint, Builder, Instruction, Script};
use failure;
use hex;
use secp256k1::{PublicKey, Secp256k1};

/// A standard redeem script.
#[derive(Debug, PartialEq, Clone)]
pub struct RedeemScript(pub(crate) Script);

impl RedeemScript {
    /// Tries to parse a raw script as a standard redeem script and returns error
    /// if the script doesn't satisfy `BIP-16` standard.
    pub fn from_script(script: Script) -> Result<RedeemScript, RedeemScriptError> {
        RedeemScriptContent::parse(&Secp256k1::without_caps(), &script)?;
        Ok(RedeemScript(script))
    }

    /// Returns the redeem script content.
    pub fn content(&self) -> RedeemScriptContent {
        RedeemScriptContent::parse(&Secp256k1::without_caps(), &self.0).unwrap()
    }
}

impl fmt::Display for RedeemScript {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl FromStr for RedeemScript {
    type Err = failure::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let script = Script::from(hex::decode(s)?);
        RedeemScript::from_script(script).map_err(Into::into)
    }
}

impl From<&'static str> for RedeemScript {
    fn from(s: &'static str) -> RedeemScript {
        RedeemScript::from_str(s).unwrap()
    }
}

impl From<RedeemScript> for Script {
    fn from(s: RedeemScript) -> Script {
        s.0
    }
}

impl AsRef<Script> for RedeemScript {
    fn as_ref(&self) -> &Script {
        &self.0
    }
}

impl ::serde::Serialize for RedeemScript {
    fn serialize<S>(&self, ser: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: ::serde::Serializer,
    {
        ::serde_str::serialize(self, ser)
    }
}

impl<'de> ::serde::Deserialize<'de> for RedeemScript {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: ::serde::Deserializer<'de>,
    {
        ::serde_str::deserialize(deserializer)
    }
}

/// Redeem script content.
#[derive(Debug, PartialEq)]
pub struct RedeemScriptContent {
    /// The public keys of the participants of this redeem script.
    pub public_keys: Vec<PublicKey>,
    /// The number of signatures required to spend the input which corresponds
    /// to the given redeem script.
    pub quorum: usize,
}

impl RedeemScriptContent {
    /// Tries to fetch redeem script content from the given raw script and returns error
    /// if the script doesn't satisfy `BIP-16` standard.
    pub fn parse(
        context: &Secp256k1,
        script: &Script,
    ) -> Result<RedeemScriptContent, RedeemScriptError> {
        // The lint is false positive in this case.
        #![cfg_attr(feature = "cargo-clippy", allow(needless_pass_by_value))]
        fn read_usize(instruction: Instruction) -> Option<usize> {
            match instruction {
                Instruction::Op(op) => {
                    if let Class::PushNum(num) = op.classify() {
                        Some(num as usize)
                    } else {
                        None
                    }
                }
                Instruction::PushBytes(data) => {
                    let num = read_uint(data, data.len()).ok()?;
                    Some(num as usize)
                }
                _ => None,
            }
        };

        let mut instructions = script.into_iter().peekable();
        // Parses quorum.
        let quorum = instructions
            .next()
            .and_then(read_usize)
            .ok_or_else(|| RedeemScriptError::NoQuorum)?;
        let public_keys = {
            // Parses public keys.
            let mut public_keys = Vec::new();
            while let Some(Instruction::PushBytes(slice)) = instructions.peek().cloned() {
                // HACK: `public_keys_len` can be pushed as `OP_PUSHNUM` or as `OP_PUSHBYTES`
                // but its length cannot be greater than 1.
                if slice.len() == 1 {
                    break;
                }
                // Extracts public key from slice.
                let pub_key = PublicKey::from_slice(context, slice)
                    .map_err(|_| RedeemScriptError::NotStandard)?;
                public_keys.push(pub_key);
                instructions.next();
            }
            // Checks tail.
            let public_keys_len = instructions
                .next()
                .and_then(read_usize)
                .ok_or_else(|| RedeemScriptError::NotStandard)?;
            ensure!(
                public_keys.len() == public_keys_len,
                RedeemScriptError::NotEnoughPublicKeys
            );
            ensure!(
                Some(Instruction::Op(All::OP_CHECKMULTISIG)) == instructions.next(),
                RedeemScriptError::NotStandard
            );
            public_keys
        };
        // Returns parsed script.
        Ok(RedeemScriptContent {
            quorum,
            public_keys,
        })
    }
}

/// The redeem script builder.
#[derive(Debug)]
pub struct RedeemScriptBuilder(RedeemScriptContent);

impl RedeemScriptBuilder {
    /// Creates builder.
    pub fn new() -> RedeemScriptBuilder {
        RedeemScriptBuilder(RedeemScriptContent {
            quorum: 0,
            public_keys: Vec::default(),
        })        
    }

    /// Creates builder for the given quorum value.
    pub fn with_quorum(quorum: usize) -> RedeemScriptBuilder {
        RedeemScriptBuilder(RedeemScriptContent {
            quorum,
            public_keys: Vec::default(),
        })
    }

    /// Creates builder for the given bitcoin public keys.
    pub fn with_public_keys<I: IntoIterator<Item = PublicKey>>(
        public_keys: I,
    ) -> RedeemScriptBuilder {
        let public_keys = public_keys.into_iter().collect::<Vec<_>>();
        let quorum = public_keys.len();

        RedeemScriptBuilder(RedeemScriptContent {
            public_keys,
            quorum,
        })
    }

    /// Adds a new bitcoin public key.
    pub fn public_key<K: Into<PublicKey>>(&mut self, pub_key: K) -> &mut RedeemScriptBuilder {
        self.0.public_keys.push(pub_key.into());
        self
    }

    /// Sets the number of signatures required to spend the input.
    pub fn quorum(&mut self, quorum: usize) -> &mut RedeemScriptBuilder {
        self.0.quorum = quorum;
        self
    }

    /// Finalizes the redeem script building.
    pub fn to_script(&self) -> Result<RedeemScript, RedeemScriptError> {
        let total_count = self.0.public_keys.len();
        // Check preconditions
        ensure!(self.0.quorum > 0, RedeemScriptError::NoQuorum);
        ensure!(total_count != 0, RedeemScriptError::NotEnoughPublicKeys);
        ensure!(
            total_count >= self.0.quorum,
            RedeemScriptError::IncorrectQuorum
        );
        // Construct simple redeem script in form like <1 <pubkey1> <pubkey2> 2 CHECKMULTISIG>
        // See https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wsh
        let mut builder = Builder::default().push_int(self.0.quorum as i64);
        let compressed_keys = self.0.public_keys.iter().map(|key| key.serialize());
        for key in compressed_keys {
            builder = builder.push_slice(key.as_ref());
        }
        let inner = builder
            .push_int(total_count as i64)
            .push_opcode(All::OP_CHECKMULTISIG)
            .into_script();
        Ok(RedeemScript(inner))
    }
}

impl Default for RedeemScriptBuilder {
    fn default() -> Self {
        RedeemScriptBuilder::new()
    }
}

/// Possible errors related to the redeem script.
#[derive(Debug, Copy, Clone, Fail, Display, PartialEq)]
pub enum RedeemScriptError {
    /// Not enough keys for the quorum.
    #[display(fmt = "Not enough keys for the quorum.")]
    IncorrectQuorum,
    /// Quorum was not set during the redeem script building.
    #[display(fmt = "Quorum was not set.")]
    NoQuorum,
    /// Not enough public keys. At least one public key must be specified.
    #[display(fmt = "Not enough public keys. At least one public key must be specified.")]
    NotEnoughPublicKeys,
    /// Given script is not the standard redeem script.
    #[display(fmt = "Given script is not the standard redeem script.")]
    NotStandard,
}

#[cfg(test)]
mod tests {
    use multisig::{RedeemScript, RedeemScriptBuilder, RedeemScriptError};
    use std::str::FromStr;
    use test_data::secp_gen_keypair;

    #[test]
    fn test_redeem_script_builder_no_quorum() {
        assert_eq!(
            RedeemScriptBuilder::with_quorum(0).to_script(),
            Err(RedeemScriptError::NoQuorum)
        );
    }

    #[test]
    fn test_redeem_script_builder_not_enough_keys() {
        assert_eq!(
            RedeemScriptBuilder::with_quorum(3).to_script(),
            Err(RedeemScriptError::NotEnoughPublicKeys)
        );
    }

    #[test]
    fn test_redeem_script_builder_incorrect_quorum() {
        let keys = vec![secp_gen_keypair().0, secp_gen_keypair().0];
        assert_eq!(
            RedeemScriptBuilder::with_public_keys(keys)
                .quorum(3)
                .to_script(),
            Err(RedeemScriptError::IncorrectQuorum)
        );
    }

    #[test]
    fn test_redeem_script_from_hex_standard_short() {
        RedeemScript::from(
            "5321027db7837e51888e94c094703030d162c682c8dba312210f44ff440fbd5e5c24732102bdd272891c9\
             e4dfc3962b1fdffd5a59732019816f9db4833634dbdaf01a401a52103280883dc31ccaee34218819aaa24\
             5480c35a33acd91283586ff6d1284ed681e52103e2bc790a6e32bf5a766919ff55b1f9e9914e13aed84f5\
             02c0e4171976e19deb054ae",
        );
    }

    #[test]
    fn test_redeem_script_from_hex_standard_long() {
        RedeemScript::from(
            "5c21031cf96b4fef362af7d86ee6c7159fa89485730dac8e3090163dd0c282dbc84f2221028839757bba9\
             bdf46ae553c124479e5c3ded609495f3e93e88ab23c0f559e8be521035c70ffb21d1b454ec650e511e76f6\
             bd3fe76f49c471522ee187abac8d0131a18210234acd7dee22bc23688beed0c7e42c0930cfe024204b7298\
             b0b59d0e76a46476521033897e8dd88ee04cb42b69838c3167471880da23944c10eb9f67de2b5ca32a9d12\
             1027a715cf0aeec55482c1d42bfeb75c8f54348ec8b0ca0f9b535ed50a739b8ad632103a2be0380e248ec3\
             6401e99680e0fb4f8c03a0a5e00d5dda107aee6cba77b639521038bdb47da82981776e8b0e5d4175f27930\
             339a32e77ee7052ec51a1f2f0a46e88210312c4fb516caeb5eaec8ffdeecd4a507b69d6808651ae02a4a61\
             165cc56bfe55121039e021ca4d7969e5db181e0905b9baab2afe395e84587b588a6b039207c91135521025\
             9c9f752846c7bd514a042d53ea305f2d4ca7873cb21937dc6b5e82afbb8fb922102c52c3dc6e080ea4e74b\
             a2e6797548bd79a692a01baeba1c757a18fd0ef519fb42102f5010ab66dd7a8dc06caefeceb9bb7e6e42c5\
             d4afdab527a2f02d87b758920612103efbcec8bcc6ea4e58b44214b14eae2677399c28df8bb81fcd120cb4\
             c88ce3bd92103e88aa50f0d7f43cb3171a69675385f130c6abafacadde87fc84d5a194da5ad9c21025ed88\
             603b59882c3ec6ef43c0b33ac9db315ecca8e7073e60d9b56145fc0efa02103643277862c4a8ab27913e3d\
             2bcea109b6637c7454a03410aac8ccad445e81a502103380785c3e1c105e366ff445227cdde68e6a6461d6\
             793a1437db847ecd04129dc0112ae",
        );
    }

    #[test]
    fn test_redeem_script_from_hex_not_standard() {
        assert!(
            "0020e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                .parse::<RedeemScript>()
                .is_err()
        );
    }

    #[test]
    fn test_redeem_script_convert_hex() {
        let script = RedeemScriptBuilder::with_quorum(3)
            .public_key(secp_gen_keypair().0)
            .public_key(secp_gen_keypair().0)
            .public_key(secp_gen_keypair().0)
            .public_key(secp_gen_keypair().0)
            .to_script()
            .unwrap();
        let string = script.to_string();
        let script2 = RedeemScript::from_str(&string).unwrap();
        assert_eq!(script, script2);
    }
}
