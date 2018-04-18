use std::fmt;
use std::str::FromStr;

use bitcoin::blockdata::opcodes::{All, Class};
use bitcoin::blockdata::script::{Builder, Instruction, Script};
use failure;
use hex;
use secp256k1::{PublicKey, Secp256k1};

#[derive(Debug, PartialEq)]
pub struct RedeemScript(pub(crate) Script);

impl RedeemScript {
    pub fn from_script(script: Script) -> Result<RedeemScript, RedeemScriptError> {
        RedeemScriptLayout::parse(&Secp256k1::without_caps(), &script)?;
        Ok(RedeemScript(script))
    }

    pub fn info(&self) -> RedeemScriptLayout {
        RedeemScriptLayout::parse(&Secp256k1::without_caps(), &self.0).unwrap()
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

#[derive(Debug, PartialEq)]
pub struct RedeemScriptLayout {
    pub public_keys: Vec<PublicKey>,
    pub quorum: usize,
}

impl RedeemScriptLayout {
    pub fn parse(
        context: &Secp256k1,
        script: &Script,
    ) -> Result<RedeemScriptLayout, RedeemScriptError> {
        fn read_usize<'a>(instruction: Instruction<'a>) -> Option<usize> {
            if let Instruction::Op(op) = instruction {
                if let Class::PushNum(num) = op.classify() {
                    Some(num as usize)
                } else {
                    None
                }
            } else {
                None
            }
        };

        let mut instructions = script.into_iter().peekable();
        // parse quorum
        let quorum = instructions
            .next()
            .and_then(read_usize)
            .ok_or_else(|| RedeemScriptError::NoQuorum)?;
        let public_keys = {
            // Parse public keys
            let mut public_keys = Vec::new();
            while let Some(Instruction::PushBytes(slice)) = instructions.peek().cloned() {
                let pub_key = PublicKey::from_slice(context, slice)
                    .map_err(|_| RedeemScriptError::NotStandard)?;
                public_keys.push(pub_key);
                instructions.next();
            }
            // Check tail
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
        // Return parsed script
        Ok(RedeemScriptLayout {
            quorum,
            public_keys,
        })
    }
}

#[derive(Debug)]
pub struct RedeemScriptBuilder(RedeemScriptLayout);

impl RedeemScriptBuilder {
    pub fn with_quorum(quorum: usize) -> RedeemScriptBuilder {
        RedeemScriptBuilder(RedeemScriptLayout {
            quorum,
            public_keys: Vec::default(),
        })
    }

    pub fn with_public_keys<I: IntoIterator<Item = PublicKey>>(
        public_keys: I,
    ) -> RedeemScriptBuilder {
        let public_keys = public_keys.into_iter().collect::<Vec<_>>();
        let quorum = public_keys.len();

        RedeemScriptBuilder(RedeemScriptLayout {
            public_keys,
            quorum,
        })
    }

    pub fn public_key<K: Into<PublicKey>>(&mut self, pub_key: K) -> &mut RedeemScriptBuilder {
        self.0.public_keys.push(pub_key.into());
        self
    }

    pub fn quorum(&mut self, quorum: usize) -> &mut RedeemScriptBuilder {
        self.0.quorum = quorum;
        self
    }

    pub fn to_script(&mut self) -> Result<RedeemScript, RedeemScriptError> {
        let total_count = self.0.public_keys.len();
        // Check preconditions
        ensure!(self.0.quorum > 0, RedeemScriptError::NoQuorum);
        ensure!(total_count > 1, RedeemScriptError::NotEnoughPublicKeys);
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

#[derive(Debug, Copy, Clone, Fail, Display, PartialEq)]
pub enum RedeemScriptError {
    #[display(fmt = "Not enough keys for the quorum.")]
    IncorrectQuorum,
    #[display(fmt = "Quorum is not set.")]
    NoQuorum,
    #[display(fmt = "Must specify at least two public keys.")]
    NotEnoughPublicKeys,
    #[display(fmt = "Given script is not standard")]
    NotStandard,
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use multisig::{RedeemScript, RedeemScriptBuilder, RedeemScriptError};
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
    fn test_redeem_script_from_hex_standard() {
        RedeemScript::from(
            "5321027db7837e51888e94c094703030d162c682c8dba312210f44ff440fbd5e5c24732102bdd272891c9\
             e4dfc3962b1fdffd5a59732019816f9db4833634dbdaf01a401a52103280883dc31ccaee34218819aaa24\
             5480c35a33acd91283586ff6d1284ed681e52103e2bc790a6e32bf5a766919ff55b1f9e9914e13aed84f5\
             02c0e4171976e19deb054ae",
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
