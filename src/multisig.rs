use std::fmt;
use std::str::FromStr;

use bitcoin::blockdata::opcodes::All;
use bitcoin::blockdata::script::{Builder, Script};
use hex;
use secp256k1::PublicKey;

#[derive(Debug, PartialEq)]
pub struct RedeemScript(pub(crate) Script);

impl RedeemScript {
    fn from_script(script: Script) -> Result<RedeemScript, RedeemScriptError> {
        Ok(RedeemScript(script))
    }
}

impl fmt::Display for RedeemScript {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl FromStr for RedeemScript {
    type Err = hex::FromHexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let script = Script::from(hex::decode(s)?);
        // TODO check redeem_script structure
        Ok(RedeemScript::from_script(script).unwrap())
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

#[derive(Debug)]
pub struct RedeemScriptBuilder {
    public_keys: Vec<PublicKey>,
    quorum: usize,
}

impl RedeemScriptBuilder {
    pub fn with_quorum(quorum: usize) -> RedeemScriptBuilder {
        RedeemScriptBuilder {
            quorum,
            public_keys: Vec::default(),
        }
    }

    pub fn with_public_keys<I: IntoIterator<Item = PublicKey>>(
        public_keys: I,
    ) -> RedeemScriptBuilder {
        let public_keys = public_keys.into_iter().collect::<Vec<_>>();
        let quorum = public_keys.len();

        RedeemScriptBuilder {
            public_keys,
            quorum,
        }
    }

    pub fn public_key<K: Into<PublicKey>>(&mut self, pub_key: K) -> &mut RedeemScriptBuilder {
        self.public_keys.push(pub_key.into());
        self
    }

    pub fn quorum(&mut self, quorum: usize) -> &mut RedeemScriptBuilder {
        self.quorum = quorum;
        self
    }

    pub fn to_script(&mut self) -> Result<RedeemScript, RedeemScriptError> {
        let total_count = self.public_keys.len();
        // Check preconditions
        ensure!(self.quorum > 0, RedeemScriptError::NoQuorum);
        ensure!(total_count > 1, RedeemScriptError::NotEnoughPublicKeys);
        ensure!(
            total_count >= self.quorum,
            RedeemScriptError::IncorrectQuorum
        );
        // Construct simple redeem script in form like <1 <pubkey1> <pubkey2> 2 CHECKMULTISIG>
        // See https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#p2wsh
        let mut builder = Builder::default().push_int(self.quorum as i64);
        let compressed_keys = self.public_keys.iter().map(|key| key.serialize());
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
    fn test_redeem_script_from_hex() {
        RedeemScript::from(
            "5321027db7837e51888e94c094703030d162c682c8dba312210f44ff440fbd5e5c24732102bdd272891c9\
             e4dfc3962b1fdffd5a59732019816f9db4833634dbdaf01a401a52103280883dc31ccaee34218819aaa24\
             5480c35a33acd91283586ff6d1284ed681e52103e2bc790a6e32bf5a766919ff55b1f9e9914e13aed84f5\
             02c0e4171976e19deb054ae",
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
