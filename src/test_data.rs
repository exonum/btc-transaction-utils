use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::serialize;
use rand::{self, Rng};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

pub fn secp_gen_keypair_with_rng<R: Rng>(rng: &mut R) -> (PublicKey, SecretKey) {
    let context = Secp256k1::new();
    let sk = SecretKey::new(&context, rng);
    let pk = PublicKey::from_secret_key(&context, &sk).unwrap();
    (pk, sk)
}

pub fn secp_gen_keypair() -> (PublicKey, SecretKey) {
    let mut rng = rand::thread_rng();
    secp_gen_keypair_with_rng(&mut rng)
}

pub fn tx_from_hex(s: &str) -> Transaction {
    let bytes = ::bitcoin::util::misc::hex_bytes(s).unwrap();
    serialize::deserialize(&bytes).unwrap()
}
