use rand::{self, Rng};
use secp256k1::{Secp256k1, SecretKey, PublicKey};

pub fn secp_gen_keypair_with_rng<R: Rng>(rng: &mut R) -> (PublicKey, SecretKey) {
    let context = Secp256k1::new();
    let sk = SecretKey::new(&context,rng);
    let pk = PublicKey::from_secret_key(&context, &sk).unwrap();
    (pk, sk)    
}

pub fn secp_gen_keypair() -> (PublicKey, SecretKey) {
    let mut rng = rand::thread_rng();
    secp_gen_keypair_with_rng(&mut rng)
}
