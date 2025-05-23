use crate::{generate_modexp_keypair, HmacSha1, ModExpKeyPair, Sha256};

use num_bigint::BigUint;
use rand::rngs::StdRng;

#[derive(Debug, Clone)]
pub struct SrpClient {
    username: String,
    password: String,
    k: BigUint,
    keys: ModExpKeyPair,
}

impl SrpClient {
    pub fn new(
        username: String,
        password: String,
        g: BigUint,
        n_prime: BigUint,
        k: BigUint,
        mut rng: StdRng,
    ) -> Self {
        let keys = generate_modexp_keypair(n_prime, g, &mut rng);
        Self {
            username,
            password,
            k,
            keys,
        }
    }

    pub fn public_id(&self) -> (String, BigUint) {
        (self.username.clone(), self.keys.pub_key.clone())
    }

    pub fn username(&self) -> String {
        self.username.clone()
    }

    pub fn password(&self) -> String {
        self.password.clone()
    }

    pub fn session_mac(&self, big_b: &BigUint, salt: [u8; 16]) -> [u8; 20] {
        let session_key = self.compute_session(big_b, salt);
        HmacSha1::digest_message(&session_key, &salt)
    }

    fn compute_session(&self, big_b: &BigUint, salt: [u8; 16]) -> [u8; 32] {
        let u_h = Sha256::digest_message(
            &[self.keys.pub_key.to_bytes_be(), big_b.to_bytes_be()].concat(),
        );
        let u = BigUint::from_bytes_be(&u_h);
        let x_h = Sha256::digest_message(&[&salt, self.password.as_bytes()].concat());
        let x = BigUint::from_bytes_be(&x_h);
        let gx = self.keys.g.modpow(&x, &self.keys.p);
        let kgx = (&self.k * gx) % &self.keys.p;
        let base = (big_b + &self.keys.p - kgx) % &self.keys.p;
        let exp = (&self.keys.priv_key + &u * x) % &self.keys.p;
        let big_s = base.modpow(&exp, &self.keys.p);
        Sha256::digest_message(&big_s.to_bytes_be())
    }
}
