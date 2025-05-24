// Offline dictionary attack on simplified SRP

use crate::{generate_modexp_keypair, Hasher, HmacSha256, ModExpKeyPair, Sha256};

use num_bigint::BigUint;
use rand::rngs::StdRng;

pub struct SimplifiedSrpClient {
    username: String,
    password: String,
    keys: ModExpKeyPair,
}

impl SimplifiedSrpClient {
    pub fn new(
        username: String,
        password: String,
        g: BigUint,
        n_prime: BigUint,
        mut rng: StdRng,
    ) -> Self {
        let keys = generate_modexp_keypair(n_prime, g, &mut rng);
        Self {
            username,
            password,
            keys,
        }
    }

    pub fn public_id(&self) -> (String, BigUint) {
        (self.username.clone(), self.keys.pub_key.clone())
    }

    pub fn session_mac(&self, big_b: &BigUint, salt: &[u8; 16], u: &u128) -> [u8; 32] {
        let session_key = self.compute_session_key(big_b, salt, u);
        HmacSha256::digest_message(&session_key, salt)
    }

    fn compute_session_key(&self, big_b: &BigUint, salt: &[u8; 16], u: &u128) -> [u8; 32] {
        let data = [salt, self.password.as_bytes()].concat();
        let x_h = Sha256::digest_message(&data);
        let x = BigUint::from_bytes_be(&x_h);
        let exponent = &self.keys.priv_key + u * x;
        let big_s = big_b.modpow(&exponent, &self.keys.p);
        Sha256::digest_message(&big_s.to_bytes_be())
    }
}

pub fn simplified_secure_remote_password_mitm_attack(
    client: &SimplifiedSrpClient,
    g: &BigUint,
    n_prime: &BigUint,
    dictionary_words: impl Iterator<Item = String>,
) -> Result<String, String> {
    // Posing as a server, the MITM attacker receives public key and ID from
    // client.
    let (_, big_a) = client.public_id();

    let salt = [1u8; 16];
    let small_b = BigUint::from(1u64);
    let big_b = g.modpow(&small_b, n_prime);
    let u = 1u128;

    // The client sends back the MAC.
    let session_mac = client.session_mac(&big_b, &salt, &u);

    // As the idea of SRP is that the client and server can both derive the
    // same session key, the MITM can try to calculate the key (using the
    // server-side process) by running a dictionary attack on the password.
    //
    // Recall how the server would usually calculate the session key K:
    //   x = SHA256(salt|password)  (the MITM uses a guess for the password)
    //   v = g ** x mod N
    //   S = (A * v ** u) ** b mod N
    //   K = SHA256(S)
    //
    // An attacker can simplify things a bit by setting u := 1 and b := 1:
    //   S = (A * v) mod N
    for password_candidate in dictionary_words {
        let data = [&salt, password_candidate.as_bytes()].concat();
        let x_h = Sha256::digest_message(&data);
        let x = BigUint::from_bytes_be(&x_h);
        let v = g.modpow(&x, n_prime);
        let big_s = (&big_a * v) % n_prime;
        let big_k = Sha256::digest_message(&big_s.to_bytes_be());
        let candidate_mac = HmacSha256::digest_message(&big_k, &salt);
        if candidate_mac == session_mac {
            return Ok(password_candidate.to_string());
        }
    }
    Err("did not crack password".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_traits::Num;
    use rand::SeedableRng;

    use std::io::BufRead;

    fn read_lines<P>(
        filename: P,
    ) -> std::io::Result<std::io::Lines<std::io::BufReader<std::fs::File>>>
    where
        P: AsRef<std::path::Path>,
    {
        let file = std::fs::File::open(filename)?;
        Ok(std::io::BufReader::new(file).lines())
    }

    #[test]
    fn simplified_secure_remote_password_mitm_attack_recovers_client_key() {
        let g = BigUint::from(2u64);
        let p = BigUint::from_str_radix(
            "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024\
            e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd\
            3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec\
            6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f\
            24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361\
            c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552\
            bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff\
            fffffffffffff",
            16,
        )
        .unwrap();
        // This is not a particularly realistic password, but I feel like this
        // exercise is more about understanding how to attack SRP than it is
        // about performing effective dictionary attacks.
        let client_password = "aardvark".to_string();
        let client = SimplifiedSrpClient::new(
            "Alice".to_string(),
            client_password.clone(),
            g.clone(),
            p.clone(),
            StdRng::from_seed([101; 32]),
        );
        let dict_words = read_lines("./data/set05/cain_wordlist.txt")
            .unwrap()
            .map(|x| x.unwrap());

        let result = simplified_secure_remote_password_mitm_attack(&client, &g, &p, dict_words);

        assert_eq!(result.unwrap(), client_password);
    }
}
