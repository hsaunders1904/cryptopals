// Break SRP with a zero key

use num_bigint::BigUint;

use crate::{Hasher, HmacSha256, Sha256, SrpPasswordVerificationResponse, SrpServer};

pub fn zero_key_secure_remote_password_attack(
    user_id: &str,
    server: &SrpServer,
) -> Result<SrpPasswordVerificationResponse, String> {
    // Client sends the ID of the user they want to hack to the server.
    let big_i = user_id;

    // Server sends salt and public key to client.
    let (salt, _) = server.send_user_key(big_i)?;

    // To force the server to authenticate, the attacker sends a public key 'A'
    // equal to 0 to the server.
    // Consider how the server computes the session key:
    //   K = Sha256(S), where
    //   S = (A * v^u)^b mod N
    //     = 0                 (as anything times 0 is 0!).
    // Hence the attacker can easily reproduce the session key:
    //   K = Sha256(0)
    //
    // You can see that the attacker can also send any multiple of N as their
    // public key and get the same session key, as the modulus operation in the
    // derivation of S will still result in S = 0.
    let spoofed_big_a = BigUint::from(0u64);
    let forced_key = Sha256::digest_message(&spoofed_big_a.to_bytes_be());
    let forced_mac = HmacSha256::digest_message(&forced_key, &salt);

    server.validate_session(big_i, &spoofed_big_a, &forced_mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_bigint::BigUint;
    use num_traits::Num;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn srp_broken_with_0_key() {
        let g = BigUint::from(2u64);
        let k = BigUint::from(3u64);
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
        let mut server = SrpServer::new(
            g.clone(),
            p.clone(),
            k.clone(),
            StdRng::from_seed([102; 32]),
        );
        server.register_user("Alice", "Very-Secure-Password86");

        let result = zero_key_secure_remote_password_attack("Alice", &server).unwrap();

        assert_eq!(result, SrpPasswordVerificationResponse::Ok);
    }
}
