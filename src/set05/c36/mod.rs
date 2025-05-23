// Implement Secure Remote Password (SRP)
mod client;
mod server;

pub use client::SrpClient;
pub use server::{SrpPasswordVerificationResponse, SrpServer};

pub fn secure_remote_password(
    client: SrpClient,
    server: SrpServer,
) -> Result<SrpPasswordVerificationResponse, String> {
    // Client (user) sends ID and public key to server.
    let (big_i, big_a) = client.public_id();

    // Server sends salt and public key to client.
    let (salt, big_b) = server.send_user_key(&big_i)?;

    // Client computes the session MAC.
    let client_mac = client.session_mac(&big_b, salt);

    // Client sends MAC to server, which computes a (hopefully) equal session
    // key and verifies the MAC.
    server.validate_session(&big_i, &big_a, &client_mac)
}

#[cfg(test)]
mod tests {
    use super::*;

    use num_bigint::BigUint;
    use num_traits::Num;
    use rand::{rngs::StdRng, SeedableRng};

    #[test]
    fn srp_ok_for_registered_user() {
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

        let client = SrpClient::new(
            "Alice".to_string(),
            "very_$ecure".to_string(),
            g.clone(),
            p.clone(),
            k.clone(),
            StdRng::from_seed([101; 32]),
        );
        let mut server = SrpServer::new(
            g.clone(),
            p.clone(),
            k.clone(),
            StdRng::from_seed([102; 32]),
        );
        server.register_user(&client.username(), &client.password());

        let result = secure_remote_password(client, server).unwrap();

        assert_eq!(result, SrpPasswordVerificationResponse::Ok);
    }
}
