// ECB cut-and-paste

use std::{
    collections::HashMap,
    fmt::Display,
    hash::{Hash, Hasher},
};

use crate::{encrypt_aes_128_ecb, pkcs7_pad};

const BLOCK_SIZE: usize = 16;

#[derive(Debug, PartialEq, Eq)]
pub struct UserProfile {
    email: String,
    uid: u64,
    role: String,
}

impl UserProfile {
    pub fn new(email: &str, role: &str) -> Self {
        UserProfile {
            email: email.to_string(),
            uid: Self::hash_string(email),
            role: role.to_string(),
        }
    }

    pub fn profile_for(email: &str) -> Self {
        Self::new(email, "user")
    }

    fn hash_string(s: &str) -> u64 {
        let mut hasher = std::hash::DefaultHasher::new();
        s.hash(&mut hasher);
        hasher.finish()
    }
}

impl Display for UserProfile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "email={}&uid={:020}&role={}",
            self.email, self.uid, self.role
        )
    }
}

impl TryFrom<&str> for UserProfile {
    type Error = String;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let parsed = parse_query(value);
        Ok(Self {
            email: parsed
                .get("email")
                .ok_or_else(|| "email not parsed from query".to_string())?
                .to_string(),
            uid: parsed
                .get("uid")
                .ok_or_else(|| "uid not parsed from query".to_string())?
                .parse::<u64>()
                .map_err(|e| format!("cannot convert uid to string: {e}"))?,
            role: parsed
                .get("role")
                .ok_or_else(|| "role not parsed from query".to_string())?
                .to_string(),
        })
    }
}

pub struct UserProfileOracle {
    key: [u8; 16],
}

impl UserProfileOracle {
    pub fn new(key: [u8; 16]) -> Self {
        Self { key }
    }

    pub fn profile_for(&self, email: &str) -> Vec<u8> {
        let profile = UserProfile::profile_for(email);
        encrypt_user_profile(&profile, &self.key)
    }
}

/// Generate a valid ciphertext for an admin UserProfile.
///
/// Return the profile's email and the valid ciphertext.
pub fn falsify_admin_account_with_ecb_oracle(oracle: &UserProfileOracle) -> (String, Vec<u8>) {
    // Remember an account query is structured as so:
    //  email=foo@bar.com&uid=10&role=user

    // Firstly we manipulate an email and input it to the oracle such that
    // an ECB block begins with 'admin' and the rest of the block is
    // padded.
    let cut_email = [
        // The email will be encrypted with prefix 'email=', so we need 10
        // more bytes to fill a 16-byte block.
        b"lengtheq10".to_vec(),
        // Now we append our padded 'admin' block
        pkcs7_pad(b"admin", BLOCK_SIZE as u8),
        // And the rest of the email
        b"@mail.com".to_vec(),
    ]
    .concat();
    // The second block of this ciphertext is the sub-ciphertext of
    // 'admin' + padding.
    let cut_profile = oracle.profile_for(&String::from_utf8_lossy(&cut_email).to_string());

    // Now we generate another user profile ciphertext such that we can
    // take the middle block from our first ciphertext and use it as the
    // final block - replacing the user role.
    // To do this, we need the second from last block of the user profile
    // to end in 'role='; i.e., the final block contains the user role.
    // Note that in our scheme, the UID always has 20 characters.
    let paste_email = "ac@mail.com";
    let paste_profile = oracle.profile_for(paste_email);

    // We can now replace the final block in the the 'paste profile' with
    // the 'admin' ciphertext we generated earlier.
    let falsified_ciphertext = paste_profile[..(3 * BLOCK_SIZE)]
        .iter()
        .cloned()
        .chain(cut_profile[BLOCK_SIZE..(2 * BLOCK_SIZE)].iter().cloned())
        .collect::<Vec<_>>();
    (paste_email.to_string(), falsified_ciphertext)
}

fn encrypt_user_profile(user: &UserProfile, key: &[u8; 16]) -> Vec<u8> {
    encrypt_aes_128_ecb(user.to_string().as_bytes(), key)
}

fn parse_query(query: &str) -> HashMap<String, String> {
    let mut query_map = HashMap::new();
    query
        .split("&")
        .filter_map(|x| x.split_once("="))
        .for_each(|(k, v)| {
            query_map.insert(k.to_string(), v.to_string());
        });
    query_map
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::{decrypt_aes_128_ecb, random_bytes};

    fn decrypt_user_profile(ciphertext: &[u8], key: &[u8; 16]) -> Result<UserProfile, String> {
        let encoded = decrypt_aes_128_ecb(ciphertext, key);
        UserProfile::try_from(String::from_utf8_lossy(&encoded).to_string().as_ref())
            .map_err(|e| format!("cannot parse decrypted string as user profile: {e}"))
    }

    #[test]
    fn ecb_cut_and_paste_attack() {
        // Lets create our oracle, with some fixed random key.
        let key = random_bytes::<BLOCK_SIZE>();
        let oracle = UserProfileOracle::new(key);

        let (email, falsified_profile) = falsify_admin_account_with_ecb_oracle(&oracle);

        let decrypted_falsified_profile = decrypt_user_profile(&falsified_profile, &key).unwrap();
        assert_eq!(
            decrypted_falsified_profile,
            UserProfile::new(&email, "admin")
        );
    }

    #[test]
    fn parse_query_parses_query_arguments() {
        let query = "foo=bar&baz=qux&zap=zazzle";

        let parsed = parse_query(&query);

        let mut expected = HashMap::new();
        expected.insert("foo".to_string(), "bar".to_string());
        expected.insert("baz".to_string(), "qux".to_string());
        expected.insert("zap".to_string(), "zazzle".to_string());
        assert_eq!(parsed, expected);
    }

    #[test]
    fn encrypt_and_decrypt_user_profile() {
        let user = UserProfile::profile_for("test@yahoo.com");
        let key = random_bytes::<16>();

        let ciphertext = encrypt_user_profile(&user, &key);
        let decrypted = decrypt_user_profile(&ciphertext, &key).unwrap();

        assert_eq!(decrypted, user);
    }
}
