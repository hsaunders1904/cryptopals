// Implement and break HMAC-SHA1 with an artificial timing leak
use crate::{xor_bytes, Sha1};

const BLOCK_SIZE: usize = 64;
const O_PAD: [u8; BLOCK_SIZE] = [0x5c; BLOCK_SIZE];
const I_PAD: [u8; BLOCK_SIZE] = [0x36; BLOCK_SIZE];

pub struct HmacSha1 {
    inner_sha1: Sha1,
    outer_sha1: Sha1,
}

impl HmacSha1 {
    pub fn new(key: &[u8]) -> Self {
        let key_block = Self::to_block_sized_key(key);

        let mut inner_sha1 = Sha1::default();
        inner_sha1.update(&xor_bytes(&key_block, &I_PAD));

        let mut outer_sha1 = Sha1::default();
        outer_sha1.update(&xor_bytes(&key_block, &O_PAD));

        Self {
            inner_sha1,
            outer_sha1,
        }
    }

    pub fn digest_message(key: &[u8], message: &[u8]) -> [u8; 20] {
        let mut hmac = HmacSha1::new(key);
        hmac.update(message);
        hmac.digest()
    }

    pub fn update(&mut self, message: &[u8]) {
        self.inner_sha1.update(message);
    }

    pub fn digest(self) -> [u8; 20] {
        self.outer_sha1.update_and_digest(&self.inner_sha1.digest())
    }

    fn to_block_sized_key(var_len_key: &[u8]) -> [u8; BLOCK_SIZE] {
        let mut key = [0; BLOCK_SIZE];
        match var_len_key.len().cmp(&BLOCK_SIZE) {
            std::cmp::Ordering::Less => {
                key[..var_len_key.len()].copy_from_slice(var_len_key);
            }
            std::cmp::Ordering::Equal => {
                key[..].copy_from_slice(var_len_key);
            }
            std::cmp::Ordering::Greater => {
                key[..20].copy_from_slice(&Sha1::digest_message(var_len_key));
            }
        }
        key
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::base64_encode;

    #[test]
    fn hmac_sha1_returns_correct_mac() {
        let key = b"key";
        let message = b"The quick brown fox jumps over the lazy dog";

        let mac = HmacSha1::digest_message(key, message);

        let expected = "3nybhbi3iqa8ino29wqQcBydtNk=";
        assert_eq!(base64_encode(&mac), expected);
    }
}
