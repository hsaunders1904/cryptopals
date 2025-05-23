use crate::{xor_bytes, Hasher, Sha1, Sha256};

const BLOCK_SIZE: usize = 64;
const O_PAD: [u8; BLOCK_SIZE] = [0x5c; BLOCK_SIZE];
const I_PAD: [u8; BLOCK_SIZE] = [0x36; BLOCK_SIZE];

pub type HmacSha1 = Hmac<Sha1, 20>;
pub type HmacSha256 = Hmac<Sha256, 32>;

#[derive(Debug, Clone)]
pub struct Hmac<H: Hasher<N> + Default, const N: usize> {
    inner_hasher: H,
    outer_hasher: H,
}

impl<H: Hasher<N> + Default, const N: usize> Hmac<H, N> {
    pub fn new(key: &[u8]) -> Self {
        let key_block = Self::to_block_sized_key(key);

        let mut inner_hasher = H::default();
        inner_hasher.update(&xor_bytes(&key_block, &I_PAD));

        let mut outer_hasher = H::default();
        outer_hasher.update(&xor_bytes(&key_block, &O_PAD));

        Self {
            inner_hasher,
            outer_hasher,
        }
    }

    pub fn digest_message(key: &[u8], message: &[u8]) -> [u8; N] {
        let mut hmac = Self::new(key);
        hmac.update(message);
        hmac.digest()
    }

    pub fn update(&mut self, message: &[u8]) {
        self.inner_hasher.update(message);
    }

    pub fn update_and_digest(mut self, message: &[u8]) -> [u8; N] {
        self.inner_hasher.update(message);
        self.digest()
    }

    pub fn digest(self) -> [u8; N] {
        self.outer_hasher
            .update_and_digest(&self.inner_hasher.digest())
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

    #[test]
    fn hmac_sha256_returns_correct_mac() {
        let key = b"key";
        let message = b"The quick brown fox jumps over the lazy dog";

        let mac = HmacSha256::digest_message(key, message);

        let expected = "97yD9DBThCSxMpjmqm+xQ+9NWaFJRhdZl0edvC0aPNg=";
        assert_eq!(base64_encode(&mac), expected);
    }
}
