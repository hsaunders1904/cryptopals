use crate::{Hasher, Sha1};

pub fn authenticate_message_with_sha1(key: &[u8], message: &[u8]) -> [u8; 20] {
    Sha1::digest_message(&[key, message].concat())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticate_message_with_sha1_returns_expected_mac() {
        let key = b"0".repeat(16);
        let message = b"YELLOW_SUBMARINE!";

        let mac = authenticate_message_with_sha1(&key, message);

        let expected_mac = b"\xac\x1f{?\x03\xe9\x9a\x15\xbf\xe1\x80;\xa0\xe6\xe5\xdb\xa1;+\xbe";
        assert_eq!(mac, *expected_mac);
    }
}
