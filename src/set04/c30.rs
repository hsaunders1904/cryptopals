// Break an MD4 keyed MAC using length extension
use crate::{LengthExtensionForgery, Md4};

pub struct Md4KeyedMacOracle {
    key: Vec<u8>,
}

impl Md4KeyedMacOracle {
    pub fn new(key: Vec<u8>) -> Self {
        Self { key }
    }

    pub fn mac_message(&self, message: &[u8]) -> [u8; 16] {
        Md4::digest_message(&[&self.key, message].concat())
    }

    pub fn check_mac(&self, message: &[u8], mac: &[u8]) -> bool {
        self.mac_message(message) == mac
    }
}

pub fn keyed_md4_mac_length_extension_attack(
    oracle: &Md4KeyedMacOracle,
    message: &[u8],
    suffix_forgery: &[u8],
) -> Result<LengthExtensionForgery<16>, String> {
    // Try a range of key lengths until we find one that works.
    // for key_len in 0..64 {
    for key_len in 0..16 {
        // Pad the original message with "glue-padding":
        //   original-message || glue-padding || new-message
        let glue_padded_message = &md_pad(&[&b"0".repeat(key_len), message].concat())[key_len..];
        let forged_message = [glue_padded_message, suffix_forgery].concat();

        // Find the state of the MD4 hasher when it's digested the original
        // message.
        // Split it into 4 separate integers so we can use it to make a MD4
        // hasher with the same internal state as one that has just hashed the
        // original message.
        let md4_digest_state: [u32; 4] = oracle
            .mac_message(message)
            .iter()
            .as_slice()
            .chunks_exact(4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .collect::<Vec<u32>>()
            .try_into()
            .unwrap();

        // Generate a MD4 of the forgery using the state of the hasher we
        // recovered from the original MAC.
        // In effect here we're doing:
        //   MD4(key || original-message || glue-padding || new-message)
        // which will give us a MAC valid under the oracle's scheme.
        let md4 = Md4::new_with_initialisation_constants(
            md4_digest_state,
            (key_len + glue_padded_message.len()) as u64 * 8,
        );
        let forged_mac = md4.update_and_digest(suffix_forgery);

        if oracle.check_mac(&forged_message, &forged_mac) {
            return Ok(LengthExtensionForgery {
                message: forged_message,
                mac: forged_mac,
            });
        }
    }
    Err("length extension attack failed: could not generate forgery".to_string())
}

fn md_pad(message: &[u8]) -> Vec<u8> {
    let message_bit_len = (message.len() as u64) * 8;
    let mut buffer = message.to_vec();
    let len_mod = (buffer.len() + 8) % 64;
    let pad_len = (64 - len_mod) % 64;
    buffer.extend(std::iter::once(0x80));
    if pad_len > 0 {
        buffer.extend(std::iter::repeat(0x00).take(pad_len - 1));
    }
    buffer.extend_from_slice(&message_bit_len.to_le_bytes());
    buffer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keyed_md4_mac_length_extension_attack_generates_mac_for_message() {
        let key = b"forwards";
        let oracle = Md4KeyedMacOracle::new(key.to_vec());
        let message =
            b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";
        let suffix_forgery = b";admin=true;";

        let forgery =
            keyed_md4_mac_length_extension_attack(&oracle, message, suffix_forgery).unwrap();

        assert!(
            forgery
                .message
                .split(|&x| x == ';' as u8)
                .any(|x| x == b"admin=true"),
            "{}",
            String::from_utf8_lossy(&forgery.message)
        );
        assert!(oracle.check_mac(&forgery.message, &forgery.mac),);
    }
}
