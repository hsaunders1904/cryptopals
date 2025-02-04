// PKCS#7 padding validation

pub fn pkcs7_unpad(bytes: &mut Vec<u8>) -> Result<(), String> {
    if let Some(n_pad) = is_pkcs7_padded(bytes) {
        bytes.truncate(bytes.len() - n_pad as usize);
        return Ok(());
    }
    Err("invalid pkcs7 padding".to_string())
}

fn is_pkcs7_padded(bytes: &[u8]) -> Option<u8> {
    if let Some(n_pad) = bytes.last() {
        if *n_pad as usize > bytes.len() {
            return None;
        }
        let padded = &bytes[(bytes.len() - *n_pad as usize)..];
        if padded.iter().all(|el| el == n_pad) {
            return Some(*n_pad);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    use rstest::rstest;

    #[test]
    fn pkcs7_unpad_unpads_message() {
        let mut msg = b"ICE ICE BABY\x04\x04\x04\x04".to_vec();

        let unpadded = pkcs7_unpad(&mut msg);

        assert!(unpadded.is_ok());
        assert_eq!(msg, b"ICE ICE BABY");
    }

    #[rstest]
    #[case("ICE ICE BABY\x05\x05\x05\x05")]
    #[case("ICE ICE BABY\x01\x02\x03\x04")]
    fn pkcs7_unpad_returns_err_given_invalid_padding(#[case] padded: &str) {
        let mut msg = padded.as_bytes().to_vec();

        let unpadded = pkcs7_unpad(&mut msg);

        assert!(unpadded.is_err());
    }
}
