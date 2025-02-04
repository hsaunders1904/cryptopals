// Implement PKCS#7 padding

pub fn pkcs7_pad(bytes: &[u8], block_size: u8) -> Vec<u8> {
    let n_pad = if bytes.len() % block_size as usize == 0 {
        block_size
    } else {
        block_size - (bytes.len() % block_size as usize) as u8
    };
    let mut out = Vec::with_capacity(bytes.len() + n_pad as usize);
    out.extend_from_slice(bytes);
    (0..n_pad).for_each(|_| out.push(n_pad));
    out
}

pub fn pkcs7_unpad_unchecked(bytes: &mut Vec<u8>) {
    if let Some(n_pad) = is_pkcs7_padded(bytes) {
        bytes.truncate(bytes.len() - n_pad as usize);
    }
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

    #[rstest]
    #[case("YELL", 4, "YELL\x04\x04\x04\x04")]
    #[case("YELLOWS!!!", 6, "YELLOWS!!!\x02\x02")]
    #[case("YELLOW SUBMARINE", 20, "YELLOW SUBMARINE\x04\x04\x04\x04")]
    fn pkcs7_pad_pads_message(#[case] msg: &str, #[case] block_size: u8, #[case] expected: &str) {
        let msg = msg.as_bytes();

        let padded = pkcs7_pad(msg, block_size);

        assert_eq!(padded, expected.as_bytes());
    }

    #[rstest]
    #[case("YELL", "YELL\x04\x04\x04\x04")]
    #[case("YELLOWS!!!", "YELLOWS!!!\x02\x02")]
    #[case("YELLOW SUBMARINE", "YELLOW SUBMARINE\x04\x04\x04\x04")]
    fn pkcs7_unpad_unpads_message(#[case] expected: &str, #[case] padded: &str) {
        let mut msg = padded.as_bytes().to_vec();

        pkcs7_unpad_unchecked(&mut msg);

        assert_eq!(msg, expected.as_bytes());
    }
}
