/// Implement PKCS#7 padding

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

#[cfg(test)]
mod test {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case("YELL", 4, "YELL\x04\x04\x04\x04")]
    #[case("YELLOWS!!!", 6, "YELLOWS!!!\x02\x02")]
    #[case("YELLOW SUBMARINE", 20, "YELLOW SUBMARINE\x04\x04\x04\x04")]
    fn pkcs7_pad_pads_message(#[case] msg: &str, #[case] block_size: u8, #[case] expected: &str) {
        let msg = msg.as_bytes();

        let padded = pkcs7_pad(&msg, block_size);

        assert_eq!(padded, expected.as_bytes());
    }
}
