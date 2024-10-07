pub fn xor_bytes(buf_a: &[u8], buf_b: &[u8]) -> Result<Vec<u8>, String> {
    if buf_a.len() != buf_b.len() {
        return Err("Buffers are not of equal length".to_string());
    }
    Ok(buf_a.iter().zip(buf_b.iter()).map(|(a, b)| a ^ b).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hex_to_bytes;

    #[test]
    fn xor_streams() {
        let a = hex_to_bytes("1c0111001f010100061a024b53535009181c").unwrap();
        let b = hex_to_bytes("686974207468652062756c6c277320657965").unwrap();

        let xored = xor_bytes(&a, &b);

        let expected = hex_to_bytes("746865206b696420646f6e277420706c6179");
        assert_eq!(xored, expected);
    }
}
