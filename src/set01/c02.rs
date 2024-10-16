pub fn xor_slices(buf_a: &[u8], buf_b: &[u8]) -> Result<Vec<u8>, String> {
    if buf_a.len() != buf_b.len() {
        return Err("Buffers are not of equal length".to_string());
    }
    Ok(buf_a.iter().zip(buf_b.iter()).map(|(a, b)| a ^ b).collect())
}

pub fn xor_bytes<const N: usize>(buf_a: &[u8; N], buf_b: &[u8; N]) -> [u8; N] {
    let mut out = [0u8; N];
    buf_a
        .iter()
        .zip(buf_b)
        .zip(out.iter_mut())
        .for_each(|((a, b), o)| *o = a ^ b);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::hex_to_bytes;

    #[test]
    fn xor_streams() {
        let a = hex_to_bytes("1c0111001f010100061a024b53535009181c").unwrap();
        let b = hex_to_bytes("686974207468652062756c6c277320657965").unwrap();

        let xored = xor_slices(&a, &b);

        let expected = hex_to_bytes("746865206b696420646f6e277420706c6179");
        assert_eq!(xored, expected);
    }
}
