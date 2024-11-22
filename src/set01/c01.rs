// Base64 can be encoded by:
//
// 1. Concatenating all the bytes in the byte stream.
// 2. Chunking the bytes into 6 bits.
//     - If the last chunk is less than 6 bits pad the front with zeros.
// 3. Indexing into the base64 table using the 6 bit number.
//     - ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
// 4. Padding the returned string with '=' until the length is divisible by 4.
//     - Padding is not strictly necessary, but is useful when base64 encoded
//       strings are concatenated, to disambiguate the beginning of one string
//       and the end of another.
//
// For example, the bytes:
//
//     01110100 01100101 01110011 01110100
//
// Should be split like this:
//
//     011101 000110 010101 110011 011101 00
//
// Which, as a u8, is
//
//     00011101 00000110 00010101 00110011 00011101 00000000
//
//        29       6        21       51        29      0
//
// Using these as an index into the table, we get:
//
//     dGVzdA
//
// Then padding:
//
//     dGVzdA==
//

use crate::base64_encode;

pub fn hex_to_b64(hex: &str) -> Result<String, String> {
    let bytes = hex_to_bytes(hex)?;
    Ok(base64_encode(&bytes))
}

pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, String> {
    hex.as_bytes()
        .chunks(2)
        .map(|x| u8::from_str_radix(std::str::from_utf8(x).unwrap(), 16))
        .collect::<Result<Vec<u8>, std::num::ParseIntError>>()
        .map_err(|e| format!("failed to convert hex to bytes: {e}"))
}

#[cfg(test)]
mod test {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case("74657374", "dGVzdA==")] // test
    #[case("7465737432", "dGVzdDI=")] // test2
    #[case(
        "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d",
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    )]
    fn convert_hex_to_base64(#[case] hex: &str, #[case] b64: &str) {
        assert_eq!(hex_to_b64(hex).unwrap(), b64);
    }

    #[test]
    fn test_hex_to_bytes_valid() {
        let hex = "0A3F";
        let expected: Vec<u8> = vec![0x0A, 0x3F];
        let result = hex_to_bytes(hex).unwrap();
        assert_eq!(result, expected);
    }
}
