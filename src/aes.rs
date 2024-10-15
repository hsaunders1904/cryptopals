// A basis and, presumably, very insecure implementation of AES.
use crate::xor_bytes;

#[rustfmt::skip]
const S_BOX: [[u8; 16]; 16] = [
    [ 99, 124, 119, 123, 242, 107, 111, 197,  48,   1, 103,  43, 254, 215, 171, 118],
    [202, 130, 201, 125, 250,  89,  71, 240, 173, 212, 162, 175, 156, 164, 114, 192],
    [183, 253, 147,  38,  54,  63, 247, 204,  52, 165, 229, 241, 113, 216,  49,  21],
    [  4, 199,  35, 195,  24, 150,   5, 154,   7,  18, 128, 226, 235,  39, 178, 117],
    [  9, 131,  44,  26,  27, 110,  90, 160,  82,  59, 214, 179,  41, 227,  47, 132],
    [ 83, 209,   0, 237,  32, 252, 177,  91, 106, 203, 190,  57,  74,  76,  88, 207],
    [208, 239, 170, 251,  67,  77,  51, 133,  69, 249,   2, 127,  80,  60, 159, 168],
    [ 81, 163,  64, 143, 146, 157,  56, 245, 188, 182, 218,  33,  16, 255, 243, 210],
    [205,  12,  19, 236,  95, 151,  68,  23, 196, 167, 126,  61, 100,  93,  25, 115],
    [ 96, 129,  79, 220,  34,  42, 144, 136,  70, 238, 184,  20, 222,  94,  11, 219],
    [224,  50,  58,  10,  73,   6,  36,  92, 194, 211, 172,  98, 145, 149, 228, 121],
    [231, 200,  55, 109, 141, 213,  78, 169, 108,  86, 244, 234, 101, 122, 174,   8],
    [186, 120,  37,  46,  28, 166, 180, 198, 232, 221, 116,  31,  75, 189, 139, 138],
    [112,  62, 181, 102,  72,   3, 246,  14,  97,  53,  87, 185, 134, 193,  29, 158],
    [225, 248, 152,  17, 105, 217, 142, 148, 155,  30, 135, 233, 206,  85,  40, 223],
    [140, 161, 137,  13, 191, 230,  66, 104,  65, 153,  45,  15, 176,  84, 187,  22],
];

#[rustfmt::skip]
const INV_S_BOX: [[u8; 16]; 16] = [
    [ 82,   9, 106, 213,  48,  54, 165,  56, 191,  64, 163, 158, 129, 243, 215, 251],
    [124, 227,  57, 130, 155,  47, 255, 135,  52, 142,  67,  68, 196, 222, 233, 203],
    [ 84, 123, 148,  50, 166, 194,  35,  61, 238,  76, 149,  11,  66, 250, 195,  78],
    [  8,  46, 161, 102,  40, 217,  36, 178, 118,  91, 162,  73, 109, 139, 209,  37],
    [114, 248, 246, 100, 134, 104, 152,  22, 212, 164,  92, 204,  93, 101, 182, 146],
    [108, 112,  72,  80, 253, 237, 185, 218,  94,  21,  70,  87, 167, 141, 157, 132],
    [144, 216, 171,   0, 140, 188, 211,  10, 247, 228,  88,   5, 184, 179,  69,   6],
    [208,  44,  30, 143, 202,  63,  15,   2, 193, 175, 189,   3,   1,  19, 138, 107],
    [ 58, 145,  17,  65,  79, 103, 220, 234, 151, 242, 207, 206, 240, 180, 230, 115],
    [150, 172, 116,  34, 231, 173,  53, 133, 226, 249,  55, 232,  28, 117, 223, 110],
    [ 71, 241,  26, 113,  29,  41, 197, 137, 111, 183,  98,  14, 170,  24, 190,  27],
    [252,  86,  62,  75, 198, 210, 121,  32, 154, 219, 192, 254, 120, 205,  90, 244],
    [ 31, 221, 168,  51, 136,   7, 199,  49, 177,  18,  16,  89,  39, 128, 236,  95],
    [ 96,  81, 127, 169,  25, 181,  74,  13,  45, 229, 122, 159, 147, 201, 156, 239],
    [160, 224,  59,  77, 174,  42, 245, 176, 200, 235, 187,  60, 131,  83, 153,  97],
    [ 23,  43,   4, 126, 186, 119, 214,  38, 225, 105,  20,  99,  85,  33,  12, 125]
];

#[rustfmt::skip]
const MIX_MATRIX: [u8; 16] = [
    2, 3, 1, 1,
    1, 2, 3, 1,
    1, 1, 2, 3,
    3, 1, 1, 2,
];

#[rustfmt::skip]
const INV_MIX_MATRIX: [u8; 16] = [
    14, 11, 13, 9,
     9, 14, 11, 13,
    13,  9, 14, 11,
    11, 13,  9, 14
];

const ROUND_CONSTANTS: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];

struct AesCipher {
    round_keys: [[u8; 16]; 11],
}

impl AesCipher {
    fn new(key: &[u8; 16]) -> Self {
        let mut round_keys = make_11_round_keys(key);
        round_keys
            .iter_mut()
            .skip(1)
            .for_each(|k| transpose_matrix(k, 4));
        Self { round_keys }
    }

    fn encrypt_block(&mut self, mut plaintext: [u8; 16], ciphertext_buffer: &mut [u8]) {
        plaintext
            .iter_mut()
            .zip(self.round_keys[0])
            .for_each(|(b, k)| *b ^= k);
        let mut state = StateMatrix::new(&plaintext);
        for round_key in self.round_keys[1..10].iter() {
            state.substitute_bytes();
            state.shift_rows();
            state.mix();
            state.xor(&round_key.as_slice());
        }
        // No mix stage in the final round.
        state.substitute_bytes();
        state.shift_rows();
        state.xor(&self.round_keys[10]);
        ciphertext_buffer.clone_from_slice(state.as_ref());
        transpose_matrix(ciphertext_buffer, 4);
    }

    fn decrypt_block(&mut self, ciphertext: [u8; 16], plaintext_buffer: &mut [u8]) {
        let mut state = StateMatrix::new(&ciphertext);
        state.xor(self.round_keys.last().unwrap());
        for round_key in self.round_keys[1..10].iter().rev() {
            state.inv_shift_rows();
            state.inv_substitute_bytes();
            state.xor(round_key);
            state.inv_mix();
        }
        state.inv_shift_rows();
        state.inv_substitute_bytes();
        state.xor(&transposed(&self.round_keys[0]));
        plaintext_buffer.clone_from_slice(state.as_ref());
        transpose_matrix(plaintext_buffer, 4);
    }
}

#[derive(Debug, PartialEq, Eq)]
struct StateMatrix([u8; 16]);

impl StateMatrix {
    fn new(mat: &[u8]) -> Self {
        #[rustfmt::skip]
        let transposed_mat = [
            mat[0], mat[4],  mat[8], mat[12],
            mat[1], mat[5],  mat[9], mat[13],
            mat[2], mat[6], mat[10], mat[14],
            mat[3], mat[7], mat[11], mat[15],
        ];
        Self(transposed_mat)
    }

    fn substitute_bytes(&mut self) {
        self.0
            .iter_mut()
            .for_each(|byte| *byte = s_box_substitute(*byte, &S_BOX));
    }

    fn inv_substitute_bytes(&mut self) {
        self.0
            .iter_mut()
            .for_each(|byte| *byte = s_box_substitute(*byte, &INV_S_BOX));
    }

    fn shift_rows(&mut self) {
        for i in 1..4 {
            let block = &mut self.0[(i * 4)..((i + 1) * 4)];
            block.rotate_left(i);
        }
    }

    fn inv_shift_rows(&mut self) {
        for i in 1..4 {
            let block = &mut self.0[(i * 4)..((i + 1) * 4)];
            block.rotate_right(i);
        }
    }

    fn mix(&mut self) {
        let mat = StateMatrix::matrix_multiply(&MIX_MATRIX, &self.0);
        self.0
            .iter_mut()
            .zip(mat.iter())
            .for_each(|(sm, x)| *sm = *x);
    }

    fn inv_mix(&mut self) {
        let mat = StateMatrix::matrix_multiply(&INV_MIX_MATRIX, &self.0);
        self.0
            .iter_mut()
            .zip(mat.iter())
            .for_each(|(sm, x)| *sm = *x);
    }

    fn xor(&mut self, bytes: &[u8]) {
        for (i, byte) in bytes.iter().enumerate() {
            self.0[i] ^= byte;
        }
    }

    fn matrix_multiply(a: &[u8], b: &[u8]) -> Vec<u8> {
        let n = 4;
        let mut out = Vec::with_capacity(n * n);
        for i in 0..n {
            for j in 0..n {
                let mut sum = 0;
                for k in 0..n {
                    let el_a = a[i * n + k];
                    let el_b = b[j + n * k];
                    sum ^= StateMatrix::galois_multiply(el_a, el_b);
                }
                out.push(sum);
            }
        }
        out
    }

    fn galois_multiply(mut a: u8, mut b: u8) -> u8 {
        let mut product = 0;
        for _ in 0..8 {
            if (b & 1) > 0 {
                product ^= a;
            }
            let carry = a & 0x80;
            a <<= 1;
            if carry > 0 {
                a ^= 0x1B;
            }
            b >>= 1;
        }
        product & 0xFF
    }
}

impl AsRef<[u8; 16]> for StateMatrix {
    fn as_ref(&self) -> &[u8; 16] {
        &self.0
    }
}

fn transpose_matrix(matrix: &mut [u8], n: usize) {
    // Only transpose the upper triangle to avoid re-transposing
    for i in 0..n {
        for j in i + 1..n {
            // Calculate indices for the 1D vector
            let idx1 = i * n + j;
            let idx2 = j * n + i;
            // Swap the elements
            matrix.swap(idx1, idx2);
        }
    }
}

pub fn encrypt_aes_128_with_ecb(message: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut cipher = AesCipher::new(key);
    let mut ciphertext = Vec::with_capacity(message.len());
    for block in message.iter().as_slice().chunks(key.len()) {
        ciphertext.extend(vec![0; 16]);
        let range = (ciphertext.len() - 16)..(ciphertext.len());
        let mut ctext_buf: &mut [u8] = &mut ciphertext.as_mut_slice()[range];

        cipher.encrypt_block(block.try_into().unwrap(), &mut ctext_buf);
    }
    ciphertext
}

pub fn decrypt_aes_128_with_ecb(ciphertext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let mut cipher = AesCipher::new(key);
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for block in ciphertext.iter().as_slice().chunks(key.len()) {
        plaintext.extend(vec![0; 16]);
        let range = (plaintext.len() - 16)..(plaintext.len());
        let mut ptext_buf: &mut [u8] = &mut plaintext.as_mut_slice()[range];

        cipher.decrypt_block(block.try_into().unwrap(), &mut ptext_buf);
    }
    plaintext
}

fn transposed(x: &[u8]) -> Vec<u8> {
    let mut xc = x.to_owned();
    transpose_matrix(&mut xc, 4);
    xc
}

fn make_11_round_keys(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut keys: Vec<[u8; 16]> = Vec::with_capacity(11);
    keys.push(key.clone());
    for round in 0..10 {
        keys.push(
            make_round_key(keys.last().unwrap().as_slice(), round)
                .try_into()
                .unwrap(),
        );
    }
    keys.try_into().unwrap()
}

fn make_round_key(key: &[u8], round: usize) -> Vec<u8> {
    let word_0: [u8; 4] = key[0..4].try_into().unwrap();
    let word_1: [u8; 4] = key[4..8].try_into().unwrap();
    let word_2: [u8; 4] = key[8..12].try_into().unwrap();
    let word_3: [u8; 4] = key[12..16].try_into().unwrap();
    let word_4: [u8; 4] = xor_bytes(&word_0, &g(&word_3, ROUND_CONSTANTS[round]))
        .unwrap()
        .as_slice()
        .try_into()
        .unwrap();
    let word_5: [u8; 4] = xor_bytes(&word_4, &word_1).unwrap().try_into().unwrap();
    let word_6: [u8; 4] = xor_bytes(&word_5, &word_2).unwrap().try_into().unwrap();
    let word_7: [u8; 4] = xor_bytes(&word_6, &word_3).unwrap().try_into().unwrap();

    let mut key = Vec::with_capacity(16);
    key.extend_from_slice(&word_4);
    key.extend_from_slice(&word_5);
    key.extend_from_slice(&word_6);
    key.extend_from_slice(&word_7);
    key
}

fn g(word: &[u8; 4], rcon_i: u8) -> Vec<u8> {
    let mut new_word = word.to_vec();
    new_word.rotate_left(1);
    new_word = substitute_bytes(&new_word);
    new_word[0] ^= rcon_i;
    new_word
}

fn substitute_bytes(block: &[u8]) -> Vec<u8> {
    block
        .into_iter()
        .map(|byte| s_box_substitute(*byte, &S_BOX))
        .collect()
}

fn s_box_substitute(byte: u8, table: &[[u8; 16]; 16]) -> u8 {
    let first_nibble = ((0b11110000 & byte) >> 4) as usize;
    let second_nibble = (0b00001111 & byte) as usize;
    table[first_nibble][second_nibble]
}

#[cfg(test)]
mod tests {
    use std::{io::BufRead, path::PathBuf};

    use rstest::rstest;

    use crate::hex_to_bytes;

    use super::*;

    #[test]
    fn state_matrix_byte_substitution() {
        #[rustfmt::skip]
        let msg = [
            0x00, 0x3C, 0x6E, 0x47,
            0x1F, 0x4E, 0x22, 0x74,
            0x0E, 0x08, 0x1B, 0x31,
            0x54, 0x59, 0x0B, 0x1A,
        ];
        let mut matrix = StateMatrix(msg);

        matrix.substitute_bytes();

        #[rustfmt::skip]
        let expected = StateMatrix([
            0x63, 0xEB, 0x9F, 0xA0,
            0xC0, 0x2F, 0x93, 0x92,
            0xAB, 0x30, 0xAF, 0xC7,
            0x20, 0xCB, 0x2B, 0xA2,
        ]);
        assert_eq!(matrix, expected);
    }

    #[test]
    fn state_matrix_inv_byte_substitution() {
        #[rustfmt::skip]
        let msg = [
            0x63, 0xEB, 0x9F, 0xA0,
            0xC0, 0x2F, 0x93, 0x92,
            0xAB, 0x30, 0xAF, 0xC7,
            0x20, 0xCB, 0x2B, 0xA2,
        ];
        let mut matrix = StateMatrix(msg);

        matrix.inv_substitute_bytes();

        #[rustfmt::skip]
        let expected = StateMatrix([
            0x00, 0x3C, 0x6E, 0x47,
            0x1F, 0x4E, 0x22, 0x74,
            0x0E, 0x08, 0x1B, 0x31,
            0x54, 0x59, 0x0B, 0x1A,
        ]);
        assert_eq!(matrix, expected);
    }

    #[test]
    fn state_matrix_shift_rows() {
        #[rustfmt::skip]
        let mut matrix = StateMatrix([
            0x63, 0xEB, 0x9F, 0xA0,
            0xC0, 0x2F, 0x93, 0x92,
            0xAB, 0x30, 0xAF, 0xC7,
            0x20, 0xCB, 0x2B, 0xA2,
        ]);

        matrix.shift_rows();

        #[rustfmt::skip]
        let expected = StateMatrix([
            0x63, 0xEB, 0x9F, 0xA0,
            0x2F, 0x93, 0x92, 0xC0,
            0xAF, 0xC7, 0xAB, 0x30,
            0xA2, 0x20, 0xCB, 0x2B,
        ]);
        assert_eq!(matrix, expected);
    }

    #[test]
    fn state_matrix_inv_shift_rows() {
        #[rustfmt::skip]
        let mut matrix = StateMatrix([
            0x63, 0xEB, 0x9F, 0xA0,
            0x2F, 0x93, 0x92, 0xC0,
            0xAF, 0xC7, 0xAB, 0x30,
            0xA2, 0x20, 0xCB, 0x2B,
        ]);

        matrix.inv_shift_rows();

        #[rustfmt::skip]
        let expected = StateMatrix([
            0x63, 0xEB, 0x9F, 0xA0,
            0xC0, 0x2F, 0x93, 0x92,
            0xAB, 0x30, 0xAF, 0xC7,
            0x20, 0xCB, 0x2B, 0xA2,
        ]);
        assert_eq!(matrix, expected);
    }

    #[test]
    fn state_matrix_mix() {
        #[rustfmt::skip]
        let mut matrix = StateMatrix([
            0x63, 0xEB, 0x9F, 0xA0,
            0x2F, 0x93, 0x92, 0xC0,
            0xAF, 0xC7, 0xAB, 0x30,
            0xA2, 0x20, 0xCB, 0x2B,
        ]);

        matrix.mix();

        #[rustfmt::skip]
        let expected = StateMatrix([
            0xBA, 0x84, 0xE8, 0x1B,
            0x75, 0xA4, 0x8D, 0x40,
            0xF4, 0x8D, 0x06, 0x7D,
            0x7A, 0x32, 0x0E, 0x5D,
        ]);
        assert_eq!(matrix, expected);
    }

    #[test]
    fn state_matrix_inv_mix() {
        #[rustfmt::skip]
        let mut matrix = StateMatrix([
            0xBA, 0x84, 0xE8, 0x1B,
            0x75, 0xA4, 0x8D, 0x40,
            0xF4, 0x8D, 0x06, 0x7D,
            0x7A, 0x32, 0x0E, 0x5D,
        ]);

        matrix.inv_mix();

        #[rustfmt::skip]
        let expected = StateMatrix([
            0x63, 0xEB, 0x9F, 0xA0,
            0x2F, 0x93, 0x92, 0xC0,
            0xAF, 0xC7, 0xAB, 0x30,
            0xA2, 0x20, 0xCB, 0x2B,
        ]);
        assert_eq!(matrix, expected);
    }

    #[rstest]
    #[case(0x02, 0x63, 0b11000110)]
    #[case(0x03, 0x2F, 0b01110001)]
    #[case(0x01, 0xAF, 0xAF)]
    fn galois_multiply(#[case] a: u8, #[case] b: u8, #[case] expected: u8) {
        assert_eq!(StateMatrix::galois_multiply(a, b), expected);
    }

    #[test]
    fn make_round_keys_generates_correct_keys() {
        let key = [
            0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20,
            0x46, 0x75,
        ];

        let round_keys = make_11_round_keys(&key);

        assert_eq!(
            round_keys[0],
            [
                0x54, 0x68, 0x61, 0x74, 0x73, 0x20, 0x6D, 0x79, 0x20, 0x4B, 0x75, 0x6E, 0x67, 0x20,
                0x46, 0x75
            ]
        );
        assert_eq!(
            round_keys[1],
            [
                0xE2, 0x32, 0xFC, 0xF1, 0x91, 0x12, 0x91, 0x88, 0xB1, 0x59, 0xE4, 0xE6, 0xD6, 0x79,
                0xA2, 0x93
            ]
        );
        assert_eq!(
            round_keys[2],
            [
                0x56, 0x08, 0x20, 0x07, 0xC7, 0x1A, 0xB1, 0x8F, 0x76, 0x43, 0x55, 0x69, 0xA0, 0x3A,
                0xF7, 0xFA
            ]
        );
        assert_eq!(
            round_keys[3],
            [
                0xD2, 0x60, 0x0D, 0xE7, 0x15, 0x7A, 0xBC, 0x68, 0x63, 0x39, 0xE9, 0x01, 0xC3, 0x03,
                0x1E, 0xFB
            ]
        );
        assert_eq!(
            round_keys[4],
            [
                0xA1, 0x12, 0x02, 0xC9, 0xB4, 0x68, 0xBE, 0xA1, 0xD7, 0x51, 0x57, 0xA0, 0x14, 0x52,
                0x49, 0x5B
            ]
        );
        assert_eq!(
            round_keys[5],
            [
                0xB1, 0x29, 0x3B, 0x33, 0x05, 0x41, 0x85, 0x92, 0xD2, 0x10, 0xD2, 0x32, 0xC6, 0x42,
                0x9B, 0x69
            ]
        );
        assert_eq!(
            round_keys[6],
            [
                0xBD, 0x3D, 0xC2, 0x87, 0xB8, 0x7C, 0x47, 0x15, 0x6A, 0x6C, 0x95, 0x27, 0xAC, 0x2E,
                0x0E, 0x4E
            ]
        );
        assert_eq!(
            round_keys[7],
            [
                0xCC, 0x96, 0xED, 0x16, 0x74, 0xEA, 0xAA, 0x03, 0x1E, 0x86, 0x3F, 0x24, 0xB2, 0xA8,
                0x31, 0x6A
            ]
        );
        assert_eq!(
            round_keys[8],
            [
                0x8E, 0x51, 0xEF, 0x21, 0xFA, 0xBB, 0x45, 0x22, 0xE4, 0x3D, 0x7A, 0x06, 0x56, 0x95,
                0x4B, 0x6C
            ]
        );
        assert_eq!(
            round_keys[9],
            [
                0xBF, 0xE2, 0xBF, 0x90, 0x45, 0x59, 0xFA, 0xB2, 0xA1, 0x64, 0x80, 0xB4, 0xF7, 0xF1,
                0xCB, 0xD8
            ]
        );
        assert_eq!(
            round_keys[10],
            [
                0x28, 0xFD, 0xDE, 0xF8, 0x6D, 0xA4, 0x24, 0x4A, 0xCC, 0xC0, 0xA4, 0xFE, 0x3B, 0x31,
                0x6F, 0x26
            ]
        );
    }

    #[test]
    fn aes_128_with_ecb_encrypt_block() {
        let key = "Thats my Kung Fu".as_bytes();
        let plaintext = "Two One Nine Two".as_bytes();

        let ciphertext = encrypt_aes_128_with_ecb(&plaintext, &key.try_into().unwrap());

        #[rustfmt::skip]
        let expected = [
            0x29, 0xC3, 0x50, 0x5F,
            0x57, 0x14, 0x20, 0xF6,
            0x40, 0x22, 0x99, 0xB3,
            0x1A, 0x02, 0xD7, 0x3A,
        ];
        assert_eq!(ciphertext, expected);
    }

    #[derive(Debug, Default)]
    struct AesTestVector {
        count: usize,
        key: Vec<u8>,
        plaintext: Vec<u8>,
        ciphertext: Vec<u8>,
    }

    fn read_lines<P>(
        filename: P,
    ) -> std::io::Result<std::io::Lines<std::io::BufReader<std::fs::File>>>
    where
        P: AsRef<std::path::Path>,
    {
        let file = std::fs::File::open(filename)?;
        Ok(std::io::BufReader::new(file).lines())
    }

    fn read_test_vectors(path: &PathBuf) -> (Vec<AesTestVector>, Vec<AesTestVector>) {
        let lines: Vec<String> = read_lines(path)
            .expect("could not read test vectors")
            .map(|line| line.expect("could not read line").trim().to_string())
            .collect();

        let mut line_it = lines.iter();
        let mut reading_encrypt_cases = false;
        let mut reading_decrypt_cases = false;
        let mut enc_vectors = Vec::new();
        let mut dec_vectors = Vec::new();
        while let Some(line) = line_it.next() {
            if line == "[ENCRYPT]" {
                reading_encrypt_cases = true;
                reading_decrypt_cases = false;
                continue;
            }
            if line == "[DECRYPT]" {
                reading_encrypt_cases = false;
                reading_decrypt_cases = true;
                continue;
            }
            if !(reading_encrypt_cases || reading_decrypt_cases) || line.is_empty() {
                continue;
            }
            let mut vector = AesTestVector::default();
            while let Some(line) = line_it.next() {
                if line.is_empty() {
                    if reading_encrypt_cases {
                        enc_vectors.push(vector);
                    } else if reading_decrypt_cases {
                        dec_vectors.push(vector);
                    }
                    break;
                }
                let (name, value) = line
                    .split_once(" = ")
                    .expect(&format!("could not split line '{}'", line));
                match name {
                    "COUNT" => vector.count = value.parse::<usize>().unwrap(),
                    "KEY" => vector.key = hex_to_bytes(value).unwrap(),
                    "PLAINTEXT" => vector.plaintext = hex_to_bytes(value).unwrap(),
                    "CIPHERTEXT" => vector.ciphertext = hex_to_bytes(value).unwrap(),
                    _ => (),
                }
            }
        }
        (enc_vectors, dec_vectors)
    }

    #[test]
    fn aes_128_with_ecb_test_vectors() {
        let path = std::path::Path::new("./data/aes/ECBMMT128.rsp");
        let (vectors, _) = read_test_vectors(&path.to_path_buf());

        for v in vectors {
            assert_eq!(
                encrypt_aes_128_with_ecb(&v.plaintext, v.key.as_slice().try_into().unwrap()),
                v.ciphertext
            );
        }
    }

    #[test]
    fn decrypt_aes_128_with_ecb_test_vectors() {
        let path = std::path::Path::new("./data/aes/ECBMMT128.rsp");
        let (_, vectors) = read_test_vectors(&path.to_path_buf());

        for v in vectors {
            assert_eq!(
                decrypt_aes_128_with_ecb(&v.ciphertext, v.key.as_slice().try_into().unwrap()),
                v.plaintext,
                "failed on case {}",
                v.count
            );
        }
    }
}
