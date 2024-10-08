/// In this challenge we are given a file containing 60-character strings.
/// One of those strings has been encrypted using a single-character XOR. Our
/// task is to find the encrypted string.
use std::io::BufRead;

use crate::{brute_force_byte_xor_cipher, hex_to_bytes};

pub fn find_byte_xor_encrypted_string(path: std::path::PathBuf) -> Result<String, String> {
    let mut best_english_score = 0.;
    let mut best_candidate = String::new();
    if let Ok(lines) = read_lines(&path) {
        for string in lines.flatten() {
            let bytes = hex_to_bytes(string.trim())
                .map_err(|e| format!("could not decode {string}: {e}"))?;
            let (_, msg, score) = brute_force_byte_xor_cipher(&bytes);
            if score > best_english_score {
                best_english_score = score;
                best_candidate = msg;
            }
        }
    } else {
        return Err(format!("could not read file {}", path.to_string_lossy()));
    }
    Ok(best_candidate)
}

fn read_lines<P>(filename: P) -> std::io::Result<std::io::Lines<std::io::BufReader<std::fs::File>>>
where
    P: AsRef<std::path::Path>,
{
    let file = std::fs::File::open(filename)?;
    Ok(std::io::BufReader::new(file).lines())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_encrypted_string() {
        let path = std::path::Path::new("./data/set01/c04.hex");

        let x = find_byte_xor_encrypted_string(path.to_path_buf()).unwrap();

        assert_eq!(x, "Now that the party is jumping\n".to_string());
    }
}
