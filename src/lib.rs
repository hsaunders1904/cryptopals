mod aes;
mod base64;
mod hash;
mod hmac;
mod md4;
mod prime;
mod prime_tables;
mod sha1;
mod sha256;

mod set01;
mod set02;
mod set03;
mod set04;
mod set05;

pub use aes::{encrypt_aes_128_ecb, AesCipher};
pub use base64::{base64_decode, base64_encode};
pub use hash::Hasher;
pub use hmac::{HmacSha1, HmacSha256};
pub use md4::Md4;
pub use prime::generate_prime;
pub use sha1::Sha1;
pub use sha256::Sha256;

pub use set01::c01::{hex_to_b64, hex_to_bytes};
pub use set01::c02::{xor_bytes, xor_slices};
pub use set01::c03::{brute_force_byte_xor_cipher, score_english_by_frequency};
pub use set01::c04::find_byte_xor_encrypted_string;
pub use set01::c05::repeating_xor_cipher;
pub use set01::c06::{brute_force_repeating_xor, hamming_distance};
pub use set01::c07::decrypt_aes_128_ecb;
pub use set01::c08::score_aes_ecb_likelihood;

pub use set02::c09::{pkcs7_pad, pkcs7_unpad_unchecked};
pub use set02::c10::{decrypt_aes_128_cbc, encrypt_aes_128_cbc};
pub use set02::c11::{aes_encryption_oracle, random_bytes, random_bytes_with_seed, EncryptionMode};
pub use set02::c12::{byte_at_a_time_aes_ecb_decrypt, EcbOracle};
pub use set02::c13::{falsify_admin_account_with_ecb_oracle, UserProfile, UserProfileOracle};
pub use set02::c14::{random_prefix_byte_at_a_time_with_aes_ecb_decrypt, EcbRandomPrefixOracle};
pub use set02::c15::pkcs7_unpad;
pub use set02::c16::{forge_admin_cbc_ciphertext_with_bit_flipping_attack, CbcQueryOracle};

pub use set03::c17::{cbc_padding_oracle_attack, PaddingOracle};
pub use set03::c18::aes_128_ctr;
pub use set03::c19::brute_force_reused_nonce_aes_ctr_ciphertexts;
pub use set03::c21::Mt19937;
pub use set03::c22::break_time_dependent_mt19937_seed;
pub use set03::c23::clone_mt19937_from_output;
pub use set03::c24::{
    detect_time_seeded_mt19973_generated_token, generate_password_reset_token, mt19937_cipher,
    recover_seed_from_mt19937_cipher_encrypted_message,
};

pub use set04::c25::{edit_aes_ctr_ciphertext, recover_ctr_edit_oracle_plaintext, CtrEditOracle};
pub use set04::c26::{forge_admin_ctr_ciphertext_with_bit_flipping_attack, CtrQueryOracle};
pub use set04::c27::{recover_key_from_iv_eq_key_cbc_oracle, CbcIvEqKeyQueryOracle};
pub use set04::c28::authenticate_message_with_sha1;
pub use set04::c29::{
    keyed_sha1_mac_length_extension_attack, LengthExtensionForgery, Sha1KeyedMacOracle,
};
pub use set04::c30::{keyed_md4_mac_length_extension_attack, Md4KeyedMacOracle};
pub use set04::c31::{hmac_sha1_timing_attack, server};
pub use set04::c32::hmac_sha1_timing_attack_with_rounds;

pub use set05::c33::{generate_modexp_keypair, ModExpKeyPair};
pub use set05::c34::{simulate_dh_parameter_injection_attack, Person};
pub use set05::c35::simulate_dh_g_injection_attack;
pub use set05::c36::{
    secure_remote_password, SrpClient, SrpPasswordVerificationResponse, SrpServer,
};
pub use set05::c37::zero_key_secure_remote_password_attack;
pub use set05::c38::{simplified_secure_remote_password_mitm_attack, SimplifiedSrpClient};
pub use set05::c39::{generate_rsa_key_pair, rsa_apply, RsaKeyPair};
