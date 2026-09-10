//! Pure protocol builders.  Device-specific credentials are deliberately not
//! included here; the authentication exchange must be supplied by a licensed
//! deployment rather than copied into the repository.

use aes::Aes128;
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use sha1::{Digest, Sha1};

use crate::Error;

pub const SECURE_COMMAND_SIZE: usize = 512;
pub const SECURE_PAYLOAD_SIZE: usize = 496;

pub fn swap_words(data: &mut [u8], count: usize) -> Result<(), Error> {
    let count = count.min(data.len());
    if count % 2 != 0 { return Err(Error::InvalidArgument("word-swap length must be even")); }
    for pair in data[..count].chunks_exact_mut(2) { pair.swap(0, 1); }
    Ok(())
}

pub fn swap_dwords(data: &[u8]) -> Result<Vec<u8>, Error> {
    if data.len() % 4 != 0 { return Err(Error::InvalidArgument("dword-swap length must be a multiple of four")); }
    Ok(data.chunks_exact(4).flat_map(|x| [x[3], x[2], x[1], x[0]]).collect())
}

pub fn build_secure_command(command: u32, parameter_count: u32, params: &[u8]) -> [u8; SECURE_COMMAND_SIZE] {
    let mut out = [0u8; SECURE_COMMAND_SIZE];
    out[0..4].copy_from_slice(&[(command >> 16) as u8, (command >> 24) as u8, command as u8, (command >> 8) as u8]);
    out[8..12].copy_from_slice(&[(parameter_count >> 16) as u8, (parameter_count >> 24) as u8, parameter_count as u8, (parameter_count >> 8) as u8]);
    out[12..16].fill(0xff);
    let n = params.len().min(SECURE_PAYLOAD_SIZE);
    out[16..16 + n].copy_from_slice(&params[..n]);
    out
}

pub fn sha1_bytes(parts: &[&[u8]]) -> [u8; 20] {
    let mut digest = Sha1::new();
    for part in parts { digest.update(part); }
    digest.finalize().into()
}

pub fn aes_cbc(key: &[u8], input: &[u8], decrypt: bool) -> Result<Vec<u8>, Error> {
    if key.len() != 16 || input.len() % 16 != 0 { return Err(Error::InvalidArgument("AES-128 CBC requires a 16-byte key and block-aligned input")); }
    let cipher = Aes128::new_from_slice(key).map_err(|_| Error::InvalidArgument("invalid AES key"))?;
    let mut out = input.to_vec();
    let mut iv = [0u8; 16];
    if decrypt {
        for block in out.chunks_exact_mut(16) {
            let ciphertext = *GenericArray::from_slice(block); let mut plain = ciphertext;
            cipher.decrypt_block(&mut plain); for (v, prior) in plain.iter_mut().zip(iv) { *v ^= prior; }
            block.copy_from_slice(&plain); iv.copy_from_slice(&ciphertext);
        }
    } else {
        for block in out.chunks_exact_mut(16) {
            for (v, prior) in block.iter_mut().zip(iv) { *v ^= prior; }
            let mut encrypted = GenericArray::clone_from_slice(block); cipher.encrypt_block(&mut encrypted);
            block.copy_from_slice(&encrypted); iv.copy_from_slice(&encrypted);
        }
    }
    Ok(out)
}

pub fn build_bcas_apdu(apdu: &[u8], key: &[u8]) -> Result<(Vec<u8>, u16), Error> {
    if apdu.is_empty() || apdu.len() > 0x10c { return Err(Error::InvalidArgument("B-CAS APDU length out of range")); }
    let total = (apdu.len() + 4 + 1) & !1;
    let encrypted_len = (total + 15) & !15;
    if encrypted_len > 0x110 { return Err(Error::InvalidArgument("B-CAS APDU exceeds relay buffer")); }
    let mut plain = vec![0u8; encrypted_len]; plain[..4].copy_from_slice(&[0xff, 0, 0xff, 0]);
    for i in (0..apdu.len()).step_by(2) { plain[4 + i] = apdu.get(i + 1).copied().unwrap_or(0); plain[5 + i] = apdu[i]; }
    let encrypted = aes_cbc(key, &plain, false)?;
    let mut wire = vec![0u8; encrypted_len]; wire.copy_from_slice(&encrypted);
    swap_words(&mut wire, encrypted_len)?;
    Ok((wire, total as u16))
}

pub fn parse_bcas_response(raw: &[u8], key: &[u8], length: usize) -> Result<Vec<u8>, Error> {
    if length == 0 || length > 512 || length > raw.len() || length % 16 != 0 { return Err(Error::InvalidArgument("invalid B-CAS response length")); }
    let mut wire = raw[..length].to_vec(); swap_words(&mut wire, length)?;
    let plain = aes_cbc(key, &wire, true)?;
    if plain.len() >= 4 && plain[..4] == [0xff, 0, 0xff, 0] { Ok(plain[4..].to_vec()) } else { Err(Error::ProtocolUnavailable("B-CAS response header validation failed")) }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn secure_header_encoding_is_word_swapped() { let c = build_secure_command(0x01010000, 8, &[1, 2]); assert_eq!(&c[..4], &[1, 1, 0, 0]); assert_eq!(&c[8..12], &[0, 0, 8, 0]); }
    #[test] fn swap_rejects_odd_length() { assert!(swap_words(&mut [1, 2, 3], 3).is_err()); }
    #[test] fn aes_round_trip() { let input = [7u8; 32]; let key = [3u8; 16]; assert_eq!(aes_cbc(&key, &aes_cbc(&key, &input, false).unwrap(), true).unwrap(), input); }
}
