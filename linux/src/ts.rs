use aes::Aes128;
use cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};

pub const TS_PACKET_SIZE: usize = 188;
const IV: [u8; 16] = [
    0xec, 0x8f, 0x4b, 0x6a, 0xd9, 0x2a, 0x36, 0x89, 0x2b, 0xdf, 0xb6, 0x18, 0xfc, 0x25, 0x5e, 0xfc,
];

pub fn synchronize(input: &[u8], carry: &mut Vec<u8>) -> Vec<[u8; TS_PACKET_SIZE]> {
    carry.extend_from_slice(input);
    let mut out = Vec::new();
    let mut pos = 0;
    while pos + TS_PACKET_SIZE <= carry.len() {
        if carry[pos] != 0x47 {
            pos += 1;
            continue;
        }
        let mut p = [0; TS_PACKET_SIZE];
        p.copy_from_slice(&carry[pos..pos + TS_PACKET_SIZE]);
        out.push(p);
        pos += TS_PACKET_SIZE;
    }
    carry.drain(..pos);
    out
}

pub fn decrypt_packet(packet: &mut [u8], key: &[u8]) -> bool {
    if packet.len() != TS_PACKET_SIZE || packet[0] != 0x47 || key.len() != 16 || packet[3] >> 6 == 0
    {
        return false;
    }
    let adapt = (packet[3] >> 4) & 3;
    if adapt == 2 {
        return false;
    }
    let offset = if adapt == 3 {
        5usize.saturating_add(packet[4] as usize)
    } else {
        4
    };
    if offset >= TS_PACKET_SIZE {
        return false;
    }
    let len = TS_PACKET_SIZE - offset;
    let cbc_len = len & !15;
    let cipher = Aes128::new(GenericArray::from_slice(key));
    let mut ofb_iv = IV;
    if cbc_len >= 16 {
        ofb_iv.copy_from_slice(&packet[offset + cbc_len - 16..offset + cbc_len]);
    }
    let mut previous = IV;
    for block in packet[offset..offset + cbc_len].chunks_exact_mut(16) {
        let ciphertext = *GenericArray::from_slice(block);
        let mut decrypted = ciphertext;
        cipher.decrypt_block(&mut decrypted);
        for (value, prior) in decrypted.iter_mut().zip(previous) {
            *value ^= prior;
        }
        block.copy_from_slice(&decrypted);
        previous.copy_from_slice(&ciphertext);
    }
    if len > cbc_len {
        let mut stream = GenericArray::clone_from_slice(&ofb_iv);
        cipher.encrypt_block(&mut stream);
        for (a, b) in packet[offset + cbc_len..].iter_mut().zip(stream.iter()) {
            *a ^= b;
        }
    }
    packet[3] &= 0x3f;
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sync_keeps_partial_packet() {
        let mut c = vec![1, 2];
        let p = vec![0x47; 188];
        let out = synchronize(&p[..100], &mut c);
        assert!(out.is_empty());
        let out = synchronize(&p[100..], &mut c);
        assert_eq!(out.len(), 1);
    }
    #[test]
    fn decrypt_rejects_bad_bounds() {
        assert!(!decrypt_packet(&mut [0; 188], &[0; 16]));
        assert!(!decrypt_packet(&mut [0x47; 188], &[0; 15]));
    }
}
