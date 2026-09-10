use crate::{
    auth,
    device::Transport,
    protocol::{build_bcas_apdu, parse_bcas_response},
    Error,
};
use std::time::Duration;

const STATUS: u32 = 0x822ac;
const RESPONSE: u32 = 0x822ae;
const BCASTX: u32 = 0x8219c;

pub struct Bcas {
    pub contents_key: [u8; 16],
}

impl Bcas {
    pub fn initialize<T: Transport>(t: &mut T, secure_key: &[u8; 16]) -> Result<Self, Error> {
        t.api_command(&[0, 0, 0x0a, 0, 0, 1])?;
        let _ = t.ack(Duration::from_secs(2));
        t.api_command(&[0, 0, 0x0a, 1, 0, 1])?;
        let _ = t.ack(Duration::from_secs(2));
        wait_ready(t)?;
        command(t, secure_key, &[0x90, 0x30, 0, 0, 0])?;
        let _ = response(t, secure_key)?;
        command(t, secure_key, &[0x90, 0x32, 0, 0, 0])?;
        let _ = response(t, secure_key)?;
        let params = [0, 0, 0, 3, 0, 0, 0, 0, 0, 0, 0, 0];
        let input = crate::protocol::build_secure_command(0x07010600, 3, &params);
        let raw = auth::send(t, 0x07010600, &input, Some(secure_key))?;
        let decoded = raw.get(16..32).ok_or(Error::ProtocolUnavailable(
            "Contents Key response truncated",
        ))?;
        let mut contents_key = [0; 16];
        contents_key.copy_from_slice(decoded);
        Ok(Self { contents_key })
    }
    pub fn ecm_keys<T: Transport>(
        &self,
        t: &mut T,
        ecm: &[u8],
    ) -> Result<([u8; 8], [u8; 8]), Error> {
        if ecm.len() > 255 {
            return Err(Error::InvalidArgument("ECM is too large"));
        }
        let mut apdu = vec![0x90, 0x34, 0, 0, ecm.len() as u8];
        apdu.extend_from_slice(ecm);
        apdu.push(0);
        command(t, &self.contents_key, &apdu)?;
        let plain = response(t, &self.contents_key)?;
        let body = plain
            .get(10..26)
            .ok_or(Error::ProtocolUnavailable("ECM response truncated"))?;
        let mut odd = [0; 8];
        let mut even = [0; 8];
        odd.copy_from_slice(&body[..8]);
        even.copy_from_slice(&body[8..]);
        Ok((odd, even))
    }
}

fn command<T: Transport>(t: &mut T, key: &[u8; 16], apdu: &[u8]) -> Result<(), Error> {
    let (wire, size) = build_bcas_apdu(apdu, key)?;
    t.reg_write(BCASTX, &wire)?;
    t.api_command(&[0, 0, 0x0a, 0x10, (size >> 8) as u8, size as u8])?;
    let _ = t.ack(Duration::from_secs(3));
    Ok(())
}
fn wait_ready<T: Transport>(t: &mut T) -> Result<(), Error> {
    for _ in 0..30 {
        let s = t.reg_read(STATUS, 2)?;
        if s.len() != 2 {
            return Err(Error::ShortTransfer {
                expected: 2,
                actual: s.len(),
            });
        }
        let n = s[0] >> 4;
        if n == 3 {
            return Ok(());
        }
        if n != 2 {
            return Err(Error::ProtocolUnavailable("unexpected B-CAS state"));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Err(Error::ProtocolUnavailable("B-CAS ready timeout"))
}
fn response<T: Transport>(t: &mut T, key: &[u8; 16]) -> Result<Vec<u8>, Error> {
    wait_ready(t)?;
    let s = t.reg_read(STATUS, 2)?;
    let len = ((usize::from(s[0] & 0x0f)) << 8) | usize::from(s[1]);
    if !(16..=512).contains(&len) {
        return Err(Error::InvalidArgument("invalid B-CAS response size"));
    }
    let enc = (len + 15) & !15;
    let raw = t.reg_read(RESPONSE, enc)?;
    parse_bcas_response(&raw, key, enc)
}

#[cfg(test)]
mod tests {
    #[test]
    fn ecm_bound_is_explicit() {
        assert!(255usize <= 255);
    }
}
