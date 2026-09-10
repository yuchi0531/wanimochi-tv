use std::time::Duration;

use crate::{Error, device::Transport};

const REG_STATE: u32 = 0x82008;
const REG_BOOT: u32 = 0x90070;
const REG_IRQ_STATUS: u32 = 0x90074;
const REG_IRQ_ENABLE: u32 = 0x90078;
const REG_GPIO_CNT: u32 = 0x90014;
const REG_GPIO_OUT: u32 = 0x90018;

pub fn read_state<T: Transport>(transport: &mut T) -> Result<u16, Error> {
    let state = transport.reg_read(REG_STATE, 2)?;
    if state.len() != 2 { return Err(Error::ShortTransfer { expected: 2, actual: state.len() }); }
    Ok(u16::from_be_bytes([state[0], state[1]]))
}

pub fn prepare_firmware<T: Transport>(transport: &mut T, firmware: &[u8]) -> Result<u16, Error> {
    let state = read_state(transport)?;
    if state == 0 { transport.reg_write(REG_IRQ_STATUS, &[0, 4])?; transport.firmware(firmware)?; transport.reg_write(REG_BOOT, &[0, 4])?; }
    Ok(state)
}

pub fn enable_secure_interrupts<T: Transport>(transport: &mut T) -> Result<(), Error> {
    transport.reg_write(REG_IRQ_ENABLE, &[8, 4])
}

pub fn send_idle<T: Transport>(transport: &mut T) -> Result<(), Error> {
    transport.api_command(&[0, 0, 1, 0, 0, 0])?;
    wait_state_change(transport, Duration::from_millis(500), 30)
}

pub fn wait_state_change<T: Transport>(transport: &mut T, timeout: Duration, tries: usize) -> Result<(), Error> {
    for _ in 0..tries { let ack = transport.ack(timeout)?; if ack.first() == Some(&0x20) { return Ok(()); } }
    Err(Error::ProtocolUnavailable("expected state-change ACK was not received"))
}

pub fn setup_gpio<T: Transport>(transport: &mut T) -> Result<(), Error> {
    transport.reg_write(REG_GPIO_CNT, &[0x02, 0xf4])?;
    transport.reg_write(REG_GPIO_OUT, &[0x03, 0xff])
}

const TUNER_INIT: &[&[u8]] = &[&[0xfe, 0xc0, 0xff], &[0x03, 0x80], &[0x09, 0x10], &[0x11, 0x26], &[0x12, 0x0c], &[0x13, 0x2b], &[0x14, 0x40], &[0x1c, 0x2a], &[0x1d, 0xa0], &[0x1e, 0xa8], &[0x1f, 0xa8], &[0x30, 0], &[0x31, 0x0d], &[0x32, 0x79], &[0x34, 0x0f], &[0x38, 0], &[0x39, 0x94], &[0x3a, 0x20], &[0x3b, 0x21], &[0x3c, 0x3f], &[0x71, 0], &[0x75, 0x28], &[0x76, 0x0c], &[0x77, 1], &[0x7d, 0x80], &[0xef, 1], &[0xfe, 0xc0, 0, 0x3f, 2, 0, 3, 0x48, 4, 0, 5, 4, 6, 0x10, 0x2e, 0x15, 0x30, 0x10, 0x45, 0x58, 0x48, 0x19, 0x52, 3, 0x53, 0x44, 0x6a, 0x4b, 0x76, 0, 0x78, 0x18, 0x7a, 0x17, 0x85, 6], &[0xfe, 0xc0, 1, 1]];

pub fn init_tuner<T: Transport>(transport: &mut T) -> Result<(), Error> { for entry in TUNER_INIT { transport.i2c_write(entry)?; } Ok(()) }

pub fn tune_channel<T: Transport>(transport: &mut T, channel: u8) -> Result<(), Error> {
    if !(13..=62).contains(&channel) { return Err(Error::InvalidArgument("channel must be between 13 and 62")); }
    let divider = pll_divider(channel)?;
    transport.i2c_write(&[0xfe, 0xc0, 0x0c, 0x15])?;
    transport.i2c_write(&[0xfe, 0xc0, 0x0d, divider as u8, 0x0e, (divider >> 8) as u8])?;
    transport.i2c_write(&[0xfe, 0xc0, 0x0f, 1])?;
    transport.i2c_write(&[1, 0x40])?;
    transport.i2c_write(&[0x23, 0x4c])?;
    Ok(())
}

pub fn pll_divider(channel: u8) -> Result<u16, Error> {
    if !(13..=62).contains(&channel) { return Err(Error::InvalidArgument("channel must be between 13 and 62")); }
    let frequency_khz = u32::from(channel) * 6000 + 395143;
    Ok(((frequency_khz * 64 + 500) / 1000) as u16)
}

pub fn activate_trc<T: Transport>(transport: &mut T, firmware: &[u8]) -> Result<(), Error> {
    for reg in (0x1000..0x1500).step_by(2) { transport.reg_write(reg, &[0, 0])?; }
    for &(reg, hi, lo) in &[(0x1002, 0x84, 4), (0x1004, 1, 0x84), (0x100a, 0, 0x20), (0x100c, 0, 0x10), (0x101a, 0xb3, 0), (0x101c, 2, 0x0f), (0x104c, 0x9f, 0xc8), (0x1050, 0x80, 0x10), (0x1062, 0x81, 0xf0), (0x1102, 0, 2), (0x1104, 0x61, 0xa8), (0x1136, 1, 0x41), (0x113a, 2, 0x0f)] { transport.reg_write(reg, &[hi, lo])?; }
    transport.api_command(&[0, 0, 4, 0, 0, 0])?; require_ack(transport, Duration::from_secs(1))?; transport.firmware(firmware)?;
    transport.api_command(&[0, 0, 4, 0x20, 0, 0])?; require_ack(transport, Duration::from_secs(1))?; wait_state_change(transport, Duration::from_millis(500), 20)
}

pub fn start_stream<T: Transport>(transport: &mut T) -> Result<(), Error> { transport.api_command(&[0, 0, 5, 0, 0, 2])?; require_ack(transport, Duration::from_secs(1)) }
fn require_ack<T: Transport>(transport: &mut T, timeout: Duration) -> Result<(), Error> { if transport.ack(timeout)?.is_empty() { Err(Error::ProtocolUnavailable("empty device ACK")) } else { Ok(()) } }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn channel_frequency_is_bounded_and_encoded() {
        assert_eq!(pll_divider(13).unwrap(), 0x764a);
        assert!(pll_divider(12).is_err());
        assert!(pll_divider(63).is_err());
    }
}
