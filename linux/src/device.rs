use crate::{Error, ts::TS_PACKET_SIZE};
use rusb::{Context, DeviceHandle, UsbContext};
use std::{fs, path::Path, time::Duration};

pub const VID: u16 = 0x04bb;
pub const PID: u16 = 0x053a;
const IFACE: u8 = 0;
const EP_FIRMWARE: u8 = 0x02;
const EP_ACK: u8 = 0x83;
const EP_TS: u8 = 0x81;
const API: u8 = 0xb8;
const REG: u8 = 0xbc;
const I2C: u8 = 0xbd;
const I2C_INDEX: u16 = 0x1800;

pub trait Transport {
    fn reg_read(&mut self, reg: u32, len: usize) -> Result<Vec<u8>, Error>;
    fn reg_write(&mut self, reg: u32, data: &[u8]) -> Result<(), Error>;
    fn api_command(&mut self, command: &[u8]) -> Result<(), Error>;
    fn ack(&mut self, timeout: Duration) -> Result<Vec<u8>, Error>;
    fn firmware(&mut self, data: &[u8]) -> Result<(), Error>;
    fn i2c_write(&mut self, data: &[u8]) -> Result<(), Error>;
    fn i2c_read(&mut self, register: u8, len: usize) -> Result<Vec<u8>, Error>;
    fn ts_read(&mut self, data: &mut [u8], timeout: Duration) -> Result<usize, Error>;
}

pub struct UsbTransport {
    handle: DeviceHandle<Context>,
    sequence: u8,
}

impl UsbTransport {
    pub fn open() -> Result<Self, Error> {
        let context = Context::new()?;
        let device = context.devices()?.iter().find(|d| {
            d.device_descriptor().map(|x| x.vendor_id() == VID && x.product_id() == PID).unwrap_or(false)
        }).ok_or(Error::DeviceNotFound)?;
        let handle = device.open()?;
        if handle.kernel_driver_active(IFACE).unwrap_or(false) { let _ = handle.detach_kernel_driver(IFACE); }
        handle.claim_interface(IFACE)?;
        Ok(Self { handle, sequence: 0 })
    }

    fn control(&mut self, request_type: u8, request: u8, value: u16, index: u16, data: &mut [u8], timeout: Duration) -> Result<usize, Error> {
        let n = if request_type & 0x80 != 0 {
            self.handle.read_control(request_type, request, value, index, data, timeout)?
        } else {
            self.handle.write_control(request_type, request, value, index, data, timeout)?
        };
        Ok(n)
    }

    fn reg_value(reg: u32) -> (u16, u16) { (((reg >> 8) & 0xf00) as u16, (reg & 0xffff) as u16) }
}

impl Transport for UsbTransport {
    fn reg_read(&mut self, reg: u32, len: usize) -> Result<Vec<u8>, Error> {
        let (value, index) = Self::reg_value(reg); let mut data = vec![0; len];
        let n = self.control(0xc0, REG, value, index, &mut data, Duration::from_secs(3))?;
        if n != len { return Err(Error::ShortTransfer { expected: len, actual: n }); } Ok(data)
    }
    fn reg_write(&mut self, reg: u32, data: &[u8]) -> Result<(), Error> {
        let (value, index) = Self::reg_value(reg); let mut data = data.to_vec();
        let n = self.control(0x40, REG, value, index, &mut data, Duration::from_secs(3))?;
        if n != data.len() { return Err(Error::ShortTransfer { expected: data.len(), actual: n }); } Ok(())
    }
    fn api_command(&mut self, command: &[u8]) -> Result<(), Error> {
        if command.len() != 6 { return Err(Error::InvalidArgument("API commands must be six bytes")); }
        let mut data = command.to_vec(); data[1] = self.sequence; self.sequence = (self.sequence + 1) % 0x3f;
        let n = self.control(0x40, API, 0, 0, &mut data, Duration::from_secs(3))?;
        if n != data.len() { return Err(Error::ShortTransfer { expected: data.len(), actual: n }); } Ok(())
    }
    fn ack(&mut self, timeout: Duration) -> Result<Vec<u8>, Error> { let mut b = [0u8; 64]; let n = self.handle.read_interrupt(EP_ACK, &mut b, timeout)?; Ok(b[..n].to_vec()) }
    fn firmware(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.len() < 8 || &data[..8] != b"MB8AC018" { return Err(Error::InvalidFirmware); }
        self.handle.clear_halt(EP_FIRMWARE)?;
        for chunk in data.chunks(512) { let n = self.handle.write_bulk(EP_FIRMWARE, chunk, Duration::from_secs(3))?; if n != chunk.len() { return Err(Error::ShortTransfer { expected: chunk.len(), actual: n }); } }
        Ok(())
    }
    fn i2c_write(&mut self, data: &[u8]) -> Result<(), Error> {
        if data.is_empty() || data.len() > 255 { return Err(Error::InvalidArgument("I2C write length out of range")); }
        let mut payload = data.to_vec(); let n = self.control(0x40, I2C, 0, I2C_INDEX, &mut payload, Duration::from_secs(3))?;
        if n != payload.len() { return Err(Error::ShortTransfer { expected: payload.len(), actual: n }); }
        Ok(())
    }
    fn i2c_read(&mut self, register: u8, len: usize) -> Result<Vec<u8>, Error> {
        if len == 0 || len > 255 { return Err(Error::InvalidArgument("I2C read length out of range")); }
        let mut address = [register]; self.control(0x40, I2C, 0, I2C_INDEX, &mut address, Duration::from_secs(3))?;
        let mut status = [0x08, 0x08]; let _ = self.control(0xc0, I2C, 0x000f, I2C_INDEX, &mut status, Duration::from_secs(3));
        let mut data = vec![0; len]; let n = self.control(0xc0, I2C, 0, I2C_INDEX, &mut data, Duration::from_secs(3))?;
        if n != len { return Err(Error::ShortTransfer { expected: len, actual: n }); } Ok(data)
    }
    fn ts_read(&mut self, data: &mut [u8], timeout: Duration) -> Result<usize, Error> { Ok(self.handle.read_bulk(EP_TS, data, timeout)?) }
}

pub fn load_firmware(path: &Path) -> Result<Vec<u8>, Error> {
    let data = fs::read(path)?;
    validate_firmware(&data)?;
    Ok(data)
}

pub fn validate_firmware(data: &[u8]) -> Result<(), Error> {
    if data.len() < 8 || &data[..8] != b"MB8AC018" { return Err(Error::InvalidFirmware); }
    Ok(())
}

pub fn validate_packet_buffer(data: &[u8]) -> bool { data.len() >= TS_PACKET_SIZE }

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn firmware_header_is_checked_without_logging_contents() {
        assert!(validate_firmware(b"MB8AC018payload").is_ok());
        assert!(matches!(validate_firmware(b"bad"), Err(Error::InvalidFirmware)));
    }
    #[test]
    fn register_fields_match_usb_encoding() {
        assert_eq!(UsbTransport::reg_value(0x82008), (0x200, 0x2008));
    }
}
