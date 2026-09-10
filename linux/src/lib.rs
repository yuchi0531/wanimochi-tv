pub mod auth;
pub mod bcas;
pub mod device;
pub mod lifecycle;
pub mod protocol;
pub mod ts;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("USB error: {0}")]
    Usb(#[from] rusb::Error),
    #[error("device not found (VID:PID 04bb:053a)")]
    DeviceNotFound,
    #[error("invalid firmware: expected MB8AC018 header")]
    InvalidFirmware,
    #[error("short USB transfer: expected {expected} bytes, got {actual}")]
    ShortTransfer { expected: usize, actual: usize },
    #[error("protocol is not available: {0}")]
    ProtocolUnavailable(&'static str),
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
