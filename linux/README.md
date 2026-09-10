# recm2tv

`recm2tv` is a standalone Linux CLI for the I-O DATA GV-M2TV (`04bb:053a`).
It is intentionally independent of the macOS SwiftUI and DriverKit targets.

## Status

The USB transport, firmware chunking, MPEG-TS synchronization, AES packet
processing, signal-safe recording loop, secure-command encoding, encrypted
B-CAS relay framing, GPIO setup, tuner initialization/tuning writes, and TRC
register/firmware activation sequence are implemented. Pure protocol tests
cover word swapping, AES-CBC, B-CAS framing, and bounds checks.

Certificate authentication and the B-CAS card/Contents Key exchange are now
implemented from the authorized macOS reference. Credential constants are used
only in memory during the handshake; keys, certificates, card responses, and
ECM keys are never printed or written to disk. A physical tuner, valid
firmware, and B-CAS card remain required for end-to-end validation.

## Linux prerequisites

Install Rust and libusb 1.0 development files (Debian/Ubuntu):

```sh
sudo apt install build-essential pkg-config libusb-1.0-0-dev
```

Install firmware obtained from your own legally licensed device/software in a
private location. Do not commit it. The firmware files must begin with the
device's `MB8AC018` header.

For non-root access, install a udev rule such as
`/etc/udev/rules.d/70-gv-m2tv.rules`:

```text
SUBSYSTEM=="usb", ATTR{idVendor}=="04bb", ATTR{idProduct}=="053a", MODE="0660", GROUP="plugdev"
```

Reload rules and reconnect the tuner. A physical tuner, antenna, and valid
B-CAS card are required for hardware validation.

## Build and usage

```sh
cargo build --release
./target/release/recm2tv --channel 13 --duration 30 --output capture.ts \
  --idle-firmware /private/firmware/idle.bin \
  --trc-firmware /private/firmware/trc.bin
```

Use `--output -` for stdout. Stop recording with Ctrl-C; SIGINT/SIGTERM are
handled by the recording loop and output is flushed. Before hardware testing,
verify `lsusb -d 04bb:053a`; after implementation of the remaining protocol
stages, validate a short capture with `ffprobe`.
