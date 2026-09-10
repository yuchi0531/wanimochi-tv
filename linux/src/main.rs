use clap::Parser;
use recm2tv::{Error, auth, bcas::Bcas, device::{Transport, UsbTransport, load_firmware}, lifecycle, ts::{decrypt_packet, synchronize}};
use std::{io::Write, path::PathBuf, sync::{Arc, atomic::{AtomicBool, Ordering}}, time::{Duration, Instant}};

#[derive(Parser, Debug)]
#[command(name = "recm2tv", about = "Record decrypted MPEG-TS from a GV-M2TV tuner")]
struct Args {
    #[arg(long, value_parser = clap::value_parser!(u8).range(13..=62))] channel: u8,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))] duration: u64,
    #[arg(long, default_value = "-")] output: PathBuf,
    #[arg(long)] idle_firmware: PathBuf,
    #[arg(long)] trc_firmware: PathBuf,
}

fn run(args: Args, stop: &AtomicBool) -> Result<(), Error> {
    let idle = load_firmware(&args.idle_firmware)?; let trc = load_firmware(&args.trc_firmware)?;
    let mut transport = UsbTransport::open()?;
    lifecycle::prepare_firmware(&mut transport, &idle)?; lifecycle::enable_secure_interrupts(&mut transport)?;
    lifecycle::send_idle(&mut transport)?; lifecycle::setup_gpio(&mut transport)?; lifecycle::init_tuner(&mut transport)?;
    lifecycle::tune_channel(&mut transport, args.channel)?; lifecycle::activate_trc(&mut transport, &trc)?;
    let secure_key = auth::authenticate(&mut transport)?;
    let bcas = Bcas::initialize(&mut transport, &secure_key)?;
    lifecycle::start_stream(&mut transport)?;
    let mut output: Box<dyn Write> = if args.output.as_os_str() == "-" { Box::new(std::io::stdout()) } else { Box::new(std::fs::File::create(args.output)?) };
    record_stream(&mut transport, &mut output, &bcas.contents_key, Duration::from_secs(args.duration), stop)
}

fn main() {
    let args = Args::parse();
    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = Arc::clone(&stop);
    if let Err(error) = ctrlc::set_handler(move || signal_stop.store(true, Ordering::Relaxed)) {
        eprintln!("recm2tv: cannot install signal handler: {error}");
        std::process::exit(1);
    }
    if let Err(e) = run(args, &stop) { eprintln!("recm2tv: {e}"); std::process::exit(1); }
}

#[allow(dead_code)]
fn record_stream<T: Transport>(transport: &mut T, output: &mut dyn Write, key: &[u8], duration: Duration, stop: &AtomicBool) -> Result<(), Error> {
    let start = Instant::now(); let mut carry = Vec::new(); let mut buf = vec![0; 16 * 1024];
    while !stop.load(Ordering::Relaxed) && start.elapsed() < duration { let n = transport.ts_read(&mut buf, Duration::from_millis(500))?; for mut packet in synchronize(&buf[..n], &mut carry) { decrypt_packet(&mut packet, key); output.write_all(&packet)?; } }
    output.flush()?; Ok(())
}
