use std::fs::{File, OpenOptions};
use std::os::windows::io::AsRawHandle;
use std::thread::sleep;
use std::time::Duration;

use clap::{Parser, Subcommand};
use common::{InjectCommand, IOCTL_KIT_PROCESS_CALLBACK_PATCH};
use postcard::to_allocvec;
use winioctl::{ioctl_write_len, DeviceType, Error};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Inject { dll_path: String, pid: u32 },
}

fn main() -> Result<(), Error> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .open("\\??\\Example")?;
    let cli = Cli::parse();

    match &cli.command {
        Some(Commands::Inject { dll_path, pid }) => inject_dll(&file, pid, dll_path)?,
        None => println!("Provide a command"),
    }

    Ok(())
}
ioctl_write_len!(
    ioctl_inject,
    DeviceType::Unknown,
    IOCTL_KIT_PROCESS_CALLBACK_PATCH,
    u8
);

fn inject_dll(file: &File, pid: &u32, dll_path: &String) -> Result<(), Error> {
    let encoded = InjectCommand {
        pid: *pid,
        dll_path: (*dll_path.clone()).to_string(),
    };
    let encoded = to_allocvec(&encoded).unwrap();
    println!("sending data {}", encoded.len());
    unsafe {
        ioctl_inject(file.as_raw_handle(), encoded.as_ptr(), encoded.len() as u32)?;
    }

    sleep(Duration::from_secs(40));

    Ok(())
}
