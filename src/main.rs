use clap::{Parser, Subcommand};
use crossbeam_channel::{select, Sender};
use notify_debouncer_mini::new_debouncer;
use serde::{Deserialize, Serialize};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;
use std::fs::{read_to_string, File};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::thread;
use std::time::Duration;
use thiserror::Error;
use tracing::{error, info, warn};

#[derive(Debug, Error)]
enum ConfigError {
    #[error("error opening config file: {0}")]
    File(#[from] io::Error),
    #[error("error parsing config file: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Serialize, Deserialize)]
struct OxidizedDevice {
    name: String,
    model: String,
    username: String,
    password: String,
}

#[derive(Deserialize)]
struct NetBoxDeviceCustomFieldData {
    fqdn: String,
}

#[derive(Deserialize)]
struct NetBoxDevice {
    #[serde(rename = "platform__slug")]
    platform: String,
    custom_field_data: NetBoxDeviceCustomFieldData,
}

#[derive(Debug, Deserialize)]
struct ConfigGenerator {
    netbox_url: String,
    username_file: PathBuf,
    password_file: PathBuf,
    netbox_token_file: PathBuf,
    output_file: PathBuf,
    oxidized_url: String,
}

#[derive(Debug, Deserialize)]
struct Config {
    config_interval_s: u64,
    #[serde(flatten)]
    config_generator: ConfigGenerator,
}

impl Config {
    fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let config = serde_json::from_reader(reader)?;

        Ok(config)
    }
}

#[derive(Error, Debug)]
enum Error {
    #[error("NetBox error: {0}")]
    NetBox(Box<ureq::Error>),
    #[error("IO error reading NetBox repsponse: {0}")]
    NetBoxIo(std::io::Error),
    #[error("error reading secret: {0}")]
    SecretRead(std::io::Error),
    #[error("error writing output: {0}")]
    Output(std::io::Error),
    #[error("error serializing output: {0}")]
    OutputJson(serde_json::Error),
    #[error("error reloading oxidized: {0}")]
    OxidizedReload(Box<ureq::Error>),
}

impl ConfigGenerator {
    fn update_oxidized(&self) -> Result<(), Error> {
        ureq::post(&self.oxidized_url)
            .timeout(Duration::from_secs(10))
            .call()
            .map_err(|e| Error::OxidizedReload(Box::new(e)))?;
        Ok(())
    }

    fn get_netbox_devices(&self, netbox_token: &str) -> Result<Vec<NetBoxDevice>, Error> {
        ureq::get(&self.netbox_url)
            .set("Authorization", &("Token ".to_string() + netbox_token))
            .timeout(Duration::from_secs(20))
            .call()
            .map_err(|e| Error::NetBox(Box::new(e)))?
            .into_json::<Vec<NetBoxDevice>>()
            .map_err(Error::NetBoxIo)
    }

    fn generate_oxidized_source(
        devices: Vec<NetBoxDevice>,
        username: String,
        password: String,
    ) -> Vec<OxidizedDevice> {
        devices
            .into_iter()
            .map(|d| OxidizedDevice {
                name: d.custom_field_data.fqdn,
                model: d.platform,
                username: username.clone(),
                password: password.clone(),
            })
            .collect()
    }

    fn write_config(&self, config: Vec<OxidizedDevice>) -> Result<(), Error> {
        let file = File::create(&self.output_file).map_err(Error::Output)?;
        let mut writer = BufWriter::new(file);
        serde_json::to_writer(&mut writer, &config).map_err(Error::OutputJson)?;
        writer.flush().map_err(Error::Output)?;

        Ok(())
    }

    // Returns Ok(device count) on success or error.
    fn generate_config(&self, oxidized_reload: bool) -> Result<usize, Error> {
        // read all secrets
        let netbox_token = read_to_string(&self.netbox_token_file).map_err(Error::SecretRead)?;
        let username = read_to_string(&self.username_file).map_err(Error::SecretRead)?;
        let password = read_to_string(&self.password_file).map_err(Error::SecretRead)?;

        let netbox_devices = self.get_netbox_devices(&netbox_token)?;
        let device_count = netbox_devices.len();

        let oxidized_config =
            ConfigGenerator::generate_oxidized_source(netbox_devices, username, password);

        self.write_config(oxidized_config)?;

        if oxidized_reload {
            self.update_oxidized()?;
        }

        Ok(device_count)
    }
}

fn startup_probe(cg: ConfigGenerator) {
    match File::open(cg.output_file) {
        Ok(f) => {
            let reader = BufReader::new(f);
            if let Err(err) = serde_json::from_reader::<_, Vec<OxidizedDevice>>(reader) {
                error!(err = ?err, "error parsing output file");
                exit(1)
            }
            exit(0)
        }
        Err(err) => {
            error!(err = ?err, "error opening output file");
            exit(1);
        }
    }
}

fn sig_channel(tx: Sender<i32>) {
    let mut sigs = Signals::new(TERM_SIGNALS).expect("error setting up signal handler");
    for signal in sigs.forever() {
        tx.send(signal).expect("error sending to sig tx channel");
    }
}

fn run(config: Config) {
    let cg = config.config_generator;

    let (notify_tx, notify_rx) = crossbeam_channel::bounded(1);
    let mut debouncer =
        new_debouncer(Duration::from_secs(10), notify_tx).expect("error creating notify debouncer");
    debouncer
        .watcher()
        .watch(
            &cg.password_file,
            notify_debouncer_mini::notify::RecursiveMode::NonRecursive,
        )
        .expect("error watching file");

    // Initial config
    info!("generating initial config");
    match cg.generate_config(false) {
        Ok(count) => info!(devices = count, "initial config generated successfully"),
        Err(err) => {
            error!(err = %err, "error generating initial config");
            exit(1);
        }
    }

    let (sig_tx, sig_rx) = crossbeam_channel::bounded(1);
    thread::spawn(move || sig_channel(sig_tx));

    let generate_config = || match cg.generate_config(true) {
        Ok(count) => info!(devices = count, "new config generated successfully"),
        Err(err) => error!(err = %err, "error generating config"),
    };

    loop {
        select! {
        recv(sig_rx) -> sig => match sig {
            Ok(sig) => {
                warn!(sig = sig, "received signal");
                break;
            }
            Err(err) => {
                error!(err = ?err, "error receiving from signal channel");
                exit(1);
            }
        },
        recv(notify_rx) -> msg => match msg {
                Ok(Err(err)) => {
                    error!(err = ?err, "error from notify");
                }
                Ok(Ok(_)) => {
                    info!("password change: generating new config");
                    generate_config();
                }
                Err(err) => {
                    error!(err = ?err, "error receiving from channel");
                    exit(1);
                }
            },
        default(Duration::from_secs(config.config_interval_s)) => {
            info!("schedule: generating new config");
            generate_config();
        }
        }
    }
}

#[derive(Parser)]
#[command(version = env!("VERSION_STRING"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    #[arg(long, default_value = "config.json")]
    config: PathBuf,
}

#[derive(Subcommand)]
enum Commands {
    StartupProbe,
    Run,
}

fn main() {
    tracing_subscriber::fmt::init();

    let args = Cli::parse();
    match Config::from_file(args.config) {
        Ok(cg) => match args.command {
            Commands::StartupProbe => startup_probe(cg.config_generator),
            Commands::Run => run(cg),
        },
        Err(err) => {
            error!(err = %err, "error reading config");
            exit(1);
        }
    }
}
