use chrono::{DateTime, Utc};
use clap::{Parser, Subcommand};
use crossbeam_channel::{select, Sender};
use notify_debouncer_mini::new_debouncer;
use serde::{Deserialize, Serialize};
use signal_hook::consts::TERM_SIGNALS;
use signal_hook::iterator::Signals;
use std::fmt::Debug;
use std::fs::{read_to_string, File};
use std::io::{BufReader, BufWriter, Write};
use std::path::PathBuf;
use std::process::exit;
use std::time::Duration;
use std::{env, thread};
use thiserror::Error;
use tracing::{debug, error, info, warn};

#[derive(Debug, Error)]
enum ConfigError {
    #[error("environment variable {0} not set: {1}")]
    Env(&'static str, std::env::VarError),
    #[error("{0}: ")]
    Parse(&'static str, String),
    #[error("this should never happen: {0}")]
    Infallible(#[from] std::convert::Infallible),
    #[error("environment parsing value as int: {0}")]
    IntParse(#[from] std::num::ParseIntError),
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
struct NetBoxResult {
    count: u32,
}

#[derive(Deserialize)]
struct NetBoxDevice {
    #[serde(rename = "platform__slug")]
    platform: String,
    custom_field_data: NetBoxDeviceCustomFieldData,
}

#[derive(Debug)]
struct ConfigGenerator {
    netbox_url: String,
    netbox_object_changes_url: String,
    netbox_token_file: PathBuf,
    username_file: PathBuf,
    password_file: PathBuf,
    output_file: PathBuf,
    oxidized_url: String,
    last_config: DateTime<Utc>,
}

#[derive(Debug)]
struct Config {
    config_interval_s: u64,
}

impl Config {
    fn from_env() -> Result<Self, ConfigError> {
        Ok(Config {
            config_interval_s: read_env_parse("NB_OXIDIZED_CONFIG_INTERVAL_S")?,
        })
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

fn read_env_parse<T: std::str::FromStr>(var: &'static str) -> Result<T, ConfigError>
where
    <T as std::str::FromStr>::Err: std::fmt::Display,
{
    env::var(var)
        .map_err(|err| ConfigError::Env(var, err))?
        .parse()
        .map_err(|err: T::Err| ConfigError::Parse(var, err.to_string()))
}

impl ConfigGenerator {
    fn from_env() -> Result<Self, ConfigError> {
        Ok(ConfigGenerator {
            netbox_url: read_env_parse("NB_OXIDIZED_NETBOX_URL")?,
            netbox_object_changes_url: read_env_parse("NB_OXIDIZED_NETBOX_OBJECT_CHANGES_URL")?,
            netbox_token_file: read_env_parse("NB_OXIDIZED_NETBOX_TOKEN_FILE")?,
            username_file: read_env_parse("NB_OXIDIZED_USERNAME_FILE")?,
            password_file: read_env_parse("NB_OXIDIZED_PASSWORD_FILE")?,
            output_file: read_env_parse("NB_OXIDIZED_OUTPUT_FILE")?,
            oxidized_url: read_env_parse("NB_OXIDIZED_OXIDIZED_URL")?,
            last_config: Utc::now(),
        })
    }

    fn update_oxidized(&self) -> Result<(), Error> {
        ureq::get(&self.oxidized_url)
            .timeout(Duration::from_secs(10))
            .call()
            .map_err(|e| Error::OxidizedReload(Box::new(e)))?;
        Ok(())
    }

    fn get_netbox_devices(&self, netbox_token: &str) -> Result<Vec<NetBoxDevice>, Error> {
        ureq::get(&self.netbox_url)
            .query("time_after", &self.last_config.format("%+").to_string())
            .query("brief", "1")
            .query("limit", "1")
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

    fn netbox_changed(&self, netbox_token: &str) -> bool {
        let resp = ureq::get(&self.netbox_object_changes_url)
            .set("Authorization", &("Token ".to_string() + netbox_token))
            .timeout(Duration::from_secs(20))
            .call()
            .map_err(|e| Error::NetBox(Box::new(e)));

        match resp {
            Ok(resp) => match resp.into_json::<NetBoxResult>() {
                Ok(result) => result.count > 0,
                Err(err) => {
                    error!(err = ?err, "error unmarshalling NetBox object-changes");
                    false
                }
            },
            Err(err) => {
                error!(err = ?err, "error getting NetBox object-changes");
                false
            }
        }
    }

    // Returns Ok(device count) on success or error.
    fn generate_config(
        &mut self,
        oxidized_reload: bool,
        force: bool,
    ) -> Result<Option<usize>, Error> {
        // read all secrets
        let netbox_token = read_to_string(&self.netbox_token_file).map_err(Error::SecretRead)?;
        let username = read_to_string(&self.username_file).map_err(Error::SecretRead)?;
        let password = read_to_string(&self.password_file).map_err(Error::SecretRead)?;

        if !force && self.netbox_changed(&netbox_token) {
            debug!(last_config = %self.last_config, "NetBox has not changed");
            return Ok(None);
        }

        let netbox_devices = self.get_netbox_devices(&netbox_token)?;
        let device_count = netbox_devices.len();

        let oxidized_config =
            ConfigGenerator::generate_oxidized_source(netbox_devices, username, password);

        self.write_config(oxidized_config)?;

        if oxidized_reload {
            self.update_oxidized()?;
        }

        self.last_config = Utc::now();

        Ok(Some(device_count))
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

fn run(config: Config, mut cg: ConfigGenerator) {
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
    match cg.generate_config(false, true) {
        Ok(count) => info!(devices = count, "initial config generated successfully"),
        Err(err) => {
            error!(err = %err, "error generating initial config");
            exit(1);
        }
    }

    let (sig_tx, sig_rx) = crossbeam_channel::bounded(1);
    thread::spawn(move || sig_channel(sig_tx));

    let mut generate_config = || match cg.generate_config(true, false) {
        Ok(None) => debug!("no NetBox changes"),
        Ok(Some(count)) => info!(devices = count, "new config generated successfully"),
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
    #[arg(long, default_value = "info")]
    log_level: tracing::Level,
}

#[derive(Subcommand)]
enum Commands {
    StartupProbe,
    Run,
}

fn main() -> Result<(), ConfigError> {
    let args = Cli::parse();
    tracing_subscriber::fmt()
        .with_max_level(args.log_level)
        .init();

    let config = Config::from_env()?;
    let cg = ConfigGenerator::from_env()?;

    match args.command {
        Commands::StartupProbe => startup_probe(cg),
        Commands::Run => run(config, cg),
    }

    Ok(())
}
