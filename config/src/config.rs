// wallet/config/src/config.rs
// Copyright 2025 Lurker Developers

use dirs;
use rand::distributions::{Alphanumeric, Distribution};
use rand::thread_rng;
use std::env;
use std::fs::{self, File};
use std::io::prelude::*;
use std::io::BufReader;
use std::path::PathBuf;
use toml;

use crate::comments::{insert_comments, migrate_comments};
use crate::core::global;
use crate::core::global::ChainTypes;
use crate::types::{ConfigError, GlobalWalletConfig, GlobalWalletConfigMembers, WalletConfig};
use crate::util::logger::LoggingConfig;

/// Wallet configuration file name
pub const WALLET_CONFIG_FILE_NAME: &str = "lurker-wallet.toml";
const WALLET_LOG_FILE_NAME: &str = "lurker-wallet.log";
const GRIN_HOME: &str = ".lurker"; // Changed from .grin
/// Wallet data directory
pub const GRIN_WALLET_DIR: &str = "wallet_data";
/// Node API secret
pub const API_SECRET_FILE_NAME: &str = ".foreign_api_secret";
/// Owner API secret
pub const OWNER_API_SECRET_FILE_NAME: &str = ".owner_api_secret";

fn get_lurker_path(chain_type: &ChainTypes, create_path: bool) -> Result<PathBuf, ConfigError> {
	let mut lurker_path = match dirs::home_dir() {
		Some(p) => p,
		None => PathBuf::new(),
	};
	lurker_path.push(GRIN_HOME);

	// Fixed: replaced removed shortname() with match
	lurker_path.push(match chain_type {
		ChainTypes::Mainnet => "main",
		ChainTypes::Testnet => "test",
		ChainTypes::UserTesting => "user",
		ChainTypes::AutomatedTesting => "auto",
	});

	if !lurker_path.exists() && create_path {
		fs::create_dir_all(lurker_path.clone())?;
	}

	if !lurker_path.exists() {
		Err(ConfigError::PathNotFoundError(String::from(
			lurker_path.to_str().unwrap(),
		)))
	} else {
		Ok(lurker_path)
	}
}

fn check_config_current_dir(path: &str) -> Option<PathBuf> {
	let p = env::current_dir();
	let mut c = match p {
		Ok(c) => c,
		Err(_) => return None,
	};
	c.push(path);
	if c.exists() {
		Some(c)
	} else {
		None
	}
}

/// Whether a config file exists at the given directory
pub fn config_file_exists(path: &str) -> bool {
	let mut path = PathBuf::from(path);
	path.push(WALLET_CONFIG_FILE_NAME);
	path.exists()
}

/// Create file with api secret
pub fn init_api_secret(api_secret_path: &PathBuf) -> Result<(), ConfigError> {
	let mut api_secret_file = File::create(api_secret_path)?;
	let api_secret: String = Alphanumeric
		.sample_iter(&mut thread_rng())
		.take(20)
		.collect();
	api_secret_file.write_all(api_secret.as_bytes())?;
	Ok(())
}

/// Check if file contains a secret and nothing else
pub fn check_api_secret(api_secret_path: &PathBuf) -> Result<(), ConfigError> {
	let api_secret_file = File::open(api_secret_path)?;
	let buf_reader = BufReader::new(api_secret_file);
	let mut lines_iter = buf_reader.lines();
	let first_line = lines_iter.next();
	if first_line.is_none() || first_line.unwrap().is_err() {
		fs::remove_file(api_secret_path)?;
		init_api_secret(api_secret_path)?;
	}
	Ok(())
}

fn check_api_secret_file(
	chain_type: &ChainTypes,
	data_path: Option<PathBuf>,
	file_name: &str,
) -> Result<(), ConfigError> {
	let lurker_path = match data_path {
		Some(p) => p,
		None => get_lurker_path(chain_type, false)?,
	};
	let mut api_secret_path = lurker_path;
	api_secret_path.push(file_name);
	if !api_secret_path.exists() {
		init_api_secret(&api_secret_path)
	} else {
		check_api_secret(&api_secret_path)
	}
}

/// Handles setup and detection of paths for wallet
pub fn initial_setup_wallet(
	chain_type: &ChainTypes,
	data_path: Option<PathBuf>,
	create_path: bool,
) -> Result<GlobalWalletConfig, ConfigError> {
	if create_path {
		if let Some(p) = data_path.clone() {
			fs::create_dir_all(p)?;
		}
	}

	let (path, config) = if let Some(p) = check_config_current_dir(WALLET_CONFIG_FILE_NAME) {
		let mut path = p.clone();
		path.pop();
		(path, GlobalWalletConfig::new(p.to_str().unwrap())?)
	} else {
		let lurker_path = match data_path {
			Some(p) => p,
			None => get_lurker_path(chain_type, create_path)?,
		};

		let mut config_path = lurker_path.clone();
		config_path.push(WALLET_CONFIG_FILE_NAME);

		match config_path.exists() {
			false => {
				let mut default_config = GlobalWalletConfig::for_chain(chain_type);
				default_config.config_file_path = Some(config_path);
				default_config.update_paths(&lurker_path);
				(lurker_path, default_config)
			}
			true => {
				let mut path = config_path.clone();
				path.pop();
				(
					path,
					GlobalWalletConfig::new(config_path.to_str().unwrap())?,
				)
			}
		}
	};

	check_api_secret_file(chain_type, Some(path.clone()), OWNER_API_SECRET_FILE_NAME)?;
	check_api_secret_file(chain_type, Some(path), API_SECRET_FILE_NAME)?;
	Ok(config)
}

impl Default for GlobalWalletConfigMembers {
	fn default() -> GlobalWalletConfigMembers {
		GlobalWalletConfigMembers {
			config_file_version: Some(2),
			logging: Some(LoggingConfig::default()),
			wallet: WalletConfig::default(),
		}
	}
}

impl Default for GlobalWalletConfig {
	fn default() -> GlobalWalletConfig {
		GlobalWalletConfig {
			config_file_path: None,
			members: Some(GlobalWalletConfigMembers::default()),
		}
	}
}

impl GlobalWalletConfig {
	pub fn for_chain(chain_type: &ChainTypes) -> GlobalWalletConfig {
		let mut defaults_conf = GlobalWalletConfig::default();
		let defaults = &mut defaults_conf.members.as_mut().unwrap().wallet;
		defaults.chain_type = Some(*chain_type);

		match *chain_type {
			ChainTypes::Mainnet => {}
			ChainTypes::Testnet => {
				defaults.api_listen_port = 13415;
				defaults.check_node_api_http_addr = "http://127.0.0.1:13413".to_owned();
			}
			ChainTypes::UserTesting => {
				defaults.api_listen_port = 23415;
				defaults.check_node_api_http_addr = "http://127.0.0.1:23413".to_owned();
			}
			ChainTypes::AutomatedTesting => {}
		}
		defaults_conf
	}

	pub fn new(file_path: &str) -> Result<GlobalWalletConfig, ConfigError> {
		let mut return_value = GlobalWalletConfig::default();
		return_value.config_file_path = Some(PathBuf::from(&file_path));

		let config_file = return_value.config_file_path.clone().unwrap();
		if !config_file.exists() {
			return Err(ConfigError::FileNotFoundError(String::from(
				config_file.to_str().unwrap(),
			)));
		}

		return_value.read_config()
	}

	fn read_config(mut self) -> Result<GlobalWalletConfig, ConfigError> {
		let config_file_path = self.config_file_path.as_mut().unwrap();
		let contents = fs::read_to_string(config_file_path.clone())?;
		let migrated = GlobalWalletConfig::migrate_config_file_version_none_to_2(
			contents,
			config_file_path.to_owned(),
		)?;
		let fixed = GlobalWalletConfig::fix_warning_level(migrated);
		let decoded: Result<GlobalWalletConfigMembers, toml::de::Error> = toml::from_str(&fixed);
		match decoded {
			Ok(gc) => {
				self.members = Some(gc);
				Ok(self)
			}
			Err(e) => Err(ConfigError::ParseError(
				String::from(self.config_file_path.as_mut().unwrap().to_str().unwrap()),
				format!("{}", e),
			)),
		}
	}

	pub fn update_paths(&mut self, wallet_home: &PathBuf) {
		let mut wallet_path = wallet_home.clone();
		wallet_path.push(GRIN_WALLET_DIR);
		self.members.as_mut().unwrap().wallet.data_file_dir =
			wallet_path.to_str().unwrap().to_owned();

		let mut secret_path = wallet_home.clone();
		secret_path.push(OWNER_API_SECRET_FILE_NAME);
		self.members.as_mut().unwrap().wallet.api_secret_path =
			Some(secret_path.to_str().unwrap().to_owned());

		let mut node_secret_path = wallet_home.clone();
		node_secret_path.push(API_SECRET_FILE_NAME);
		self.members.as_mut().unwrap().wallet.node_api_secret_path =
			Some(node_secret_path.to_str().unwrap().to_owned());

		let mut log_path = wallet_home.clone();
		log_path.push(WALLET_LOG_FILE_NAME);
		self.members
			.as_mut()
			.unwrap()
			.logging
			.as_mut()
			.unwrap()
			.log_file_path = log_path.to_str().unwrap().to_owned();
	}

	pub fn ser_config(&mut self) -> Result<String, ConfigError> {
		let encoded: Result<String, toml::ser::Error> =
			toml::to_string(self.members.as_mut().unwrap());
		match encoded {
			Ok(enc) => Ok(enc),
			Err(e) => Err(ConfigError::SerializationError(format!("{}", e))),
		}
	}

	pub fn write_to_file(
		&mut self,
		name: &str,
		migration: bool,
		old_config: Option<String>,
		old_version: Option<u32>,
	) -> Result<(), ConfigError> {
		let conf_out = self.ser_config()?;
		let commented_config = if migration {
			migrate_comments(old_config.unwrap(), conf_out, old_version)
		} else {
			let fixed_config = GlobalWalletConfig::fix_log_level(conf_out);
			insert_comments(fixed_config)
		};
		let mut file = File::create(name)?;
		file.write_all(commented_config.as_bytes())?;
		Ok(())
	}

	fn migrate_config_file_version_none_to_2(
		config_str: String,
		config_file_path: PathBuf,
	) -> Result<String, ConfigError> {
		let config: GlobalWalletConfigMembers =
			toml::from_str(&GlobalWalletConfig::fix_warning_level(config_str.clone())).unwrap();
		if config.config_file_version != None {
			return Ok(config_str);
		}
		let adjusted_config = GlobalWalletConfigMembers {
			config_file_version: GlobalWalletConfigMembers::default().config_file_version,
			..config
		};
		let mut gc = GlobalWalletConfig {
			members: Some(adjusted_config),
			config_file_path: Some(config_file_path.clone()),
		};
		let str_path = config_file_path.into_os_string().into_string().unwrap();
		gc.write_to_file(
			&str_path,
			true,
			Some(config_str),
			config.config_file_version,
		)?;
		let adjusted_config_str = fs::read_to_string(str_path)?;
		Ok(adjusted_config_str)
	}

	fn fix_warning_level(conf: String) -> String {
		conf.replace("Warning", "WARN")
	}

	fn fix_log_level(conf: String) -> String {
		conf.replace("TRACE", "Trace")
			.replace("DEBUG", "Debug")
			.replace("INFO", "Info")
			.replace("WARN", "Warning")
			.replace("ERROR", "Error")
	}
}
