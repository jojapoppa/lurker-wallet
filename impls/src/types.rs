// Copyright 2021 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Types and traits that should be provided by a wallet implementation

use crate::config::WalletConfig;
use crate::error::Error;
use crate::lurker_core::core::hash::Hash;
use crate::lurker_core::core::{FeeFields, Output, Transaction, TxKernel};
use crate::lurker_core::libtx::error as libtx_error;
use crate::lurker_core::{global, ser};
use crate::lurker_keychain::error as keychain_error;
use crate::lurker_keychain::{Identifier, Keychain};
use crate::lurker_store::error as store_error;
use crate::lurker_util::logger::LoggingConfig;
use crate::lurker_util::secp::key::{PublicKey, SecretKey};
use crate::lurker_util::secp::pedersen::{Commitment, RangeProof};
use crate::lurker_util::secp::{self, Secp256k1};
use crate::lurker_util::{ToHex, ZeroingString};
use crate::slate_versions::ser as dalek_ser;
use crate::InitTxArgs;
use chrono::prelude::*;
use ed25519_dalek::{PublicKey as DalekPublicKey, Signature as DalekSignature};
use rand::{rngs::mock::StepRng, thread_rng};
use serde;
use serde_json;
use std::collections::HashMap;
use std::fmt;
use std::path::Path;
use std::time::Duration;
use uuid::Uuid;

use crate::lurker_core::libtx::aggsig;

/// Combined trait to allow dynamic wallet dispatch
pub trait WalletInst<'a, L, C, K>: WalletBackend<'a, C, K> + Send + Sync
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn lc_provider(&self) -> Result<L, Error>;
	fn w2n_client(&self) -> C;
	fn keychain_mask(&self) -> Option<&SecretKey>;
}

/// Trait for a provider of wallet lifecycle methods
pub trait WalletLCProvider<'a, C, K>: Send + Sync
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn set_top_level_directory(&mut self, dir: &str) -> Result<(), Error>;
	fn get_top_level_directory(&self) -> Result<String, Error>;

	fn create_config(
		&self,
		chain_type: &global::ChainTypes,
		file_name: &str,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
	) -> Result<(), Error>;

	fn create_wallet(
		&mut self,
		name: Option<&str>,
		mnemonic: Option<ZeroingString>,
		mnemonic_length: usize,
		password: ZeroingString,
		test_mode: bool,
	) -> Result<(), Error>;

	fn open_wallet(
		&mut self,
		name: Option<&str>,
		password: ZeroingString,
		create_mask: bool,
		use_test_rng: bool,
	) -> Result<Option<SecretKey>, Error>;

	fn close_wallet(&mut self, name: Option<&str>) -> Result<(), Error>;
	fn wallet_exists(&self, name: Option<&str>) -> Result<bool, Error>;

	fn get_mnemonic(
		&self,
		name: Option<&str>,
		password: ZeroingString,
	) -> Result<ZeroingString, Error>;
	fn validate_mnemonic(&self, mnemonic: ZeroingString) -> Result<(), Error>;

	fn recover_from_mnemonic(
		&self,
		mnemonic: ZeroingString,
		password: ZeroingString,
	) -> Result<(), Error>;
	fn change_password(
		&self,
		name: Option<&str>,
		old: ZeroingString,
		new: ZeroingString,
	) -> Result<(), Error>;
	fn delete_wallet(&self, name: Option<&str>) -> Result<(), Error>;

	fn wallet_inst(&mut self) -> Result<&mut Box<dyn WalletBackend<'a, C, K> + 'a>, Error>;
}

/// Wallet backend trait
pub trait WalletBackend<'ck, C, K>: Send + Sync
where
	C: NodeClient + 'ck,
	K: Keychain + 'ck,
{
	fn set_keychain(
		&mut self,
		k: Box<K>,
		mask: bool,
		use_test_rng: bool,
	) -> Result<Option<SecretKey>, Error>;
	fn close(&mut self) -> Result<(), Error>;
	fn keychain(&self, mask: Option<&SecretKey>) -> Result<K, Error>;
	fn w2n_client(&mut self) -> &mut C;

	fn calc_commit_for_cache(
		&mut self,
		keychain_mask: Option<&SecretKey>,
		amount: u64,
		id: &Identifier,
	) -> Result<Option<String>, Error>;

	fn set_parent_key_id_by_name(&mut self, label: &str) -> Result<(), Error>;
	fn set_parent_key_id(&mut self, _: Identifier);
	fn parent_key_id(&mut self) -> Identifier;

	fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = OutputData> + 'a>;
	fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error>;
	fn get_tx_log_entry(&self, uuid: &Uuid) -> Result<Option<TxLogEntry>, Error>;
	fn get_private_context(
		&mut self,
		keychain_mask: Option<&SecretKey>,
		slate_id: &[u8],
	) -> Result<Context, Error>;
	fn tx_log_iter<'a>(&'a self) -> Box<dyn Iterator<Item = TxLogEntry> + 'a>;

	fn save_tx_log_entry(&mut self, t: TxLogEntry, parent_id: &Identifier) -> Result<(), Error>;
	fn save_acct_path(&mut self, mapping: AcctPathMapping) -> Result<(), Error>;
	fn acct_path_iter<'a>(&'a self) -> Box<dyn Iterator<Item = AcctPathMapping> + 'a>;
	fn get_acct_path(&self, label: String) -> Result<Option<AcctPathMapping>, Error>;

	fn store_tx(&self, uuid: &str, tx: &Transaction) -> Result<(), Error>;
	fn get_stored_tx(&self, uuid: &str) -> Result<Option<Transaction>, Error>;

	fn batch<'a>(
		&'a mut self,
		keychain_mask: Option<&SecretKey>,
	) -> Result<Box<dyn WalletOutputBatch<K> + 'a>, Error>;

	fn batch_no_mask<'a>(&'a mut self) -> Result<Box<dyn WalletOutputBatch<K> + 'a>, Error>;

	fn current_child_index(&mut self, parent_key_id: &Identifier) -> Result<u32, Error>;
	fn next_child(&mut self, keychain_mask: Option<&SecretKey>) -> Result<Identifier, Error>;
	fn last_confirmed_height(&mut self) -> Result<u64, Error>;
	fn last_scanned_block(&mut self) -> Result<ScannedBlockInfo, Error>;
	fn init_status(&mut self) -> Result<WalletInitStatus, Error>;
}

/// Batch operations on wallet data
pub trait WalletOutputBatch<K>
where
	K: Keychain,
{
	fn keychain(&mut self) -> &mut K;

	fn save(&mut self, out: OutputData) -> Result<(), Error>;
	fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error>;
	fn iter(&self) -> Box<dyn Iterator<Item = OutputData>>;

	fn delete(&mut self, id: &Identifier, mmr_index: &Option<u64>) -> Result<(), Error>;
	fn save_child_index(&mut self, parent_key_id: &Identifier, child_n: u32) -> Result<(), Error>;
	fn save_last_confirmed_height(
		&mut self,
		parent_key_id: &Identifier,
		height: u64,
	) -> Result<(), Error>;
	fn save_last_scanned_block(&mut self, block: ScannedBlockInfo) -> Result<(), Error>;
	fn save_init_status(&mut self, value: WalletInitStatus) -> Result<(), Error>;

	fn next_tx_log_id(&mut self, parent_key_id: &Identifier) -> Result<u32, Error>;
	fn tx_log_iter(&self) -> Box<dyn Iterator<Item = TxLogEntry>>;
	fn save_tx_log_entry(&mut self, t: TxLogEntry, parent_id: &Identifier) -> Result<(), Error>;
	fn save_acct_path(&mut self, mapping: AcctPathMapping) -> Result<(), Error>;
	fn acct_path_iter(&self) -> Box<dyn Iterator<Item = AcctPathMapping>>;

	fn lock_output(&mut self, out: &mut OutputData) -> Result<(), Error>;
	fn save_private_context(&mut self, slate_id: &[u8], ctx: &Context) -> Result<(), Error>;
	fn delete_private_context(&mut self, slate_id: &[u8]) -> Result<(), Error>;

	fn commit(&self) -> Result<(), Error>;
}

// ———————————————————————— Data structures ————————————————————————

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WalletData {
	pub outputs: HashMap<String, OutputData>,
	pub tx_log: HashMap<u32, TxLogEntry>,
	pub acct_path_mapping: HashMap<String, AcctPathMapping>,
	pub last_confirmed_height: u64,
	pub last_scanned_block: ScannedBlockInfo,
	pub last_refresh: u64,
	pub last_scanned_height: u64,
	pub refresh_height: u64,
	pub init_status: WalletInitStatus,
}

/// Dummy wrapper for a hex-encoded transaction
#[derive(Serialize, Deserialize)]
pub struct TxWrapper {
	pub tx_hex: String,
}

/// Wallet summary information
#[derive(Serialize, Eq, PartialEq, Deserialize, Debug, Clone)]
pub struct WalletInfo {
	#[serde(with = "secp_ser::string_or_u64")]
	pub last_confirmed_height: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	pub minimum_confirmations: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	pub total: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_awaiting_finalization: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_awaiting_confirmation: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_immature: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_currently_spendable: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_locked: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_reverted: u64,
}

/// Types of transaction log entries
#[derive(Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub enum TxLogEntryType {
	ConfirmedCoinbase,
	TxReceived,
	TxSent,
	TxReceivedCancelled,
	TxSentCancelled,
	TxReverted,
}

impl fmt::Display for TxLogEntryType {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match *self {
			TxLogEntryType::ConfirmedCoinbase => write!(f, "Confirmed \nCoinbase"),
			TxLogEntryType::TxReceived => write!(f, "Received Tx"),
			TxLogEntryType::TxSent => write!(f, "Sent Tx"),
			TxLogEntryType::TxReceivedCancelled => write!(f, "Received Tx\n- Cancelled"),
			TxLogEntryType::TxSentCancelled => write!(f, "Sent Tx\n- Cancelled"),
			TxLogEntryType::TxReverted => write!(f, "Received Tx\n- Reverted"),
		}
	}
}

/// Transaction log entry
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TxLogEntry {
	pub parent_key_id: Identifier,
	pub id: u32,
	pub tx_slate_id: Option<Uuid>,
	pub tx_type: TxLogEntryType,
	pub creation_ts: DateTime<Utc>,
	pub confirmation_ts: Option<DateTime<Utc>>,
	pub confirmed: bool,
	pub num_inputs: usize,
	pub num_outputs: usize,
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_credited: u64,
	#[serde(with = "secp_ser::string_or_u64")]
	pub amount_debited: u64,
	pub fee: Option<FeeFields>,
	#[serde(with = "secp_ser::opt_string_or_u64")]
	#[serde(default)]
	pub ttl_cutoff_height: Option<u64>,
	pub stored_tx: Option<String>,
	#[serde(with = "secp_ser::option_commitment_serde")]
	#[serde(default)]
	pub kernel_excess: Option<Commitment>,
	#[serde(default)]
	pub kernel_lookup_min_height: Option<u64>,
	#[serde(default)]
	pub payment_proof: Option<StoredProofInfo>,
	#[serde(with = "option_duration_as_secs", default)]
	pub reverted_after: Option<Duration>,
}

impl ser::Writeable for TxLogEntry {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|_| ser::Error::CorruptedData)?)
	}
}

impl ser::Readable for TxLogEntry {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<TxLogEntry, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|_| ser::Error::CorruptedData)
	}
}

impl TxLogEntry {
	pub fn new(parent_key_id: Identifier, t: TxLogEntryType, id: u32) -> Self {
		TxLogEntry {
			parent_key_id,
			tx_type: t,
			id,
			tx_slate_id: None,
			creation_ts: Utc::now(),
			confirmation_ts: None,
			confirmed: false,
			amount_credited: 0,
			amount_debited: 0,
			num_inputs: 0,
			num_outputs: 0,
			fee: None,
			ttl_cutoff_height: None,
			stored_tx: None,
			kernel_excess: None,
			kernel_lookup_min_height: None,
			payment_proof: None,
			reverted_after: None,
		}
	}

	pub fn sum_confirmed(txs: &[TxLogEntry]) -> (u64, u64) {
		txs.iter().fold((0, 0), |acc, tx| {
			if tx.confirmed {
				(acc.0 + tx.amount_credited, acc.1 + tx.amount_debited)
			} else {
				acc
			}
		})
	}

	pub fn update_confirmation_ts(&mut self) {
		self.confirmation_ts = Some(Utc::now());
	}
}

/// Payment proof storage
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct StoredProofInfo {
	#[serde(with = "dalek_ser::dalek_pubkey_serde")]
	pub receiver_address: DalekPublicKey,
	#[serde(with = "dalek_ser::option_dalek_sig_serde")]
	pub receiver_signature: Option<DalekSignature>,
	pub sender_address_path: u32,
	#[serde(with = "dalek_ser::dalek_pubkey_serde")]
	pub sender_address: DalekPublicKey,
	#[serde(with = "dalek_ser::option_dalek_sig_serde")]
	pub sender_signature: Option<DalekSignature>,
}

impl ser::Writeable for StoredProofInfo {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|_| ser::Error::CorruptedData)?)
	}
}

impl ser::Readable for StoredProofInfo {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<StoredProofInfo, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|_| ser::Error::CorruptedData)
	}
}

/// Account path mapping
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AcctPathMapping {
	pub label: String,
	pub path: Identifier,
}

impl ser::Writeable for AcctPathMapping {
	fn write<W: ser::Writer>(&self, writer: &mut W) -> Result<(), ser::Error> {
		writer.write_bytes(&serde_json::to_vec(self).map_err(|_| ser::Error::CorruptedData)?)
	}
}

impl ser::Readable for AcctPathMapping {
	fn read<R: ser::Reader>(reader: &mut R) -> Result<AcctPathMapping, ser::Error> {
		let data = reader.read_bytes_len_prefix()?;
		serde_json::from_slice(&data[..]).map_err(|_| ser::Error::CorruptedData)
	}
}
