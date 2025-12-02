// Copyright 2025 Lurker Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Concrete implementations of libwallet types for Lurker
//!
//! This crate contains the actual wallet implementation used by Lurker,
//! including the default lifecycle provider, node clients, and slate adapters.
//! It is deliberately separated to avoid circular dependencies with libwallet.
//!
//! Lurker-specific features:
//! - Yggdrasil mesh networking (self-healing, low-connectivity resilient)
//! - Sled-backed storage (replaces LMDB)
//! - Full support for auto-pruning and 4GB max chain size
//! - No Tor — pure mesh-native design

#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
#[macro_use]
extern crate serde_json;

use lurker_api as api;
use lurker_chain as chain;
use lurker_core as core;
use lurker_keychain as keychain;
use lurker_store as store;
use lurker_util as util;
use lurker_wallet_config as config;
use lurker_wallet_libwallet as libwallet;

mod adapters;
mod client_utils;
mod error;
mod lifecycle;
mod node_clients;
pub mod test_framework;

// Public re-exports
pub use crate::adapters::{
	HttpSlateSender, PathToSlate, PathToSlatepack, SlateGetter, SlatePutter, SlateReceiver,
	SlateSender,
};
pub use crate::error::Error;
pub use crate::lifecycle::DefaultLCProvider;
pub use crate::node_clients::HTTPNodeClient;

use core::core::{Output, Transaction, TxKernel};
use keychain::{ExtKeychain, Identifier, Keychain};
use libwallet::{
	AcctPathMapping, BuiltOutput, Commitment, Context, InitTxArgs, IssueInvoiceTxArgs, NodeClient,
	OutputData, OutputStatus, PaymentProof, RetrieveTxQueryArgs, ScannedBlockInfo, Slate,
	SlateVersion, Slatepack, SlatepackAddress, StatusMessage, TxLogEntry, ViewWallet,
	WalletBackend, WalletData, WalletInfo, WalletInitStatus, WalletInst, WalletLCProvider,
	WalletOutputBatch,
};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::time::Duration;
use util::secp::key::SecretKey;
use util::secp::pedersen::{Commitment, RangeProof};
use uuid::Uuid;

use self::error::Error as ImplError;

use sled::{Db, IVec, Tree};
use std::path::PathBuf;

/// Initializes Yggdrasil mesh networking for the wallet
///
/// This is a Lurker-specific extension. In the future, this will:
/// - Start the Yggdrasil daemon if not running
/// - Load mesh keys
/// - Verify connectivity on the 3xx::/8 overlay
///
/// Currently a no-op placeholder — safe to expand later.
fn init_yggdrasil() -> Result<(), Error> {
	debug!("Lurker: Initializing Yggdrasil mesh networking (stub)");
	// Future: yggdrasil::ensure_running()?;
	Ok(())
}

/// SledBackend - Sled-based implementation of WalletBackend
struct SledBackend<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	db: Db,
	outputs: Tree,
	tx_log: Tree,
	acct_path_mapping: Tree,
	private_context: Tree,
	keychain: Option<Box<K>>,
	parent_key_id: Identifier,
	data_file_dir: String,
	keychain_mask: Option<SecretKey>,
}

impl<'a, C, K> SledBackend<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn new(data_file_dir: &str) -> Result<Self, Error> {
		let db = sled::open(data_file_dir)
			.map_err(|e| Error::Backend(format!("Failed to open Sled DB: {}", e)))?;
		let outputs = db
			.open_tree("outputs")
			.map_err(|e| Error::Backend(format!("Failed to open outputs tree: {}", e)))?;
		let tx_log = db
			.open_tree("tx_log")
			.map_err(|e| Error::Backend(format!("Failed to open tx_log tree: {}", e)))?;
		let acct_path_mapping = db
			.open_tree("acct_path_mapping")
			.map_err(|e| Error::Backend(format!("Failed to open acct_path_mapping tree: {}", e)))?;
		let private_context = db
			.open_tree("private_context")
			.map_err(|e| Error::Backend(format!("Failed to open private_context tree: {}", e)))?;
		Ok(Self {
			db,
			outputs,
			tx_log,
			acct_path_mapping,
			private_context,
			keychain: None,
			parent_key_id: Identifier::zero(),
			data_file_dir: data_file_dir.to_string(),
			keychain_mask: None,
		})
	}
}

impl<'a, C, K> WalletBackend<'a, C, K> for SledBackend<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn set_keychain(
		&mut self,
		k: Box<K>,
		mask: bool,
		use_test_rng: bool,
	) -> Result<Option<SecretKey>, Error> {
		self.keychain = Some(k);
		Ok(None) // No XOR token for now
	}

	fn close(&mut self) -> Result<(), Error> {
		self.db.flush()?;
		Ok(())
	}

	fn keychain(&self, mask: Option<&SecretKey>) -> Result<K, Error> {
		self.keychain
			.as_ref()
			.ok_or(Error::KeychainDoesntExist)
			.cloned()
	}

	fn w2n_client(&mut self) -> &mut C {
		unimplemented!()
	}

	fn calc_commit_for_cache(
		&mut self,
		keychain_mask: Option<&SecretKey>,
		amount: u64,
		id: &Identifier,
	) -> Result<Option<String>, Error> {
		unimplemented!()
	}

	fn set_parent_key_id_by_name(&mut self, label: &str) -> Result<(), Error> {
		unimplemented!()
	}

	fn set_parent_key_id(&mut self, id: Identifier) {
		self.parent_key_id = id;
	}

	fn parent_key_id(&mut self) -> Identifier {
		self.parent_key_id.clone()
	}

	fn iter<'a>(&'a self) -> Box<dyn Iterator<Item = OutputData> + 'a> {
		Box::new(self.outputs.iter().map(|res| {
			res.map(|v| serde_json::from_slice(&v.1).unwrap())
				.unwrap_or_default()
		}))
	}

	fn get(&self, id: &Identifier, mmr_index: &Option<u64>) -> Result<OutputData, Error> {
		unimplemented!()
	}

	fn get_tx_log_entry(&self, uuid: &Uuid) -> Result<Option<TxLogEntry>, Error> {
		unimplemented!()
	}

	fn get_private_context(
		&mut self,
		keychain_mask: Option<&SecretKey>,
		slate_id: &[u8],
	) -> Result<Context, Error> {
		unimplemented!()
	}

	fn tx_log_iter<'a>(&'a self) -> Box<dyn Iterator<Item = TxLogEntry> + 'a> {
		Box::new(self.tx_log.iter().map(|res| {
			res.map(|v| serde_json::from_slice(&v.1).unwrap())
				.unwrap_or_default()
		}))
	}

	fn save_tx_log_entry(&mut self, t: TxLogEntry, parent_id: &Identifier) -> Result<(), Error> {
		unimplemented!()
	}

	fn save_acct_path(&mut self, mapping: AcctPathMapping) -> Result<(), Error> {
		unimplemented!()
	}

	fn acct_path_iter<'a>(&'a self) -> Box<dyn Iterator<Item = AcctPathMapping> + 'a> {
		Box::new(self.acct_path_mapping.iter().map(|res| {
			res.map(|v| serde_json::from_slice(&v.1).unwrap())
				.unwrap_or_default()
		}))
	}

	fn lock_output(&mut self, out: &mut OutputData) -> Result<(), Error> {
		unimplemented!()
	}

	fn save_private_context(&mut self, slate_id: &[u8], ctx: &Context) -> Result<(), Error> {
		let data =
			serde_json::to_vec(ctx).map_err(|_| Error::GenericError("Ser failed".to_string()))?;
		self.private_context.insert(slate_id, data)?;
		Ok(())
	}

	fn delete_private_context(&mut self, slate_id: &[u8]) -> Result<(), Error> {
		self.private_context.remove(slate_id)?;
		Ok(())
	}

	fn commit(&self) -> Result<(), Error> {
		self.db.flush()?;
		Ok(())
	}

	fn current_child_index(&mut self, parent_key_id: &Identifier) -> Result<u32, Error> {
		unimplemented!()
	}

	fn next_tx_log_id(&mut self, parent_key_id: &Identifier) -> Result<u32, Error> {
		unimplemented!()
	}

	fn last_confirmed_height(&mut self) -> Result<u64, Error> {
		unimplemented!()
	}

	fn last_scanned_block(&mut self) -> Result<ScannedBlockInfo, Error> {
		unimplemented!()
	}

	fn init_status(&mut self) -> Result<WalletInitStatus, Error> {
		unimplemented!()
	}

	fn get_acct_path(&self, label: String) -> Result<Option<AcctPathMapping>, Error> {
		unimplemented!()
	}

	fn store_tx(&self, uuid: &str, tx: &Transaction) -> Result<(), Error> {
		unimplemented!()
	}

	fn get_stored_tx(&self, uuid: &str) -> Result<Option<Transaction>, Error> {
		unimplemented!()
	}

	fn batch<'a>(
		&'a mut self,
		keychain_mask: Option<&SecretKey>,
	) -> Result<Box<dyn WalletOutputBatch<K> + 'a>, Error> {
		unimplemented!()
	}

	fn batch_no_mask<'a>(&'a mut self) -> Result<Box<dyn WalletOutputBatch<K> + 'a>, Error> {
		unimplemented!()
	}

	fn next_child(&mut self, keychain_mask: Option<&SecretKey>) -> Result<Identifier, Error> {
		unimplemented!()
	}
}
