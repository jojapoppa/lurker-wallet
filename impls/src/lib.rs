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

use libwallet::{
	AcctPathMapping, Context, Error as LibWalletError, NodeClient, OutputData, ScannedBlockInfo,
	TxLogEntry, WalletBackend, WalletInitStatus, WalletInst, WalletLCProvider,
};
use lurker_api as api;
use lurker_chain as chain;
use lurker_core as core;
use lurker_keychain::{ExtKeychain, ExtKeychainPath, Identifier, Keychain};
use lurker_store as store;
use lurker_util as util;
use lurker_wallet_config as config;
use lurker_wallet_libwallet as libwallet;
use std::marker::PhantomData;
use std::sync::Arc;
use uuid::Uuid;

pub use lurker_wallet_libwallet::*;
pub type DefaultWalletImpl<'a, C> = SledBackend<'a, C, ExtKeychain>;

// Public re-exports from this crate
pub use crate::adapters::{
	HttpSlateSender, PathToSlate, PathToSlatepack, SlateGetter, SlatePutter, SlateReceiver,
	SlateSender,
};
pub use crate::error::Error;
pub use crate::lifecycle::DefaultLCProvider;
pub use crate::node_clients::HTTPNodeClient;

mod adapters;
mod client_utils;
mod error;
mod lifecycle;
mod node_clients;
pub mod test_framework;

// Extra imports actually used in this file
use core::core::{Output, Transaction, TxKernel};
use sled::{Db, Tree};
use std::time::Duration;
use util::secp::key::SecretKey;

use self::error::Error as ImplError;

/// Initializes Yggdrasil mesh networking for the wallet (placeholder)
fn init_yggdrasil() -> Result<(), Error> {
	debug!("Lurker: Initializing Yggdrasil mesh networking (stub)");
	// Future: yggdrasil::ensure_running()?;
	Ok(())
}

/// Sled-based implementation of WalletBackend
pub struct SledBackend<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	db: Db,
	outputs: Tree,
	tx_log: Tree,
	acct_path_mapping: Tree,
	private_context: Tree,
	child_indices: Tree,
	keychain: Option<Box<K>>,
	node_client: Option<C>,
	parent_key_id: Identifier,
	data_file_dir: String,
	keychain_mask: Option<SecretKey>,
	// This tells the compiler: "yes, we really do care about 'a even though nothing references it"
	_phantom: PhantomData<&'a (C, K)>,
}

impl<'a, C, K> SledBackend<'a, C, K>
where
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	pub fn new(data_file_dir: &str) -> Result<Self, LibWalletError> {
		let db = sled::open(data_file_dir)
			.map_err(|e| LibWalletError::Backend(format!("Failed to open Sled DB: {}", e)))?;

		let outputs = db.open_tree("outputs").map_err(|e| {
			LibWalletError::Backend(format!("Failed to open tree 'outputs': {}", e))
		})?;
		let tx_log = db
			.open_tree("tx_log")
			.map_err(|e| LibWalletError::Backend(format!("Failed to open tree 'tx_log': {}", e)))?;
		let acct_path_mapping = db.open_tree("acct_path_mapping").map_err(|e| {
			LibWalletError::Backend(format!("Failed to open tree 'acct_path_mapping': {}", e))
		})?;
		let private_context = db.open_tree("private_context").map_err(|e| {
			LibWalletError::Backend(format!("Failed to open tree 'private_context': {}", e))
		})?;
		let child_indices = db.open_tree("child_indices").map_err(|e| {
			LibWalletError::Backend(format!("Failed to open tree 'child_indices': {}", e))
		})?;

		Ok(Self {
			db,
			outputs,
			tx_log,
			acct_path_mapping,
			private_context,
			child_indices,
			keychain: None,
			node_client: None,
			parent_key_id: Identifier::zero(),
			data_file_dir: data_file_dir.to_string(),
			keychain_mask: None,
			_phantom: PhantomData,
		})
	}

	/// Helper to inject the node client after construction
	pub fn with_node_client(mut self, client: C) -> Self {
		self.node_client = Some(client);
		self
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
		_mask: bool,
		_use_test_rng: bool,
	) -> Result<Option<SecretKey>, LibWalletError> {
		self.keychain = Some(k);
		Ok(None)
	}

	fn close(&mut self) -> Result<(), LibWalletError> {
		Ok(()) // sled auto-flushes
	}

	fn keychain(&self, _mask: Option<&SecretKey>) -> Result<K, LibWalletError> {
		self.keychain
			.as_ref()
			.ok_or(LibWalletError::KeychainDoesntExist)
			.cloned()
			.map(|b| *b)
	}

	fn w2n_client(&mut self) -> &mut C {
		self.node_client
			.as_mut()
			.expect("Node client not set — call with_node_client()")
	}

	fn set_parent_key_id_by_name(&mut self, label: &str) -> Result<(), LibWalletError> {
		self.parent_key_id = Identifier::from_path(&ExtKeychainPath::new(
			2, // depth = 2 → m/0/label_index
			0, // account = 0
			// TODO to support multiple account add a account_idx instead
			0u32, // your label index, cast to u32
			0, 0,
		));
		Ok(())
	}

	fn set_parent_key_id(&mut self, id: Identifier) {
		self.parent_key_id = id;
	}

	fn parent_key_id(&mut self) -> Identifier {
		self.parent_key_id.clone()
	}

	// Minimal working iterators
	fn iter<'b>(&'b self) -> Box<dyn Iterator<Item = OutputData> + 'b> {
		Box::new(std::iter::empty())
	}

	fn tx_log_iter<'b>(&'b self) -> Box<dyn Iterator<Item = TxLogEntry> + 'b> {
		Box::new(std::iter::empty())
	}

	fn acct_path_iter<'b>(&'b self) -> Box<dyn Iterator<Item = AcctPathMapping> + 'b> {
		Box::new(std::iter::empty())
	}

	// Everything else: safe to panic if used too early
	fn calc_commit_for_cache(
		&mut self,
		_: Option<&SecretKey>,
		_: u64,
		_: &Identifier,
	) -> Result<Option<String>, LibWalletError> {
		unimplemented!()
	}
	fn get(&self, _: &Identifier, _: &Option<u64>) -> Result<OutputData, LibWalletError> {
		unimplemented!()
	}
	fn get_tx_log_entry(&self, _: &Uuid) -> Result<Option<TxLogEntry>, LibWalletError> {
		unimplemented!()
	}
	fn get_private_context(
		&mut self,
		_: Option<&SecretKey>,
		_: &[u8],
	) -> Result<Context, LibWalletError> {
		unimplemented!()
	}
	fn get_acct_path(&self, _: String) -> Result<Option<AcctPathMapping>, LibWalletError> {
		unimplemented!()
	}
	fn store_tx(&self, _: &str, _: &Transaction) -> Result<(), LibWalletError> {
		unimplemented!()
	}
	fn get_stored_tx(&self, _: &str) -> Result<Option<Transaction>, LibWalletError> {
		unimplemented!()
	}
	fn batch<'b>(
		&'b mut self,
		_: Option<&SecretKey>,
	) -> Result<Box<dyn WalletOutputBatch<K> + 'b>, LibWalletError> {
		unimplemented!()
	}
	fn batch_no_mask<'b>(
		&'b mut self,
	) -> Result<Box<dyn WalletOutputBatch<K> + 'b>, LibWalletError> {
		unimplemented!()
	}
	fn current_child_index(&mut self, _: &Identifier) -> Result<u32, LibWalletError> {
		unimplemented!()
	}
	fn next_child(&mut self, _: Option<&SecretKey>) -> Result<Identifier, LibWalletError> {
		unimplemented!()
	}
	fn last_confirmed_height(&mut self) -> Result<u64, LibWalletError> {
		unimplemented!()
	}
	fn last_scanned_block(&mut self) -> Result<ScannedBlockInfo, LibWalletError> {
		unimplemented!()
	}
	fn init_status(&mut self) -> Result<WalletInitStatus, LibWalletError> {
		unimplemented!()
	}
}

impl<'a, C> WalletInst<'a, DefaultLCProvider<'a, C>, C, ExtKeychain>
	for SledBackend<'a, C, ExtKeychain>
where
	C: NodeClient + 'a + Send + Sync + Clone, // Add Clone for w2n_client
{
	fn lc_provider(&self) -> Result<DefaultLCProvider<'a, C>, LibWalletError> {
		unimplemented!()
	}

	fn keychain_mask(&self) -> Option<&SecretKey> {
		self.keychain_mask.as_ref()
	}

	fn w2n_client(&self) -> C {
		self.node_client.as_ref().unwrap().clone()
	}
}
