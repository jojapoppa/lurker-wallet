// Copyright 2025 Lurker Developers
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

use keychain::{ExtKeychain, Keychain};
use libwallet::{NodeClient, WalletInst, WalletLCProvider};

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

/// Default wallet implementation for Lurker
///
/// This is the concrete wallet instance used by all Lurker nodes and wallets.
/// It wraps the `DefaultLCProvider` and adds Lurker-specific initialization.
pub struct DefaultWalletImpl<'a, C>
where
	C: NodeClient + 'a,
{
	lc_provider: DefaultLCProvider<'a, C>,
	// Keeps 'a alive — required by WalletInst trait
	_marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, C> DefaultWalletImpl<'a, C>
where
	C: NodeClient + 'a,
{
	pub fn new(node_client: C) -> Result<Self, Error> {
		let lc_provider = DefaultLCProvider::new(node_client);
		init_yggdrasil()?;
		Ok(Self {
			lc_provider,
			_marker: std::marker::PhantomData,
		})
	}
}

/// Implement the WalletInst trait for Lurker's default wallet
impl<'a, L, C, K> WalletInst<'a, L, C, K> for DefaultWalletImpl<'a, C>
where
	DefaultLCProvider<'a, C>: WalletLCProvider<'a, C, K>,
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn lc_provider(
		&mut self,
	) -> Result<&mut (dyn WalletLCProvider<'a, C, K> + 'a), libwallet::Error> {
		Ok(&mut self.lc_provider)
	}
}
