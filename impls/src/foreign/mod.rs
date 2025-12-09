// lurker-wallet/impls/src/foreign/mod.rs
// LURKER — Minimal Foreign implementation (no middleware, no version negotiation)

use crate::util::Mutex;
use crate::Keychain;
use lurker_wallet_libwallet::internal::{self, selection, updater};
use lurker_wallet_libwallet::{BlockFees, CbData, Error, Slate, WalletInst};
use lurker_wallet_libwallet::{NodeClient, WalletLCProvider};
use std::sync::Arc;

#[derive(Clone)]
pub struct Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	pub wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	pub keychain_mask: Option<lurker_util::secp::key::SecretKey>,
}

impl<'a, L, C, K> Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K> + Sync + Send + 'a,
	C: NodeClient + Sync + Send + 'a,
	K: Keychain + Sync + Send + 'a,
{
	pub fn new(
		wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
		keychain_mask: Option<lurker_util::secp::key::SecretKey>,
	) -> Self {
		Self {
			wallet_inst,
			keychain_mask,
		}
	}

	pub fn check_version(&self) -> Result<(), Error> {
		Ok(()) // Lurker has no version negotiation
	}

	pub fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, Error> {
		let mut w = self.wallet_inst.lock();
		let w = w.wallet_inst()?;
		internal::build::build_coinbase(&mut **w, self.keychain_mask.as_ref(), block_fees)
	}

	pub fn receive_tx(
		&self,
		slate: &Slate,
		dest_acct_name: Option<&str>,
		_dest: Option<String>,
	) -> Result<Slate, Error> {
		let mut w = self.wallet_inst.lock();
		let w = w.wallet_inst()?;
		internal::receive::receive_tx(&mut **w, self.keychain_mask.as_ref(), slate, dest_acct_name)
	}

	pub fn finalize_tx(&self, slate: &Slate, _noop: bool) -> Result<Slate, Error> {
		let mut w = self.wallet_inst.lock();
		let w = w.wallet_inst()?;
		internal::finalize::finalize_tx(&mut **w, self.keychain_mask.as_ref(), slate)
	}
}
