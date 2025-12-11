// lurker-wallet/impls/src/foreign/mod.rs
// LURKER — Minimal Foreign implementation (no middleware, no version negotiation)

use crate::util::Mutex;
use crate::Keychain;
use lurker_wallet_libwallet::internal::{self, selection};
use lurker_wallet_libwallet::{BlockFees, CbData, Error, Slate, WalletInst};
use lurker_wallet_libwallet::{NodeClient, WalletLCProvider};
use lurker_wallet_libwallet::{SlateVersion, VersionInfo};
use std::sync::Arc;

use lurker_wallet_libwallet::api_impl::foreign;
use lurker_wallet_libwallet::internal::{tx, updater};

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

	pub fn check_version(&self) -> Result<VersionInfo, Error> {
		Ok(VersionInfo {
			foreign_api_version: 2,
			supported_slate_versions: vec![SlateVersion::V4],
		})
	}

	pub fn build_coinbase(&self, block_fees: &BlockFees) -> Result<CbData, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		foreign::build_coinbase(&mut **w, self.keychain_mask.as_ref(), block_fees, false)
	}

	pub fn receive_tx(
		&self,
		slate: &Slate,
		dest_acct_name: Option<&str>,
		_dest: Option<String>,
	) -> Result<Slate, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		foreign::receive_tx(
			&mut **w,
			self.keychain_mask.as_ref(),
			slate,
			dest_acct_name,
			false,
		)
	}

	pub fn finalize_tx(&self, slate: &Slate, _noop: bool) -> Result<Slate, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		foreign::finalize_tx(&mut **w, self.keychain_mask.as_ref(), slate, false)
	}
}
