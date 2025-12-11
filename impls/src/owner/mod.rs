// lurker-wallet/impls/src/owner/mod.rs
// LURKER — ultra-minimal Owner, no bloat, no middleware

use crate::util::Mutex;
use crate::Keychain;
use lurker_wallet_libwallet::internal::{self, selection};
use lurker_wallet_libwallet::{
	BlockFees, CbData, Error, InitTxArgs, IssueInvoiceTxArgs, NodeClient as _, Slate, TxLogEntry,
	WalletInfo, WalletInst,
};
use lurker_wallet_libwallet::{NodeClient, WalletLCProvider};
use std::sync::Arc;

use lurker_wallet_libwallet::api_impl::owner;
use lurker_wallet_libwallet::internal::{tx, updater};

#[derive(Clone)]
pub struct Owner<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	pub wallet_inst: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	pub keychain_mask: Option<lurker_util::secp::key::SecretKey>,
}

impl<'a, L, C, K> Owner<'a, L, C, K>
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

	pub fn init_send_tx(&self, args: InitTxArgs) -> Result<Slate, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		owner::init_send_tx(&mut **w, self.keychain_mask.as_ref(), args, true)
	}

	pub fn issue_invoice_tx(&self, args: IssueInvoiceTxArgs) -> Result<Slate, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		owner::issue_invoice_tx(&mut **w, self.keychain_mask.as_ref(), args, true)
	}

	pub fn finalize_tx(&self, slate: &Slate) -> Result<Slate, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		owner::finalize_tx(&mut **w, self.keychain_mask.as_ref(), slate)
	}

	pub fn post_tx(&self, slate: &Slate, fluff: bool) -> Result<(), Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		let tx = slate.tx_or_err()?;
		w.w2n_client().post_tx(tx, fluff)?;
		Ok(())
	}

	pub fn get_wallet_info(&self) -> Result<WalletInfo, Error> {
		let w = self.wallet_inst.clone(); // ← clone the Arc
		owner::retrieve_summary_info(
			w, // ← pass the Arc<Mutex<...>>
			self.keychain_mask.as_ref(),
			&None, // ← no status messages needed
			true,  // ← refresh from node
			10,    // ← minimum confirmations
		)
		.map(|(_, info)| info) // ← return just the WalletInfo
	}

	pub fn get_transactions(&self) -> Result<Vec<TxLogEntry>, Error> {
		let wallet_inst = self.wallet_inst.clone();
		let (_updated, txs) = owner::retrieve_txs(
			wallet_inst,
			self.keychain_mask.as_ref(),
			&None,
			true,
			None,
			None,
			None,
		)?;
		Ok(txs)
	}

	// Add more stubs as you need them — these are the most common ones
}
