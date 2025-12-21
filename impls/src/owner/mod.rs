// lurker-wallet/impls/src/owner/mod.rs
// LURKER — ultra-minimal Owner, no bloat, no middleware

use crate::util::Mutex;
use crate::Keychain;
use api_common::types::Ed25519SecretKey;
use api_common::types::Token;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey as EdSecretKey;
use lurker_wallet_libwallet::internal::{self, selection};
use lurker_wallet_libwallet::Amount;
use lurker_wallet_libwallet::{
	BlockFees, CbData, Error, InitTxArgs, IssueInvoiceTxArgs, NodeClient as _, Slate, TxLogEntry,
	WalletInfo, WalletInst,
};
use lurker_wallet_libwallet::{NodeClient, WalletLCProvider};
use std::sync::Arc;

use lurker_core::core::Output;
use lurker_core::core::OutputFeatures;
use lurker_keychain::BlindingFactor;
use lurker_keychain::SwitchCommitmentType;
use lurker_secp256k1zkp::pedersen::RangeProof;
use lurker_util::secp::key::SecretKey;
use lurker_util::static_secp_instance;
use lurker_wallet_libwallet::api_impl::owner;
use lurker_wallet_libwallet::internal::{tx, updater};
use lurker_wallet_libwallet::WalletOutputBatch;
use lurker_wallet_libwallet::{
	BuiltOutput, PaymentProof, SlateVersion, Slatepack, SlatepackAddress, Slatepacker,
	SlatepackerArgs, VersionedSlate,
};
use rand::thread_rng;
use uuid::Uuid;

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
		let w = self.wallet_inst.clone();
		owner::retrieve_summary_info(w, self.keychain_mask.as_ref(), &None, true, 10)
			.map(|(_, info)| info)
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

	pub fn create_slatepack_message(
		&self,
		slate: VersionedSlate,
		sender_index: Option<u32>,
		recipients: Vec<SlatepackAddress>,
	) -> Result<String, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let mut backend = lc.wallet_inst()?;
		let k = backend.keychain(self.keychain_mask.as_ref())?;

		let sender = if let Some(index) = sender_index {
			let sender_priv_key = k.derive_key(
				index as u64,
				&w.parent_key_id().clone(),
				SwitchCommitmentType::Regular,
			)?;
			let secp = static_secp_instance();
			let mut secp_guard = secp.lock();
			let sender_pub_key_bytes = secp_guard.commit(0, sender_priv_key)?.0;
			let sender_pub_key = ed25519_dalek::PublicKey::from_bytes(&sender_pub_key_bytes)
				.map_err(|e| Error::GenericError(format!("Invalid sender public key: {}", e)))?;
			Some(SlatepackAddress::new(&sender_pub_key))
		} else {
			None
		};

		let packer_args = SlatepackerArgs {
			sender,
			recipients,
			dec_key: None,
		};

		let packer = Slatepacker::new(SlatepackerArgs {
			sender: None,
			recipients: vec![],
			dec_key: None,
		});

		let slatepack = packer.create_slatepack(&slate.into())?;
		packer.armor_slatepack(&slatepack)
	}

	fn slate_from_slatepack_message(
		&self,
		_token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<VersionedSlate, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let mut backend = lc.wallet_inst()?;
		let k = backend.keychain(self.keychain_mask.as_ref())?;

		let packer = Slatepacker::new(SlatepackerArgs {
			sender: None,
			recipients: vec![],
			dec_key: None,
		});

		let slatepack = packer.deser_slatepack(message.as_bytes(), !secret_indices.is_empty())?;

		let slate = packer.get_slate(&slatepack)?;

		Ok(VersionedSlate::into_version(slate, SlateVersion::V4)?)
	}

	fn decode_slatepack_message(
		&self,
		_token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<Slatepack, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let mut backend = lc.wallet_inst()?;
		let k = backend.keychain(self.keychain_mask.as_ref())?;

		let packer = Slatepacker::new(SlatepackerArgs {
			sender: None,
			recipients: vec![],
			dec_key: None,
		});

		packer.deser_slatepack(message.as_bytes(), !secret_indices.is_empty())
	}

	pub fn retrieve_payment_proof(
		&self,
		_refresh_from_node: bool,
		_tx_id: Option<u32>,
		_tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, Error> {
		// Payment proofs not supported in Lurker
		Err(Error::GenericError("Payment proofs not supported".into()))
	}

	pub fn verify_payment_proof(&self, _proof: PaymentProof) -> Result<(bool, bool), Error> {
		// Payment proofs not supported in Lurker
		Err(Error::GenericError("Payment proofs not supported".into()))
	}

	pub fn build_output(
		&self,
		_token: Token,
		features: OutputFeatures,
		amount: Amount,
	) -> Result<BuiltOutput, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let mut backend = lc.wallet_inst()?;
		let k = backend.keychain(self.keychain_mask.as_ref())?;

		let secp_instance = static_secp_instance();
		let mut secp = secp_instance.lock();
		let blind = SecretKey::new(&mut secp, &mut thread_rng());
		let commit = secp.commit(amount.0, blind.clone())?;
		let output = Output::new(
			features,
			commit,
			lurker_secp256k1zkp::pedersen::RangeProof::zero(),
		);
		let key_id = w.parent_key_id().clone();
		Ok(BuiltOutput {
			blind: BlindingFactor::from_secret_key(blind),
			key_id,
			output,
		})
	}

	fn get_slatepack_address(
		&self,
		_token: Token,
		derivation_index: u32,
	) -> Result<SlatepackAddress, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let mut backend = lc.wallet_inst()?;
		let k = backend.keychain(self.keychain_mask.as_ref())?;

		let priv_key = k.derive_key(
			derivation_index as u64,
			&w.parent_key_id().clone(),
			SwitchCommitmentType::Regular,
		)?;

		let secp_instance = static_secp_instance();
		let mut secp = secp_instance.lock();
		let pub_key_bytes = secp.commit(0, priv_key)?.0;

		let pub_key = ed25519_dalek::PublicKey::from_bytes(&pub_key_bytes)
			.map_err(|e| Error::GenericError(format!("Invalid public key: {}", e)))?;

		Ok(SlatepackAddress::new(&pub_key))
	}

	pub fn get_slatepack_secret_key(
		&self,
		derivation_index: u32,
	) -> Result<Ed25519SecretKey, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let mut backend = lc.wallet_inst()?;
		let k = backend.keychain(self.keychain_mask.as_ref())?;

		let root_key_id = w.parent_key_id().clone();

		let priv_key = k.derive_key(
			derivation_index as u64,
			&root_key_id,
			SwitchCommitmentType::Regular,
		)?;

		let ed_secret_key = EdSecretKey::from_bytes(&priv_key.0)
			.map_err(|e| Error::GenericError(format!("Invalid Ed25519 secret key: {}", e)))?;
		Ok(Ed25519SecretKey { key: ed_secret_key })
	}

	// Add more stubs as needed — these are the ones used by the RPC impl
}
