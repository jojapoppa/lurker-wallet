// lurker-wallet/impls/src/owner_rpc_impl.rs
// LURKER — MINIMAL OWNER RPC — SINGLE ACCOUNT ONLY

use crate::owner::Owner;
use api_common::owner_rpc::OwnerRpc;
use api_common::types::AcctPathMapping;
use api_common::types::Ed25519SecretKey;
use api_common::types::{Error, Token};
use ed25519_dalek::SecretKey as EdSecretKey;
use lurker_core::core::Output;
use lurker_core::core::OutputFeatures;
use lurker_core::global;
use lurker_keychain::BlindingFactor;
use lurker_keychain::Identifier;
use lurker_keychain::Keychain;
use lurker_keychain::SwitchCommitmentType;
use lurker_util::logger::LoggingConfig;
use lurker_util::static_secp_instance;
use lurker_util::ZeroingString;
use lurker_wallet_config::WalletConfig;
use lurker_wallet_libwallet::api_impl::owner;
use lurker_wallet_libwallet::Slatepacker;
use lurker_wallet_libwallet::SlatepackerArgs;
use lurker_wallet_libwallet::WalletInst;
use lurker_wallet_libwallet::WalletOutputBatch;
use lurker_wallet_libwallet::{
	Amount, BuiltOutput, InitTxArgs, IssueInvoiceTxArgs, NodeClient, NodeHeightResult,
	PaymentProof, Slate, SlateVersion, Slatepack, SlatepackAddress, StatusMessage, TxLogEntry,
	VersionedSlate, ViewWallet, WalletInfo, WalletLCProvider,
};
use rand::thread_rng;
use secp256k1zkp::pedersen::RangeProof;
use secp256k1zkp::SecretKey;
use uuid::Uuid;

impl<'a, L, C, K> OwnerRpc for Owner<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K> + WalletOutputBatch<K> + Sync + Send + 'a,
	C: NodeClient + Sync + Send + 'a,
	K: Keychain + Sync + Send + 'a,
{
	// Lurker has only one account — "default"
	fn accounts(&self, _token: Token) -> Result<Vec<AcctPathMapping>, Error> {
		Ok(vec![AcctPathMapping {
			path: Identifier::zero(),
			label: "Default Account".to_string(),
		}])
	}

	// These are intentionally removed — Lurker does not support multiple accounts
	fn create_account_path(&self, _token: Token, _label: String) -> Result<Identifier, Error> {
		Err(Error::GenericError(
			"Multiple accounts not supported".into(),
		))
	}

	fn set_active_account(&self, _token: Token, _label: String) -> Result<(), Error> {
		Err(Error::GenericError(
			"Multiple accounts not supported".into(),
		))
	}

	fn retrieve_txs(
		&self,
		_token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), Error> {
		let wallet_inst = self.wallet_inst.clone();
		owner::retrieve_txs(
			wallet_inst,
			self.keychain_mask.as_ref(),
			&None,
			refresh_from_node,
			tx_id,
			tx_slate_id,
			None,
		)
	}

	fn retrieve_summary_info(
		&self,
		_token: Token,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), Error> {
		let wallet_inst = self.wallet_inst.clone();
		owner::retrieve_summary_info(
			wallet_inst,
			self.keychain_mask.as_ref(),
			&None,
			refresh_from_node,
			minimum_confirmations,
		)
	}

	fn init_send_tx(&self, _token: Token, args: InitTxArgs) -> Result<VersionedSlate, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		let slate = owner::init_send_tx(&mut **w, None, args, true)?;
		Ok(VersionedSlate::into_version(slate, SlateVersion::V4)?)
	}

	fn issue_invoice_tx(
		&self,
		_token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		let slate = owner::issue_invoice_tx(&mut **w, None, args, true)?;
		Ok(VersionedSlate::into_version(slate, SlateVersion::V4)?)
	}

	fn process_invoice_tx(
		&self,
		_token: Token,
		slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		let inner: Slate = slate.into();
		let out = owner::process_invoice_tx(&mut **w, None, &inner, args, true)?;
		Ok(VersionedSlate::into_version(out, SlateVersion::V4)?)
	}

	fn tx_lock_outputs(&self, _token: Token, slate: VersionedSlate) -> Result<(), Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		let inner: Slate = slate.into();
		owner::tx_lock_outputs(&mut **w, None, &inner)
	}

	fn finalize_tx(&self, _token: Token, slate: VersionedSlate) -> Result<VersionedSlate, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let w = lc.wallet_inst()?;
		let mut inner: Slate = slate.into();
		let finalized = owner::finalize_tx(&mut **w, None, &mut inner)?;
		Ok(VersionedSlate::into_version(finalized, SlateVersion::V4)?)
	}

	fn post_tx(&self, _token: Token, slate: VersionedSlate, fluff: bool) -> Result<(), Error> {
		let inner: Slate = slate.into();
		let client = {
			let w_lock = self.wallet_inst.lock();
			let mut lc = w_lock.lc_provider()?;
			let inst = lc.wallet_inst()?;
			inst.w2n_client().clone()
		};
		let tx = inner
			.tx
			.as_ref()
			.ok_or(Error::GenericError("Missing tx".into()))?;
		owner::post_tx(&client, tx, fluff)
	}

	fn cancel_tx(
		&self,
		_token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), Error> {
		let wallet_inst = self.wallet_inst.clone();
		owner::cancel_tx(
			wallet_inst,
			self.keychain_mask.as_ref(),
			&None,
			tx_id,
			tx_slate_id,
		)
	}

	fn get_stored_tx(
		&self,
		_token: Token,
		id: Option<u32>,
		slate_id: Option<Uuid>,
	) -> Result<Option<VersionedSlate>, Error> {
		let w_lock = self.wallet_inst.lock();
		let mut lc = w_lock.lc_provider()?;
		let w = lc.wallet_inst()?;
		let res = owner::get_stored_tx(&mut **w, id, slate_id.as_ref())?;
		Ok(res
			.map(|s| VersionedSlate::into_version(s, SlateVersion::V4))
			.transpose()?)
	}

	fn get_rewind_hash(&self, _token: Token) -> Result<String, Error> {
		owner::get_rewind_hash(self.wallet_inst.clone(), self.keychain_mask.as_ref())
	}

	fn scan_rewind_hash(
		&self,
		rewind_hash: String,
		start_height: Option<u64>,
	) -> Result<ViewWallet, Error> {
		owner::scan_rewind_hash(self.wallet_inst.clone(), rewind_hash, start_height, &None)
	}

	fn scan(
		&self,
		_token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), Error> {
		owner::scan(
			self.wallet_inst.clone(),
			self.keychain_mask.as_ref(),
			start_height,
			delete_unconfirmed,
			&None,
		)
	}

	fn node_height(&self, _token: Token) -> Result<NodeHeightResult, Error> {
		owner::node_height(self.wallet_inst.clone(), self.keychain_mask.as_ref())
	}

	fn get_top_level_directory(&self) -> Result<String, Error> {
		let w = self.wallet_inst.lock();
		let lc = w.lc_provider()?;
		Ok(lc.get_top_level_directory()?.clone())
	}

	fn set_top_level_directory(&self, dir: String) -> Result<(), Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		lc.set_top_level_directory(&dir)
	}

	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
	) -> Result<(), Error> {
		Owner::create_config(self, chain_type, wallet_config, logging_config)
	}

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), Error> {
		Owner::create_wallet(self, name, mnemonic, mnemonic_length, password)
	}

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, Error> {
		Owner::open_wallet(self, name, password)
	}

	fn close_wallet(&self, name: Option<String>) -> Result<(), Error> {
		Owner::close_wallet(self, name)
	}

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, Error> {
		Owner::get_mnemonic(self, name, password)
	}

	fn change_password(&self, name: Option<String>, old: String, new: String) -> Result<(), Error> {
		Owner::change_password(self, name, old, new)
	}

	fn delete_wallet(&self, name: Option<String>) -> Result<(), Error> {
		Owner::delete_wallet(self, name)
	}

	fn start_updater(&self, _token: Token, _frequency: u32) -> Result<(), Error> {
		// Updater not used in Lurker CLI
		Ok(())
	}

	fn stop_updater(&self) -> Result<(), Error> {
		// Updater not used
		Ok(())
	}

	fn get_updater_messages(&self, _count: u32) -> Result<Vec<StatusMessage>, Error> {
		// No updater
		Ok(vec![])
	}

	fn get_slatepack_address(
		&self,
		_token: Token,
		derivation_index: u32,
	) -> Result<SlatepackAddress, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let k = lc.keychain();

		let root_key_id = w.parent_key_id().clone();

		let priv_key = k.derive_key(
			derivation_index as u64,
			&root_key_id,
			SwitchCommitmentType::Regular,
		)?;

		let secp_instance = static_secp_instance();
		let mut secp = secp_instance.lock();
		let pub_key_bytes = secp.commit(0, priv_key)?.0;

		let pub_key = ed25519_dalek::PublicKey::from_bytes(&pub_key_bytes)
			.map_err(|e| Error::GenericError(format!("Invalid public key: {}", e)))?;

		Ok(SlatepackAddress::new(&pub_key))
	}

	fn get_slatepack_secret_key(
		&self,
		_token: Token,
		derivation_index: u32,
	) -> Result<Ed25519SecretKey, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let mut k = lc.keychain();
		let priv_key = k.derive_key(
			derivation_index as u64,
			&w.parent_key_id().clone(),
			SwitchCommitmentType::Regular,
		)?;

		Ok(Ed25519SecretKey {
			key: EdSecretKey::from_bytes(&priv_key.0)
				.map_err(|e| Error::GenericError(format!("Failed to create secret key: {}", e)))?,
		})
	}

	fn create_slatepack_message(
		&self,
		_token: Token,
		slate: VersionedSlate,
		sender_index: Option<u32>,
		recipients: Vec<SlatepackAddress>,
	) -> Result<String, Error> {
		Owner::create_slatepack_message(self, slate, sender_index, recipients)
	}

	fn slate_from_slatepack_message(
		&self,
		_token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<VersionedSlate, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let k = lc.keychain();

		let base_args = SlatepackerArgs {
			sender: None,
			recipients: vec![],
			dec_key: None,
		};

		if secret_indices.is_empty() {
			let packer = Slatepacker::new(base_args);
			let slatepack = packer.deser_slatepack(message.as_bytes(), false)?;
			let slate = packer.get_slate(&slatepack)?;
			Ok(VersionedSlate::into_version(slate, SlateVersion::V4)?)
		} else {
			let mut last_err = None;
			for index in secret_indices {
				let dec_priv_key = k.derive_key(
					index as u64,
					&w.parent_key_id().clone(),
					SwitchCommitmentType::Regular,
				)?;

				let dec_key_bytes = dec_priv_key.0;
				let dec_key = ed25519_dalek::SecretKey::from_bytes(&dec_key_bytes)
					.map_err(|e| Error::GenericError(format!("Invalid decryption key: {}", e)))?;

				let mut args = base_args.clone();
				args.dec_key = Some(&dec_key);

				let packer = Slatepacker::new(args);
				let slatepack = packer.deser_slatepack(message.as_bytes(), true)?;
				if let Ok(slate) = packer.get_slate(&slatepack) {
					return Ok(VersionedSlate::into_version(slate, SlateVersion::V4)?);
				}
				last_err = Some(Error::GenericError(
					"Decryption failed with this key".into(),
				));
			}
			Err(last_err.unwrap_or(Error::GenericError(
				"No matching decryption key found".into(),
			)))
		}
	}

	fn decode_slatepack_message(
		&self,
		_token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<Slatepack, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let k = lc.keychain();

		let packer = Slatepacker::new(SlatepackerArgs {
			sender: None,
			recipients: vec![],
			dec_key: None,
		});

		packer.deser_slatepack(message.as_bytes(), !secret_indices.is_empty())
	}

	fn retrieve_payment_proof(
		&self,
		_token: Token,
		_refresh_from_node: bool,
		_tx_id: Option<u32>,
		_tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, Error> {
		// Payment proofs not supported in Lurker
		Err(Error::GenericError("Payment proofs not supported".into()))
	}

	fn verify_payment_proof(
		&self,
		_token: Token,
		_proof: PaymentProof,
	) -> Result<(bool, bool), Error> {
		// Payment proofs not supported
		Err(Error::GenericError("Payment proofs not supported".into()))
	}

	fn build_output(
		&self,
		_token: Token,
		features: OutputFeatures,
		amount: Amount,
	) -> Result<BuiltOutput, Error> {
		let mut w = self.wallet_inst.lock();
		let mut lc = w.lc_provider()?;
		let k = lc.keychain();

		let secp_instance = static_secp_instance();
		let mut secp = secp_instance.lock();
		let blind = SecretKey::new(&mut secp, &mut thread_rng());

		let commit = secp.commit(amount.0, blind.clone())?;
		let output = Output::new(features, commit, RangeProof::zero());

		let key_id = w.parent_key_id().clone();

		Ok(BuiltOutput {
			blind: BlindingFactor::from_secret_key(blind),
			key_id,
			output,
		})
	}
}
