// lurker-wallet/src/owner_rpc_impl.rs
// LURKER — WALLET IMPLEMENTATION OF OWNER RPC — FULL, COMPLETE, PURE

use crate::owner::Owner;
use api_common::owner_rpc::OwnerRpc;

use crate::libwallet::{
	AcctPathMapping, Amount, BlockFees, BuiltOutput, Error, InitTxArgs, IssueInvoiceTxArgs,
	NodeClient, NodeHeightResult, OutputCommitMapping, PaymentProof, RetrieveTxQueryArgs, Slate,
	SlateVersion, Slatepack, SlatepackAddress, StatusMessage, TxLogEntry, VersionedSlate,
	ViewWallet, WalletInfo, WalletLCProvider,
};
use api_common::types::{ECDHPubkey, Ed25519SecretKey, Token};
use lurker_keychain::keychain;

use crate::util::{from_hex, static_secp_instance, ZeroingString};
use lurker_core::core::OutputFeatures;
use lurker_core::global;
use lurker_util::logger::LoggingConfig;
use lurker_wallet_config::WalletConfig;
use lurker_wallet_libwallet::mwixnet::SwapReq;
use rand::thread_rng;
use uuid::Uuid;

impl<L, C, K> OwnerRpc for Owner<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, Error> {
		owner::accounts(&mut **self.wallet_inst.lock())
	}

	fn create_account_path(&self, token: Token, label: String) -> Result<Identifier, Error> {
		owner::create_account_path(
			self.wallet_inst.lock().as_mut(),
			token.keychain_mask.as_ref(),
			&label,
		)
	}

	fn set_active_account(&self, token: Token, label: String) -> Result<(), Error> {
		owner::set_active_account(&mut **self.wallet_inst.lock(), &label).map_err(Error::from)
	}

	fn retrieve_outputs(
		&self,
		token: Token,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), Error> {
		owner::retrieve_outputs(
			self.wallet_inst.clone(),
			token.keychain_mask.as_ref(),
			&None,
			refresh_from_node,
			include_spent,
			tx_id,
		)
	}

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), Error> {
		owner::retrieve_txs(
			self.wallet_inst.clone(),
			token.keychain_mask.as_ref(),
			&None,
			refresh_from_node,
			tx_id,
			tx_slate_id,
			None,
		)
	}

	fn query_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		query: RetrieveTxQueryArgs,
	) -> Result<(bool, Vec<TxLogEntry>), Error> {
		owner::retrieve_txs(
			self.wallet_inst.clone(),
			token.keychain_mask.as_ref(),
			&None,
			refresh_from_node,
			None,
			None,
			Some(query),
		)
	}

	fn retrieve_summary_info(
		&self,
		token: Token,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), Error> {
		owner::retrieve_summary_info(
			self.wallet_inst.clone(),
			token.keychain_mask.as_ref(),
			&None,
			refresh_from_node,
			minimum_confirmations,
		)
	}

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, Error> {
		let w_lock = self.wallet_inst.lock();
		let mut lc = w_lock.lc_provider()?;
		let w = lc.wallet_inst()?;
		let _ = w.keychain(token.keychain_mask.as_ref())?;
		let slate = owner::init_send_tx(&mut **w, token.keychain_mask.as_ref(), args, true)?;
		Ok(VersionedSlate::into_version(slate, SlateVersion::V4)?)
	}

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, Error> {
		let w_lock = self.wallet_inst.lock();
		let mut lc = w_lock.lc_provider()?;
		let w = lc.wallet_inst()?;
		let slate = owner::issue_invoice_tx(&mut **w, token.keychain_mask.as_ref(), args, true)?;
		Ok(VersionedSlate::into_version(slate, SlateVersion::V4)?)
	}

	fn process_invoice_tx(
		&self,
		token: Token,
		slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, Error> {
		let inner: Slate = slate.into();
		let out = owner::process_invoice_tx(
			self.wallet_inst.lock().as_mut(),
			token.keychain_mask.as_ref(),
			&inner,
			args,
			true,
		)?;
		Ok(VersionedSlate::into_version(out, SlateVersion::V4)?)
	}

	fn tx_lock_outputs(&self, token: Token, slate: VersionedSlate) -> Result<(), Error> {
		let w_lock = self.wallet_inst.lock();
		let mut lc = w_lock.lc_provider()?;
		let w = lc.wallet_inst()?;
		let inner: Slate = slate.into();
		owner::tx_lock_outputs(&mut **w, token.keychain_mask.as_ref(), &inner)
	}

	fn finalize_tx(&self, token: Token, slate: VersionedSlate) -> Result<VersionedSlate, Error> {
		let w_lock = self.wallet_inst.lock();
		let mut lc = w_lock.lc_provider()?;
		let w = lc.wallet_inst()?;
		let mut inner: Slate = slate.into();
		let finalized = owner::finalize_tx(&mut **w, token.keychain_mask.as_ref(), &mut inner)?;
		Ok(VersionedSlate::into_version(finalized, SlateVersion::V4)?)
	}

	fn post_tx(&self, token: Token, slate: VersionedSlate, fluff: bool) -> Result<(), Error> {
		let inner: Slate = slate.into();
		let client = {
			let w_lock = self.wallet_inst.lock();
			let mut lc = w_lock.lc_provider()?;
			let inst = lc.wallet_inst()?;
			let _ = inst.keychain(token.keychain_mask.as_ref())?;
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
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), Error> {
		owner::cancel_tx(
			self.wallet_inst.clone(),
			token.keychain_mask.as_ref(),
			&None,
			tx_id,
			tx_slate_id,
		)
	}

	fn get_stored_tx(
		&self,
		token: Token,
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

	fn get_rewind_hash(&self, token: Token) -> Result<String, Error> {
		owner::get_rewind_hash(self.wallet_inst.clone(), token.keychain_mask.as_ref())
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
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), Error> {
		owner::scan(
			self.wallet_inst.clone(),
			token.keychain_mask.as_ref(),
			start_height,
			delete_unconfirmed,
			&None,
		)
	}

	fn node_height(&self, token: Token) -> Result<NodeHeightResult, Error> {
		owner::node_height(self.wallet_inst.clone(), token.keychain_mask.as_ref())
	}

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, Error> {
		let secp = static_secp_instance().lock();
		let sec_key = SecretKey::new(&secp, &mut thread_rng());
		let mut shared = ecdh_pubkey.ecdh_pubkey;
		shared.mul_assign(&secp, &sec_key)?;
		let shared_key = SecretKey::from_slice(&secp, &shared.serialize_vec(&secp, true)[1..])?;
		*self.shared_key.lock() = Some(shared_key);
		let pubkey = PublicKey::from_secret_key(&secp, &sec_key)?;
		Ok(ECDHPubkey {
			ecdh_pubkey: pubkey,
		})
	}

	fn get_top_level_directory(&self) -> Result<String, Error> {
		Owner::get_top_level_directory(self)
	}

	fn set_top_level_directory(&self, dir: String) -> Result<(), Error> {
		Owner::set_top_level_directory(self, &dir)
	}

	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
	) -> Result<(), Error> {
		Owner::create_config(self, &chain_type, wallet_config, logging_config)
	}

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), Error> {
		let name = name.as_deref();
		let mnemonic = mnemonic.map(ZeroingString::from);
		Owner::create_wallet(
			self,
			name,
			mnemonic,
			mnemonic_length,
			ZeroingString::from(password),
		)
	}

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, Error> {
		let name = name.as_deref();
		let mask = Owner::open_wallet(self, name, ZeroingString::from(password), true)?;
		Ok(Token {
			keychain_mask: mask,
		})
	}

	fn close_wallet(&self, name: Option<String>) -> Result<(), Error> {
		Owner::close_wallet(self, name.as_deref())
	}

	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, Error> {
		let name = name.as_deref();
		Ok(Owner::get_mnemonic(self, name, ZeroingString::from(password))?.to_string())
	}

	fn change_password(&self, name: Option<String>, old: String, new: String) -> Result<(), Error> {
		let name = name.as_deref();
		Owner::change_password(
			self,
			name,
			ZeroingString::from(old),
			ZeroingString::from(new),
		)
	}

	fn delete_wallet(&self, name: Option<String>) -> Result<(), Error> {
		Owner::delete_wallet(self, name.as_deref())
	}

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), Error> {
		Owner::start_updater(
			self,
			token.keychain_mask.as_ref(),
			Duration::from_millis(frequency as u64),
		)
	}

	fn stop_updater(&self) -> Result<(), Error> {
		Owner::stop_updater(self)
	}

	fn get_updater_messages(&self, count: u32) -> Result<Vec<StatusMessage>, Error> {
		Owner::get_updater_messages(self, count as usize)
	}

	fn get_slatepack_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<SlatepackAddress, Error> {
		Owner::get_slatepack_address(self, token.keychain_mask.as_ref(), derivation_index)
	}

	fn get_slatepack_secret_key(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<Ed25519SecretKey, Error> {
		let key =
			Owner::get_slatepack_secret_key(self, token.keychain_mask.as_ref(), derivation_index)?;
		Ok(Ed25519SecretKey { key })
	}

	fn create_slatepack_message(
		&self,
		token: Token,
		slate: VersionedSlate,
		sender_index: Option<u32>,
		recipients: Vec<SlatepackAddress>,
	) -> Result<String, Error> {
		let inner: Slate = slate.into();
		Owner::create_slatepack_message(
			self,
			token.keychain_mask.as_ref(),
			&inner,
			sender_index,
			recipients,
		)
	}

	fn slate_from_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<VersionedSlate, Error> {
		let slate = Owner::slate_from_slatepack_message(
			self,
			token.keychain_mask.as_ref(),
			message,
			secret_indices,
		)?;
		Ok(VersionedSlate::into_version(slate, SlateVersion::V4)?)
	}

	fn decode_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<Slatepack, Error> {
		Owner::decode_slatepack_message(self, token.keychain_mask.as_ref(), message, secret_indices)
	}

	fn retrieve_payment_proof(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, Error> {
		Owner::retrieve_payment_proof(
			self,
			token.keychain_mask.as_ref(),
			refresh_from_node,
			tx_id,
			tx_slate_id,
		)
	}

	fn verify_payment_proof(
		&self,
		token: Token,
		proof: PaymentProof,
	) -> Result<(bool, bool), Error> {
		Owner::verify_payment_proof(self, token.keychain_mask.as_ref(), &proof)
	}

	fn build_output(
		&self,
		token: Token,
		features: OutputFeatures,
		amount: Amount,
	) -> Result<BuiltOutput, Error> {
		Owner::build_output(self, token.keychain_mask.as_ref(), features, amount.0)
	}

	fn create_mwixnet_req(
		&self,
		token: Token,
		commitment: String,
		fee_per_hop: String,
		lock_output: bool,
		server_keys: Vec<String>,
	) -> Result<SwapReq, Error> {
		let commit_bytes = from_hex(&commitment).map_err(|e| Error::GenericError(e.to_string()))?;
		let commit = Commitment::from_vec(commit_bytes);

		let secp = static_secp_instance().lock();
		let keys: Vec<SecretKey> = server_keys
			.into_iter()
			.map(|s| {
				let bytes =
					from_hex(&s).map_err(|e| Error::GenericError(format!("Invalid key: {}", e)))?;
				SecretKey::from_slice(&secp, &bytes)
					.map_err(|e| Error::GenericError(format!("Bad key: {}", e)))
			})
			.collect::<Result<Vec<_>, _>>()?;

		let params = MixnetReqCreationParams {
			server_keys: keys,
			fee_per_hop: fee_per_hop
				.parse()
				.map_err(|e| Error::GenericError(e.to_string()))?,
		};

		Owner::create_mwixnet_req(
			self,
			token.keychain_mask.as_ref(),
			&params,
			&commit,
			lock_output,
		)
	}
}
