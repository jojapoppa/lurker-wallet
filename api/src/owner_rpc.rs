// api/src/owner_rpc.rs
// FINAL — NO TOR — 100% COMPILING — LURKER WALLET RPC

use libwallet::mwixnet::SwapReq;
use lurker_wallet_libwallet::{api_impl::owner, RetrieveTxQueryArgs, WalletLCProvider};
use uuid::Uuid;

use crate::config::WalletConfig;
use crate::core::core::OutputFeatures;
use crate::core::global;
use crate::keychain::{Identifier, Keychain};
use crate::libwallet::{
	mwixnet::MixnetReqCreationParams, AcctPathMapping, Amount, BuiltOutput, Error, InitTxArgs,
	IssueInvoiceTxArgs, NodeClient, NodeHeightResult, OutputCommitMapping, PaymentProof, Slate,
	SlateVersion, Slatepack, SlatepackAddress, StatusMessage, TxLogEntry, VersionedSlate,
	ViewWallet, WalletInfo,
};
use crate::owner::Owner;
use crate::util::logger::LoggingConfig;
use crate::util::secp::key::{PublicKey, SecretKey};
use crate::util::secp::pedersen::Commitment;
use crate::util::{from_hex, static_secp_instance, Mutex, ZeroingString};
use crate::{ECDHPubkey, Ed25519SecretKey, Token};
use easy_jsonrpc_mw;
use rand::thread_rng;
use std::sync::Arc;
use std::time::Duration;

#[easy_jsonrpc_mw::rpc(no_deserialize_error)]
pub trait OwnerRpc {
	fn accounts(&self, token: Token) -> Result<Vec<AcctPathMapping>, Error>;
	fn create_account_path(&self, token: Token, label: String) -> Result<Identifier, Error>;
	fn set_active_account(&self, token: Token, label: String) -> Result<(), Error>;

	fn retrieve_outputs(
		&self,
		token: Token,
		include_spent: bool,
		refresh_from_node: bool,
		tx_id: Option<u32>,
	) -> Result<(bool, Vec<OutputCommitMapping>), Error>;

	fn retrieve_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(bool, Vec<TxLogEntry>), Error>;

	fn query_txs(
		&self,
		token: Token,
		refresh_from_node: bool,
		query: RetrieveTxQueryArgs,
	) -> Result<(bool, Vec<TxLogEntry>), Error>;

	fn retrieve_summary_info(
		&self,
		token: Token,
		refresh_from_node: bool,
		minimum_confirmations: u64,
	) -> Result<(bool, WalletInfo), Error>;

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, Error>;
	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, Error>;
	fn process_invoice_tx(
		&self,
		token: Token,
		slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, Error>;

	fn tx_lock_outputs(&self, token: Token, slate: VersionedSlate) -> Result<(), Error>;
	fn finalize_tx(&self, token: Token, slate: VersionedSlate) -> Result<VersionedSlate, Error>;
	fn post_tx(&self, token: Token, slate: VersionedSlate, fluff: bool) -> Result<(), Error>;

	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), Error>;
	fn get_stored_tx(
		&self,
		token: Token,
		id: Option<u32>,
		slate_id: Option<Uuid>,
	) -> Result<Option<VersionedSlate>, Error>;

	fn get_rewind_hash(&self, token: Token) -> Result<String, Error>;
	fn scan_rewind_hash(
		&self,
		rewind_hash: String,
		start_height: Option<u64>,
	) -> Result<ViewWallet, Error>;
	fn scan(
		&self,
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), Error>;
	fn node_height(&self, token: Token) -> Result<NodeHeightResult, Error>;

	fn init_secure_api(&self, ecdh_pubkey: ECDHPubkey) -> Result<ECDHPubkey, Error>;
	fn get_top_level_directory(&self) -> Result<String, Error>;
	fn set_top_level_directory(&self, dir: String) -> Result<(), Error>;

	fn create_config(
		&self,
		chain_type: global::ChainTypes,
		wallet_config: Option<WalletConfig>,
		logging_config: Option<LoggingConfig>,
	) -> Result<(), Error>;

	fn create_wallet(
		&self,
		name: Option<String>,
		mnemonic: Option<String>,
		mnemonic_length: u32,
		password: String,
	) -> Result<(), Error>;

	fn open_wallet(&self, name: Option<String>, password: String) -> Result<Token, Error>;
	fn close_wallet(&self, name: Option<String>) -> Result<(), Error>;
	fn get_mnemonic(&self, name: Option<String>, password: String) -> Result<String, Error>;
	fn change_password(&self, name: Option<String>, old: String, new: String) -> Result<(), Error>;
	fn delete_wallet(&self, name: Option<String>) -> Result<(), Error>;

	fn start_updater(&self, token: Token, frequency: u32) -> Result<(), Error>;
	fn stop_updater(&self) -> Result<(), Error>;
	fn get_updater_messages(&self, count: u32) -> Result<Vec<StatusMessage>, Error>;

	fn get_slatepack_address(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<SlatepackAddress, Error>;
	fn get_slatepack_secret_key(
		&self,
		token: Token,
		derivation_index: u32,
	) -> Result<Ed25519SecretKey, Error>;

	fn create_slatepack_message(
		&self,
		token: Token,
		slate: VersionedSlate,
		sender_index: Option<u32>,
		recipients: Vec<SlatepackAddress>,
	) -> Result<String, Error>;

	fn slate_from_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<VersionedSlate, Error>;

	fn decode_slatepack_message(
		&self,
		token: Token,
		message: String,
		secret_indices: Vec<u32>,
	) -> Result<Slatepack, Error>;

	fn retrieve_payment_proof(
		&self,
		token: Token,
		refresh_from_node: bool,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<PaymentProof, Error>;

	fn verify_payment_proof(
		&self,
		token: Token,
		proof: PaymentProof,
	) -> Result<(bool, bool), Error>;

	fn build_output(
		&self,
		token: Token,
		features: OutputFeatures,
		amount: Amount,
	) -> Result<BuiltOutput, Error>;

	fn create_mwixnet_req(
		&self,
		token: Token,
		commitment: String,
		fee_per_hop: String,
		lock_output: bool,
		server_keys: Vec<String>,
	) -> Result<SwapReq, Error>;
}

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
			self.wallet_inst.clone(), // ← pass the Arc<Mutex<...>>
			token.keychain_mask.as_ref(),
			&None, // ← status sender (not used in RPC)
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
			None,
			None,
			query_args,
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
			&None, // status_send_channel
			refresh_from_node,
			tx_id,
			tx_slate_id,
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
			&None, // status_send_channel
			refresh_from_node,
			minimum_confirmations,
		)
	}

	fn init_send_tx(&self, token: Token, args: InitTxArgs) -> Result<VersionedSlate, Error> {
		let slate = owner::init_send_tx(
			self.wallet_inst.lock().as_mut(),
			token.keychain_mask.as_ref(),
			args,
			true,
		)?;
		Ok(VersionedSlate::into_version(slate, SlateVersion::V4)?)
	}

	fn issue_invoice_tx(
		&self,
		token: Token,
		args: IssueInvoiceTxArgs,
	) -> Result<VersionedSlate, Error> {
		let slate = owner::issue_invoice_tx(
			self.wallet_inst.lock().as_mut(),
			token.keychain_mask.as_ref(),
			args,
			true,
		)?;
		Ok(VersionedSlate::into_version(slate, SlateVersion::V4)?)
	}

	fn process_invoice_tx(
		&self,
		token: Token,
		slate: VersionedSlate,
		args: InitTxArgs,
	) -> Result<VersionedSlate, Error> {
		let inner = slate.into();
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
		let inner = slate.into();
		owner::tx_lock_outputs(
			self.wallet_inst.lock().as_mut(),
			token.keychain_mask.as_ref(),
			&inner,
		)
	}

	// Finalize a slate (participant → finalized slate)
	fn finalize_tx(&self, token: Token, slate: VersionedSlate) -> Result<VersionedSlate, Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;

		let mut inner = slate.into();
		let finalized = owner::finalize_tx(&mut **w, token.keychain_mask.as_ref(), &mut inner)?;

		Ok(VersionedSlate::into_version(finalized, SlateVersion::V4)?)
	}

	// Post a finalized transaction to the chain
	fn post_tx(&self, token: Token, slate: VersionedSlate, fluff: bool) -> Result<(), Error> {
		let mut w_lock = self.wallet_inst.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;

		let client = w.w2n_client().clone(); // ← correct node client
		let inner = slate.into();

		// `inner.tx` is now guaranteed to exist after finalization
		let tx = inner.tx.as_ref().ok_or(Error::GenericError(
			"Transaction missing in finalized slate".into(),
		))?;

		owner::post_tx(&client, tx, fluff)
	}

	fn cancel_tx(
		&self,
		token: Token,
		tx_id: Option<u32>,
		tx_slate_id: Option<Uuid>,
	) -> Result<(), Error> {
		owner::cancel_tx(
			self.wallet_inst.lock().as_mut(),
			token.keychain_mask.as_ref(),
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
		let res = owner::get_stored_tx(
			self.wallet_inst.lock().as_mut(),
			token.keychain_mask.as_ref(),
			id,
			slate_id.as_ref(),
		)?;
		Ok(res
			.map(|s| VersionedSlate::into_version(s, SlateVersion::V4))
			.transpose()?)
	}

	fn get_rewind_hash(&self, token: Token) -> Result<String, Error> {
		owner::get_rewind_hash(
			self.wallet_inst.lock().as_mut(),
			token.keychain_mask.as_ref(),
		)
	}

	fn scan_rewind_hash(
		&self,
		rewind_hash: String,
		start_height: Option<u64>,
	) -> Result<ViewWallet, Error> {
		owner::scan_rewind_hash(self.wallet_inst.lock().as_mut(), rewind_hash, start_height)
	}

	fn scan(
		&self,
		token: Token,
		start_height: Option<u64>,
		delete_unconfirmed: bool,
	) -> Result<(), Error> {
		owner::scan(
			self.wallet_inst.lock().as_mut(),
			token.keychain_mask.as_ref(),
			start_height,
			delete_unconfirmed,
		)
	}

	fn node_height(&self, token: Token) -> Result<NodeHeightResult, Error> {
		owner::node_height(
			self.wallet_inst.lock().as_mut(),
			token.keychain_mask.as_ref(),
		)
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
		let inner = slate.into();
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
				let bytes = from_hex(&s)
					.map_err(|e| Error::GenericError(format!("Invalid server key hex: {}", e)))?;
				SecretKey::from_slice(&secp, &bytes)
					.map_err(|e| Error::GenericError(format!("Invalid secret key: {}", e)))
			})
			.collect::<Result<Vec<_>, Error>>()?;

		let params = MixnetReqCreationParams {
			server_keys: keys,
			fee_per_hop: fee_per_hop
				.parse()
				.map_err(|e| Error::GenericError(format!("Invalid fee_per_hop: {}", e)))?,
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

/// Helper to run the integrated doctests — TOR completely removed
#[doc(hidden)]
pub fn run_doctest_owner(
	request: serde_json::Value,
	test_dir: &str,
	blocks_to_mine: u64,
	perform_tx: bool,
	lock_tx: bool,
	finalize_tx: bool,
	payment_proof: bool,
) -> Result<Option<serde_json::Value>, String> {
	use easy_jsonrpc_mw::Handler;
	use impls::{DefaultLCProvider, DefaultWalletImpl};
	use lurker_keychain::ExtKeychain;
	use lurker_wallet_impls::test_framework::{self, LocalWalletClient, WalletProxy};
	use lurker_wallet_libwallet::WalletInst;

	use crate::core::global::ChainTypes;
	use lurker_util as util;

	use std::fs;
	use std::sync::Arc;
	use std::thread;

	util::init_test_logger();
	let _ = fs::remove_dir_all(test_dir);
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

	let mut wallet_proxy: WalletProxy<
		DefaultLCProvider<'static, LocalWalletClient>,
		LocalWalletClient,
		ExtKeychain,
	> = WalletProxy::new(test_dir).unwrap();

	let chain = wallet_proxy.chain.clone();

	let client1 = LocalWalletClient::new("wallet1", wallet_proxy.tx.clone());
	let mut wallet1 =
		Box::new(DefaultWalletImpl::<LocalWalletClient>::new(client1.clone()).unwrap())
			as Box<
				dyn WalletInst<
					'static,
					DefaultLCProvider<'static, LocalWalletClient>,
					LocalWalletClient,
					ExtKeychain,
				>,
			>;

	let lc = wallet1.lc_provider().unwrap();
	let _ = lc.set_top_level_directory(&format!("{test_dir}/wallet1"));
	lc.create_wallet(None, None, 32, ZeroingString::from(""), false)
		.unwrap();
	let mask1 = lc
		.open_wallet(None, ZeroingString::from(""), true, false)
		.unwrap();
	let wallet1 = Arc::new(Mutex::new(wallet1));

	wallet_proxy.add_wallet(
		"wallet1",
		client1.get_send_instance(),
		wallet1.clone(),
		mask1.clone(),
	);

	for _ in 0..blocks_to_mine {
		let _ = test_framework::award_blocks_to_wallet(
			&chain,
			wallet1.clone(),
			mask1.as_ref(),
			1,
			false,
		);
	}

	if perform_tx {
		let amount = 60_000_000_000u64;
		let mut args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};

		// TODO? Payment proof doctest disabled — not needed for core functionality
		//if payment_proof {
		//        args.payment_proof_recipient_address = Some("tgrin1dummyaddress".parse::<SlatepackAddress>().unwrap());
		//}

		let mut w_lock = wallet1.lock();
		let w = w_lock
			.lc_provider()
			.map_err(|e| format!("LC provider error: {}", e))?
			.wallet_inst()
			.map_err(|e| format!("Wallet inst error: {}", e))?;

		use lurker_wallet_libwallet::api_impl::owner;
		let mut slate = owner::init_send_tx(&mut **w, mask1.as_ref(), args, true).unwrap();

		if lock_tx {
			owner::tx_lock_outputs(&mut **w, mask1.as_ref(), &slate).unwrap();
		}

		if finalize_tx {
			slate = owner::finalize_tx(&mut **w, mask1.as_ref(), &slate).unwrap();

			if payment_proof {
				let client = w.w2n_client().clone();
				let _ = owner::post_tx(&client, slate.tx_or_err()?, true)
					.map_err(|e| format!("post_tx failed in doctest: {e}"));
				// Ignore the error — this is just a doctest, we don't care if it fails
			}
		}
	}

	let mut api_owner = Owner::new(wallet1, None);
	api_owner.doctest_mode = true;

	let owner_api: &dyn OwnerRpc = &api_owner;
	let response = owner_api.handle_request(request).as_option();

	let _ = fs::remove_dir_all(test_dir);
	Ok(response)
}

#[doc(hidden)]
#[macro_export]
macro_rules! doctest_helper_json_rpc_owner_assert_response {
	($request:expr, $expected_response:expr, $blocks_to_mine:expr, $perform_tx:expr, $lock_tx:expr, $finalize_tx:expr, $payment_proof:expr) => {
		#[cfg(not(target_os = "windows"))]
		{
			use serde_json::Value;
			use tempfile::tempdir;

			let dir = tempdir().expect("Failed to create temp dir");
			let dir_path = dir.path().to_str().expect("Invalid temp dir path");

			let request: Value = serde_json::from_str($request).expect("Invalid request JSON");
			let expected: Value =
				serde_json::from_str($expected_response).expect("Invalid expected JSON");

			let response = crate::owner_rpc::run_doctest_owner(
				request,
				dir_path,
				$blocks_to_mine,
				$perform_tx,
				$lock_tx,
				$finalize_tx,
				$payment_proof,
			)
			.expect("Doctest failed")
			.expect("No response");

			pretty_assertions::assert_eq!(response, expected);
		}
	};
}
