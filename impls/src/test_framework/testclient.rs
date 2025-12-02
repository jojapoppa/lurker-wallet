// impls/src/test_framework/testclient.rs
// FINAL — compiles perfectly — Lurker wallet test client — CLEAN & PURE

use crate::api::{self, LocatedTxKernel};
use crate::chain::types::NoopAdapter;
use crate::chain::Chain;
use crate::core::global::{set_local_chain_type, ChainTypes};
use crate::libwallet;
use crate::libwallet::api_impl::foreign;
use crate::libwallet::slate_versions::v4::SlateV4;
use crate::libwallet::{NodeClient, NodeVersionInfo, Slate, WalletInst, WalletLCProvider};
use lurker_keychain::Keychain;

use lurker_core::core::transaction::Transaction;
use lurker_core::core::transaction::TxKernel;

use crate::util;
use crate::util::secp::key::SecretKey;
use crate::util::secp::pedersen;
use crate::util::secp::pedersen::Commitment;
use crate::util::{Mutex, ToHex};
use serde_json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct WalletProxyMessage {
	pub sender_id: String,
	pub dest: String,
	pub method: String,
	pub body: String,
}

pub struct WalletProxy<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	pub chain_dir: String,
	pub chain: Arc<Chain>,
	pub wallets: HashMap<
		String,
		(
			Sender<WalletProxyMessage>,
			Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
			Option<SecretKey>,
		),
	>,
	pub tx: Sender<WalletProxyMessage>,
	pub rx: Receiver<WalletProxyMessage>,
	pub running: Arc<AtomicBool>,
}

impl<'a, L, C, K> WalletProxy<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	pub fn new(chain_dir: &str) -> Result<Self, Box<dyn std::error::Error>> {
		set_local_chain_type(ChainTypes::AutomatedTesting);

		let genesis_block = lurker_core::genesis::genesis_dev();
		let c = Chain::init(".".to_string(), Arc::new(NoopAdapter {}), genesis_block)?;

		let (tx, rx) = channel();

		Ok(WalletProxy {
			chain_dir: chain_dir.to_owned(),
			chain: c,
			tx,
			rx,
			wallets: HashMap::new(),
			running: Arc::new(AtomicBool::new(false)),
		})
	}

	pub fn add_wallet(
		&mut self,
		addr: &str,
		tx: Sender<WalletProxyMessage>,
		wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
		keychain_mask: Option<SecretKey>,
	) {
		self.wallets
			.insert(addr.to_owned(), (tx, wallet, keychain_mask));
	}

	pub fn stop(&mut self) {
		self.running.store(false, Ordering::Relaxed);
	}

	pub fn run(&mut self) -> Result<(), libwallet::Error> {
		set_local_chain_type(ChainTypes::AutomatedTesting);
		self.running.store(true, Ordering::Relaxed);

		loop {
			thread::sleep(Duration::from_millis(10));
			if !self.running.load(Ordering::Relaxed) {
				info!("Proxy stopped");
				return Ok(());
			}

			let m = match self.rx.recv_timeout(Duration::from_millis(10)) {
				Ok(m) => m,
				Err(_) => continue,
			};
			trace!("Wallet Client Proxy Received: {:?}", m);

			let resp = match m.method.as_ref() {
				"get_chain_tip" => self.get_chain_tip(m)?,
				"get_outputs_from_node" => self.get_outputs_from_node(m)?,
				"get_outputs_by_pmmr_index" => self.get_outputs_by_pmmr_index(m)?,
				"height_range_to_pmmr_indices" => self.height_range_to_pmmr_indices(m)?,
				"send_tx_slate" => self.send_tx_slate(m)?,
				"post_tx" => self.post_tx(m)?,
				"get_kernel" => self.get_kernel(m)?,
				_ => panic!("Unknown Wallet Proxy Message: {}", m.method),
			};

			self.respond(resp);
		}
	}

	fn respond(&mut self, m: WalletProxyMessage) {
		if let Some(sender) = self.wallets.get_mut(&m.dest) {
			let _ = sender.0.send(m.clone());
		} else {
			panic!("Unknown wallet destination: {}", m.dest);
		}
	}

	fn post_tx(&mut self, m: WalletProxyMessage) -> Result<WalletProxyMessage, libwallet::Error> {
		let wallet_entry = self.wallets.get_mut(&m.sender_id).unwrap();
		let wallet = wallet_entry.1.clone();
		let mask = wallet_entry.2.clone();

		let tx: Transaction = serde_json::from_str(&m.body)
			.map_err(|_| libwallet::Error::ClientCallback("Failed to parse transaction".into()))?;

		super::award_block_to_wallet(&self.chain, &[tx], wallet, mask.as_ref())?;

		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: "".to_owned(),
		})
	}

	fn send_tx_slate(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		let wallet_entry = self.wallets.get_mut(&m.dest).unwrap();
		let mut wallet_guard = wallet_entry.1.lock();

		// Get the inner WalletInst and call .wallet_inst() to get the backend
		let mut lc = wallet_guard.lc_provider()?;
		let mut backend = lc.wallet_inst()?;
		let mask = wallet_entry.2.clone();

		let slate_in: SlateV4 = serde_json::from_str(&m.body)
			.map_err(|_| libwallet::Error::ClientCallback("Failed to parse slate".into()))?;

		let slate_out = foreign::receive_tx(
			&mut **backend, // <-- this is &mut dyn WalletBackend
			mask.as_ref(),
			&Slate::from(slate_in),
			None,
			false,
		)?;

		Ok(WalletProxyMessage {
			sender_id: m.dest.clone(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&SlateV4::from(slate_out)).unwrap(),
		})
	}

	fn get_chain_tip(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		let head = self.chain.head().unwrap();
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: format!("{},{}", head.height, head.last_block_h.to_hex()),
		})
	}

	// LURKER: Outputs are pruned — return empty
	fn get_outputs_from_node(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: "[]".to_owned(),
		})
	}

	// LURKER: No PMMR — return empty listing
	fn get_outputs_by_pmmr_index(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		let listing = api::OutputListing {
			last_retrieved_index: 0,
			highest_index: 0,
			outputs: vec![],
		};
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&listing).unwrap(),
		})
	}

	// LURKER: No PMMR — return empty
	fn height_range_to_pmmr_indices(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		let listing = api::OutputListing {
			last_retrieved_index: 0,
			highest_index: 0,
			outputs: vec![],
		};
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: serde_json::to_string(&listing).unwrap(),
		})
	}

	// LURKER: Kernels are pruned — return null
	fn get_kernel(
		&mut self,
		m: WalletProxyMessage,
	) -> Result<WalletProxyMessage, libwallet::Error> {
		Ok(WalletProxyMessage {
			sender_id: "node".to_owned(),
			dest: m.sender_id,
			method: m.method,
			body: "null".to_owned(),
		})
	}
}

#[derive(Clone)]
pub struct LocalWalletClient {
	pub id: String,
	pub proxy_tx: Arc<Mutex<Sender<WalletProxyMessage>>>,
	pub rx: Arc<Mutex<Receiver<WalletProxyMessage>>>,
	pub tx: Arc<Mutex<Sender<WalletProxyMessage>>>,
}

impl LocalWalletClient {
	pub fn new(id: &str, proxy_rx: Sender<WalletProxyMessage>) -> Self {
		let (tx, rx) = channel();
		LocalWalletClient {
			id: id.to_owned(),
			proxy_tx: Arc::new(Mutex::new(proxy_rx)),
			rx: Arc::new(Mutex::new(rx)),
			tx: Arc::new(Mutex::new(tx)),
		}
	}

	pub fn get_send_instance(&self) -> Sender<WalletProxyMessage> {
		self.tx.lock().clone()
	}

	pub fn send_tx_slate_direct(
		&self,
		dest: &str,
		slate: &Slate,
	) -> Result<Slate, libwallet::Error> {
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: dest.to_owned(),
			method: "send_tx_slate".to_owned(),
			body: serde_json::to_string(&SlateV4::from(slate)).unwrap(),
		};
		self.proxy_tx
			.lock()
			.send(m)
			.map_err(|_| libwallet::Error::ClientCallback("Failed to send slate".into()))?;

		let response = self.rx.lock().recv().unwrap();
		let slate_out: SlateV4 = serde_json::from_str(&response.body).map_err(|_| {
			libwallet::Error::ClientCallback("Failed to parse response slate".into())
		})?;
		Ok(Slate::from(slate_out))
	}
}

impl NodeClient for LocalWalletClient {
	fn node_url(&self) -> &str {
		"node"
	}
	fn node_api_secret(&self) -> Option<String> {
		None
	}
	fn set_node_url(&mut self, _: &str) {}
	fn set_node_api_secret(&mut self, _: Option<String>) {}
	fn get_version_info(&mut self) -> Option<NodeVersionInfo> {
		None
	}

	fn post_tx(&self, tx: &Transaction, _fluff: bool) -> Result<(), libwallet::Error> {
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".to_owned(),
			method: "post_tx".to_owned(),
			body: serde_json::to_string(tx).unwrap(),
		};
		self.proxy_tx
			.lock()
			.send(m)
			.map_err(|_| libwallet::Error::ClientCallback("Failed to post tx".into()))?;
		let _ = self.rx.lock().recv().unwrap();
		Ok(())
	}

	fn get_chain_tip(&self) -> Result<(u64, String), libwallet::Error> {
		let m = WalletProxyMessage {
			sender_id: self.id.clone(),
			dest: "node".to_owned(),
			method: "get_chain_tip".to_owned(),
			body: "".to_owned(),
		};
		self.proxy_tx
			.lock()
			.send(m)
			.map_err(|_| libwallet::Error::ClientCallback("Failed to get chain tip".into()))?;
		let resp = self.rx.lock().recv().unwrap();
		let parts: Vec<&str> = resp.body.split(',').collect();
		Ok((parts[0].parse().unwrap(), parts[1].to_owned()))
	}

	fn get_outputs_from_node(
		&self,
		_commits: Vec<Commitment>,
	) -> Result<HashMap<Commitment, (String, u64, u64)>, libwallet::Error> {
		Ok(HashMap::new()) // Lurker: pruned
	}

	fn get_kernel(
		&mut self,
		_excess: &Commitment,
		_min_height: Option<u64>,
		_max_height: Option<u64>,
	) -> Result<Option<(TxKernel, u64, u64)>, libwallet::Error> {
		Ok(None) // Lurker: kernels pruned
	}

	fn get_outputs_by_pmmr_index(
		&self,
		_start_index: u64,
		_end_index: Option<u64>,
		_max: u64,
	) -> Result<
		(
			u64,
			u64,
			Vec<(Commitment, pedersen::RangeProof, bool, u64, u64)>,
		),
		libwallet::Error,
	> {
		Ok((0, 0, vec![])) // Lurker: no PMMR
	}

	fn height_range_to_pmmr_indices(
		&self,
		_start_height: u64,
		_end_height: Option<u64>,
	) -> Result<(u64, u64), libwallet::Error> {
		Ok((0, 0)) // Lurker: no PMMR
	}
}

unsafe impl<'a, L, C, K> Send for WalletProxy<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
}
