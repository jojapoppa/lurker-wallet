// controller/src/controller.rs
// Lurker Wallet — Minimal, clean Owner + Foreign API (2025)

use api_common::json_rpc::{Handler, MaybeReply};
use api_common::{ForeignRpc, OwnerRpc};

use lurker_wallet_impls::{Foreign, Owner};

use crate::keychain::Keychain;
use crate::libwallet::{Error, NodeClient, WalletInst, WalletLCProvider};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use log::warn;
use lurker_wallet_libwallet::WalletOutputBatch;
use serde_json::Value;
use std::convert::Infallible;
use std::net::AddrParseError;
use std::net::SocketAddr;
use std::sync::Arc;

/// Single-use Owner API (used by CLI)
pub fn owner_single_use<L, F, C, K>(
	wallet: Option<Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>>,
	keychain_mask: Option<&SecretKey>,
	api_context: Option<&'static mut Owner<'static, L, C, K>>,
	f: F,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + WalletOutputBatch<K> + 'static,
	F: FnOnce(&mut Owner<'static, L, C, K>, Option<&SecretKey>) -> Result<(), Error>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	match api_context {
		Some(c) => f(c, keychain_mask)?,
		None => {
			let wallet = wallet.ok_or_else(|| {
				Error::GenericError("Wallet instance required for single-use Owner API".into())
			})?;
			f(&mut Owner::new(wallet, None), keychain_mask)?
		}
	}
	Ok(())
}

/// Single-use Foreign API (used by CLI receive/finalize)
pub fn foreign_single_use<'a, L, F, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K>>>>,
	keychain_mask: Option<SecretKey>,
	f: F,
) -> Result<(), Error>
where
	L: WalletLCProvider<'a, C, K>,
	F: FnOnce(&mut Foreign<'a, L, C, K>) -> Result<(), Error>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	f(&mut Foreign::new(wallet, keychain_mask))?;
	Ok(())
}

// ——————— Owner API Listener ———————

pub fn owner_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + WalletOutputBatch<K> + Send + Sync + 'static,
	C: NodeClient + Send + Sync + 'static,
	K: Keychain + Send + Sync + 'static,
{
	let owner = Arc::new(Owner::new(wallet, keychain_mask.lock().clone()));

	let make_service = make_service_fn(move |_conn| {
		let owner = owner.clone();
		async move {
			Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
				let owner = owner.clone();
				async move {
					let body_bytes = hyper::body::to_bytes(req.into_body())
						.await
						.unwrap_or_default();
					let json: Value = match serde_json::from_slice(&body_bytes) {
						Ok(j) => j,
						Err(_) => {
							return Ok(Response::builder()
								.status(StatusCode::BAD_REQUEST)
								.body("Invalid JSON".into())
								.unwrap())
						}
					};

					let reply = OwnerRpc::handle_request(&*owner, json);
					let resp_json = match reply {
						MaybeReply::Reply(r) => r,
						MaybeReply::DontReply => return Ok(Response::new(Body::empty())),
					};

					Ok(Response::builder()
						.status(StatusCode::OK)
						.header("Content-Type", "application/json")
						.body(Body::from(resp_json.to_string()))
						.unwrap())
				}
			}))
		}
	});

	let addr: SocketAddr = addr
		.parse()
		.map_err(|e| Error::GenericError(format!("Invalid listen address '{}': {}", addr, e)))?;

	let server = Server::bind(&addr).serve(make_service);

	warn!("Lurker Owner API listening on {}", addr);
	tokio::spawn(async move {
		if let Err(e) = server.await {
			error!("Owner API server error: {}", e);
		}
	});

	Ok(())
}

// ——————— Foreign API Listener ———————

pub fn foreign_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + Send + Sync + 'static,
	C: NodeClient + Send + Sync + 'static,
	K: Keychain + Send + Sync + 'static,
{
	let foreign = Arc::new(Foreign::new(wallet, keychain_mask.lock().clone()));

	let make_service = make_service_fn(move |_conn| {
		let foreign = foreign.clone();
		async move {
			Ok::<_, Infallible>(service_fn(move |req: Request<Body>| {
				let foreign = foreign.clone();
				async move {
					let body_bytes = hyper::body::to_bytes(req.into_body())
						.await
						.unwrap_or_default();
					let json: Value = match serde_json::from_slice(&body_bytes) {
						Ok(j) => j,
						Err(_) => {
							return Ok(Response::builder()
								.status(StatusCode::BAD_REQUEST)
								.body("Invalid JSON".into())
								.unwrap())
						}
					};

					let reply = ForeignRpc::handle_request(&*foreign, json);
					let resp_json = match reply {
						MaybeReply::Reply(r) => r,
						MaybeReply::DontReply => return Ok(Response::new(Body::empty())),
					};

					Ok(Response::builder()
						.status(StatusCode::OK)
						.header("Content-Type", "application/json")
						.body(Body::from(resp_json.to_string()))
						.unwrap())
				}
			}))
		}
	});

	let addr: SocketAddr = addr
		.parse()
		.map_err(|e| Error::GenericError(format!("Invalid listen address '{}': {}", addr, e)))?;

	let server = Server::bind(&addr).serve(make_service);

	warn!("Lurker Foreign API listening on {}", addr);
	tokio::spawn(async move {
		if let Err(e) = server.await {
			error!("Foreign API server error: {}", e);
		}
	});

	Ok(())
}
