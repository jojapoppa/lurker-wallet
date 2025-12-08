// controller/src/controller.rs

use crate::api::{ApiServer, BasicAuthMiddleware, TLSConfig};

use crate::api;
use async_trait::async_trait;
use hyper::body;
use hyper::header::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, StatusCode};
use lurker_wallet_api::owner::OwnerV3Helpers;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::keychain::Keychain;
use crate::libwallet::{
	Error, NodeClient, NodeVersionInfo, Slate, SlatepackAddress, WalletInst, WalletLCProvider,
	GRIN_BLOCK_HEADER_VERSION,
};

use crate::util::secp::key::SecretKey;
use crate::util::{from_hex, static_secp_instance, to_base64, Mutex};
use futures::channel::oneshot;
use lurker_wallet_api::JsonId;

use serde_json;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::apiwallet::{
	EncryptedRequest, EncryptedResponse, EncryptionErrorResponse, Foreign,
	ForeignCheckMiddlewareFn, ForeignRpc, Owner, OwnerRpc,
};
use easy_jsonrpc_mw;
use easy_jsonrpc_mw::Handler;
use easy_jsonrpc_mw::MaybeReply;

use hyper::Error as HyperError;
type ResponseFuture = Pin<Box<dyn Future<Output = Result<Response<Body>, HyperError>> + Send>>;

async fn not_found() -> Result<Response<Body>, hyper::Error> {
	Ok(Response::builder()
		.status(StatusCode::NOT_FOUND)
		.body("404 Not Found".into())
		.unwrap())
}

lazy_static! {
	pub static ref GRIN_OWNER_BASIC_REALM: HeaderValue =
		HeaderValue::from_str("Basic realm=GrinOwnerAPI").unwrap();
}

fn check_middleware(
	name: ForeignCheckMiddlewareFn,
	node_version_info: Option<NodeVersionInfo>,
	slate: Option<&Slate>,
) -> Result<(), Error> {
	match name {
		ForeignCheckMiddlewareFn::BuildCoinbase => Ok(()),
		_ => {
			let mut bhv = 3;
			if let Some(n) = node_version_info {
				bhv = n.block_header_version;
			}
			if let Some(s) = slate {
				if bhv > 4 && s.version_info.block_header_version < GRIN_BLOCK_HEADER_VERSION {
					Err(Error::Compatibility(
						"Incoming Slate is not compatible with this wallet. \
                         Please upgrade the node or use a different one."
							.into(),
					))?;
				}
			}
			Ok(())
		}
	}
}

/// Instantiate wallet Owner API for a single-use (command line) call
pub fn owner_single_use<L, F, C, K>(
	wallet: Option<Arc<Mutex<Box<dyn WalletInst<'static, L, C, K>>>>>,
	keychain_mask: Option<&SecretKey>,
	api_context: Option<&mut Owner<L, C, K>>,
	f: F,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	F: FnOnce(&mut Owner<L, C, K>, Option<&SecretKey>) -> Result<(), Error>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	match api_context {
		Some(c) => f(c, keychain_mask)?,
		None => {
			let wallet = match wallet {
				Some(w) => w,
				None => {
					return Err(Error::GenericError(
						"Instantiated wallet or Owner API context must be provided".into(),
					));
				}
			};
			f(&mut Owner::new(wallet, None), keychain_mask)?
		}
	}
	Ok(())
}

/// Instantiate wallet Foreign API for a single-use (command line) call
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
	f(&mut Foreign::new(
		wallet,
		keychain_mask,
		Some(check_middleware),
		false,
	))?;
	Ok(())
}

/// Owner API listener — TOR REMOVED
pub fn owner_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	api_secret: Option<String>,
	tls_config: Option<TLSConfig>,
	owner_api_include_foreign: Option<bool>,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let api_handler = Arc::new(OwnerAPIHandlerV3::new(
		wallet.clone(),
		keychain_mask.clone(),
		owner_api_include_foreign.unwrap_or(false),
	));

	let foreign_handler = if owner_api_include_foreign.unwrap_or(false) {
		Some(Arc::new(ForeignAPIHandlerV2::new(
			wallet,
			keychain_mask,
			test_mode,
		)))
	} else {
		None
	};

	let make_service = make_service_fn(move |_conn| {
		let api_handler = api_handler.clone();
		let foreign_handler = foreign_handler.clone();

		async move {
			Ok::<_, Infallible>(service_fn(move |req| {
				let api_handler = api_handler.clone();
				let foreign_handler = foreign_handler.clone();

				async move {
					if req.uri().path().starts_with("/v3/owner") {
						api_handler.call(req).await
					} else if let Some(fh) = foreign_handler.as_ref() {
						if req.uri().path().starts_with("/v2/foreign") {
							fh.call(req).await
						} else {
							not_found().await
						}
					} else {
						not_found().await
					}
				}
			}))
		}
	});

	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let mut apis = ApiServer::new();
	warn!("Starting HTTP Owner API server at {}.", addr);

	let api_thread = apis
		.start(socket_addr, make_service, tls_config)
		.map_err(|e| Error::GenericError(format!("API server failed to start: {}", e)))?;

	warn!("HTTP Owner listener started.");
	api_thread
		.join()
		.map_err(|e| Error::GenericError(format!("API thread panicked: {:?}", e)))
}

pub fn foreign_listener<L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	addr: &str,
	tls_config: Option<TLSConfig>,
	test_mode: bool,
) -> Result<(), Error>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	let handler = Arc::new(ForeignAPIHandlerV2::new(wallet, keychain_mask, test_mode));

	let make_service = make_service_fn(move |_conn| {
		let handler = handler.clone();
		async move {
			Ok::<_, Infallible>(service_fn(move |req| {
				let handler = handler.clone();
				async move { handler.call(req).await }
			}))
		}
	});

	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let mut apis = ApiServer::new();
	warn!("Starting HTTP Foreign listener API server at {}.", addr);

	let api_thread = apis
		.start(socket_addr, make_service, tls_config)
		.map_err(|e| Error::GenericError(format!("Foreign API failed to start: {}", e)))?;

	warn!("HTTP Foreign listener started.");
	api_thread
		.join()
		.map_err(|e| Error::GenericError(format!("Foreign API thread panicked: {:?}", e)))
}

// ——— V3 Owner API Handler ———
pub struct OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	owner_api: Arc<Owner<L, C, K>>,
	pub shared_key: Arc<Mutex<Option<SecretKey>>>,
	pub keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	pub running_foreign: bool,
}

impl<L, C, K> OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	pub fn new(
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		running_foreign: bool,
	) -> OwnerAPIHandlerV3<L, C, K> {
		let owner_api = Arc::new(Owner::new(wallet.clone(), None));
		OwnerAPIHandlerV3 {
			wallet,
			owner_api,
			shared_key: Arc::new(Mutex::new(None)),
			keychain_mask,
			running_foreign,
		}
	}

	async fn call_api(
		req: Request<Body>,
		_key: Arc<Mutex<Option<SecretKey>>>,
		_mask: Arc<Mutex<Option<SecretKey>>>,
		_running_foreign: bool,
		api: Arc<Owner<L, C, K>>,
	) -> Result<serde_json::Value, Error> {
		let val: serde_json::Value = parse_body(req).await?;

		// Ignore legacy "init_secure_api" calls from old GUIs
		if val.is_init_secure_api() {
			return Ok(serde_json::json!({"result": "ok", "error": null, "id": 1}));
		}

		match <dyn OwnerRpc>::handle_request(&*api, val) {
			MaybeReply::Reply(r) => Ok(r),
			MaybeReply::DontReply => Ok(serde_json::json!([])),
		}
	}

	async fn handle_post_request(
		req: Request<Body>,
		key: Arc<Mutex<Option<SecretKey>>>,
		mask: Arc<Mutex<Option<SecretKey>>>,
		running_foreign: bool,
		api: Arc<Owner<L, C, K>>,
	) -> Result<Response<Body>, Error> {
		let res = Self::call_api(req, key, mask, running_foreign, api).await?;
		Ok(json_response_pretty(&res))
	}
}

#[async_trait::async_trait]
impl<L, C, K> api_common::Handler for OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static + Send + Sync,
	C: NodeClient + 'static + Send + Sync,
	K: Keychain + 'static + Send + Sync,
{
	async fn call(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
		let key = self.shared_key.clone();
		let mask = self.keychain_mask.clone();
		let running_foreign = self.running_foreign;
		let api = self.owner_api.clone();

		match Self::handle_post_request(req, key, mask, running_foreign, api).await {
			Ok(r) => Ok(r),
			Err(e) => {
				error!("Request Error: {e:?}");
				Ok(create_error_response(e))
			}
		}
	}
}

// ——— V2 Foreign API Handler — TOR REMOVED ———
pub struct ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	pub wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	pub keychain_mask: Arc<Mutex<Option<SecretKey>>>,
	pub test_mode: bool,
}

impl<L, C, K> ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	pub fn new(
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		keychain_mask: Arc<Mutex<Option<SecretKey>>>,
		test_mode: bool,
	) -> ForeignAPIHandlerV2<L, C, K> {
		ForeignAPIHandlerV2 {
			wallet,
			keychain_mask,
			test_mode,
		}
	}

	async fn call_api(
		req: Request<Body>,
		api: Foreign<'static, L, C, K>,
	) -> Result<serde_json::Value, Error> {
		let val: serde_json::Value = parse_body(req).await?;
		match <dyn ForeignRpc>::handle_request(&api, val) {
			MaybeReply::Reply(r) => Ok(r),
			MaybeReply::DontReply => Ok(serde_json::json!([])),
		}
	}

	async fn handle_post_request(
		req: Request<Body>,
		mask: Option<SecretKey>,
		wallet: Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
		test_mode: bool,
	) -> Result<Response<Body>, Error> {
		let api = Foreign::new(wallet, mask, Some(check_middleware), test_mode);
		let res = Self::call_api(req, api).await?;
		Ok(json_response_pretty(&res))
	}
}

#[async_trait::async_trait]
impl<L, C, K> api_common::Handler for ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static + Send + Sync,
	C: NodeClient + 'static + Send + Sync,
	K: Keychain + 'static + Send + Sync,
{
	async fn call(&self, req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
		let mask = self.keychain_mask.lock().clone();
		let wallet = self.wallet.clone();
		let test_mode = self.test_mode;

		match Self::handle_post_request(req, mask, wallet, test_mode).await {
			Ok(v) => Ok(v),
			Err(e) => {
				error!("Request Error: {e:?}");
				Ok(create_error_response(e))
			}
		}
	}
}

// ——— Helper functions ———
fn json_response_pretty<T>(s: &T) -> Response<Body>
where
	T: Serialize,
{
	match serde_json::to_string_pretty(s) {
		Ok(json) => response(StatusCode::OK, json),
		Err(_) => response(StatusCode::INTERNAL_SERVER_ERROR, ""),
	}
}

fn create_error_response(e: Error) -> Response<Body> {
	Response::builder()
		.status(StatusCode::INTERNAL_SERVER_ERROR)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.body(format!("{}", e).into())
		.unwrap()
}

fn create_ok_response(json: &str) -> Response<Body> {
	Response::builder()
		.status(StatusCode::OK)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		)
		.header(hyper::header::CONTENT_TYPE, "application/json")
		.body(json.to_string().into())
		.unwrap()
}

fn response<T: Into<Body>>(status: StatusCode, text: T) -> Response<Body> {
	let mut builder = Response::builder()
		.status(status)
		.header("access-control-allow-origin", "*")
		.header(
			"access-control-allow-headers",
			"Content-Type, Authorization",
		);

	if status == StatusCode::OK {
		builder = builder.header(hyper::header::CONTENT_TYPE, "application/json");
	}

	builder.body(text.into()).unwrap()
}

async fn parse_body<T>(req: Request<Body>) -> Result<T, Error>
where
	for<'de> T: Deserialize<'de> + Send + 'static,
{
	let body = body::to_bytes(req.into_body())
		.await
		.map_err(|_| Error::GenericError("Failed to read request".to_string()))?;

	serde_json::from_reader(&body[..])
		.map_err(|e| Error::GenericError(format!("Invalid request body: {}", e)))
}
