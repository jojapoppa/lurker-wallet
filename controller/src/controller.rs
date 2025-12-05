// controller/src/controller.rs

use crate::api::{ApiServer, BasicAuthMiddleware, TLSConfig};

use crate::api;
use hyper::body;
use hyper::header::HeaderValue;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, StatusCode};
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::keychain::Keychain;
use crate::libwallet::{
	Error, NodeClient, NodeVersionInfo, Slate, SlatepackAddress, WalletInst, WalletLCProvider,
	GRIN_BLOCK_HEADER_VERSION,
};
use lurker_api::Handler;

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
use easy_jsonrpc_mw::MaybeReply;

use hyper::Error as HyperError;
type ResponseFuture = Pin<Box<dyn Future<Output = Result<Response<Body>, HyperError>> + Send>>;

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
	let mut router = Router::new();
	if let Some(ref secret) = api_secret {
		let api_basic_auth = "Basic ".to_string() + &to_base64(&("grin:".to_string() + secret));
		let basic_auth_middleware = Arc::new(BasicAuthMiddleware::new(
			api_basic_auth,
			&GRIN_OWNER_BASIC_REALM,
			Some("/v2/foreign".into()),
		));
		router.add_middleware(basic_auth_middleware);
	}

	let running_foreign = owner_api_include_foreign.unwrap_or(false);

	let api_handler_v3 =
		OwnerAPIHandlerV3::new(wallet.clone(), keychain_mask.clone(), running_foreign);

	router
		.add_route("/v3/owner", Arc::new(api_handler_v3))
		.map_err(|_| Error::GenericError("Router failed to add route".to_string()))?;

	if running_foreign {
		warn!("Starting HTTP Foreign API on Owner server at {}.", addr);
		let foreign_api_handler_v2 = ForeignAPIHandlerV2::new(wallet, keychain_mask, test_mode);
		router
			.add_route("/v2/foreign", Arc::new(foreign_api_handler_v2))
			.map_err(|_| Error::GenericError("Router failed to add route".to_string()))?;
	}

	let api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>) =
		Box::leak(Box::new(oneshot::channel()));

	let mut apis = ApiServer::new();
	warn!("Starting HTTP Owner API server at {}.", addr);
	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let api_thread = apis
		.start(socket_addr, router, tls_config, api_chan)
		.map_err(|_| Error::GenericError("API thread failed to start".to_string()))?;

	warn!("HTTP Owner listener started.");
	api_thread
		.join()
		.map_err(|e| Error::GenericError(format!("API thread panicked: {:?}", e)))
}

/// Foreign API listener — TOR REMOVED
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
	let api_handler_v2 = ForeignAPIHandlerV2::new(wallet.clone(), keychain_mask, test_mode);
	let mut router = Router::new();

	router
		.add_route("/v2/foreign", Arc::new(api_handler_v2))
		.map_err(|_| Error::GenericError("Router failed to add route".to_string()))?;

	let api_chan: &'static mut (oneshot::Sender<()>, oneshot::Receiver<()>) =
		Box::leak(Box::new(oneshot::channel()));

	let mut apis = ApiServer::new();
	warn!("Starting HTTP Foreign listener API server at {}.", addr);
	let socket_addr: SocketAddr = addr.parse().expect("unable to parse socket address");
	let api_thread = apis
		.start(socket_addr, router, tls_config, api_chan)
		.map_err(|_| Error::GenericError("API thread failed to start".to_string()))?;

	warn!("HTTP Foreign listener started.");
	api_thread
		.join()
		.map_err(|e| Error::GenericError(format!("API thread panicked: {:?}", e)))
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
		key: Arc<Mutex<Option<SecretKey>>>,
		mask: Arc<Mutex<Option<SecretKey>>>,
		running_foreign: bool,
		api: Arc<Owner<L, C, K>>,
	) -> Result<serde_json::Value, Error> {
		let mut val: serde_json::Value = parse_body(req).await?;
		let mut is_init_secure_api = OwnerV3Helpers::is_init_secure_api(&val);
		let mut was_encrypted = false;
		let mut encrypted_req_id = JsonId::StrId(String::from(""));

		if !is_init_secure_api {
			if let Err(v) = OwnerV3Helpers::check_encryption_started(key.clone()) {
				return Ok(v);
			}
			let res = OwnerV3Helpers::decrypt_request(key.clone(), &val);
			match res {
				Err(e) => return Ok(e),
				Ok(v) => {
					encrypted_req_id = v.0.clone();
					val = v.1;
				}
			}
			was_encrypted = true;
		}

		is_init_secure_api = OwnerV3Helpers::is_init_secure_api(&val);
		let is_open_wallet = OwnerV3Helpers::is_open_wallet(&val);

		match <dyn OwnerRpc>::handle_request(&*api, val) {
			MaybeReply::Reply(mut r) => {
				let (_was_error, unencrypted_intercept) =
					OwnerV3Helpers::check_error_response(&r.clone());
				if is_open_wallet && running_foreign {
					OwnerV3Helpers::update_mask(mask, &r.clone());
				}
				if was_encrypted {
					let res = OwnerV3Helpers::encrypt_response(
						key.clone(),
						&encrypted_req_id,
						&unencrypted_intercept,
					);
					r = match res {
						Ok(v) => v,
						Err(v) => return Ok(v),
					}
				}
				if is_init_secure_api {
					OwnerV3Helpers::update_owner_api_shared_key(
						key.clone(),
						&unencrypted_intercept,
						api.shared_key.lock().clone(),
					);
				}
				Ok(r)
			}
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

impl<L, C, K> api::Handler for OwnerAPIHandlerV3<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		let key = self.shared_key.clone();
		let mask = self.keychain_mask.clone();
		let running_foreign = self.running_foreign;
		let api = self.owner_api.clone();

		Box::pin(async move {
			match Self::handle_post_request(req, key, mask, running_foreign, api).await {
				Ok(r) => Ok(r),
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Body>) -> ResponseFuture {
		Box::pin(async { Ok(create_ok_response("{}")) })
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

impl<L, C, K> api::Handler for ForeignAPIHandlerV2<L, C, K>
where
	L: WalletLCProvider<'static, C, K> + 'static,
	C: NodeClient + 'static,
	K: Keychain + 'static,
{
	fn post(&self, req: Request<Body>) -> ResponseFuture {
		let mask = self.keychain_mask.lock().clone();
		let wallet = self.wallet.clone();
		let test_mode = self.test_mode;

		Box::pin(async move {
			match Self::handle_post_request(req, mask, wallet, test_mode).await {
				Ok(v) => Ok(v),
				Err(e) => {
					error!("Request Error: {:?}", e);
					Ok(create_error_response(e))
				}
			}
		})
	}

	fn options(&self, _req: Request<Body>) -> ResponseFuture {
		Box::pin(async { Ok(create_ok_response("{}")) })
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
