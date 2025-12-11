// lurker-wallet/impls/src/client_utils/client.rs
// LURKER — Minimal HTTP client, no TLS, no SOCKS, no legacy junk

use crate::error::Error;
use reqwest::blocking::Client;
use serde::{de::DeserializeOwned, Serialize};

/// Single, simple blocking POST — this is all we need
pub fn post<R: Serialize, T: DeserializeOwned>(
	url: &str,
	api_secret: Option<&str>,
	request: &R,
) -> Result<T, Error> {
	let client = Client::new();

	let mut req = client.post(url).json(request);

	if let Some(secret) = api_secret {
		req = req.basic_auth("grin", Some(secret));
	}

	let resp = req.send().map_err(|e| Error::Http(e.to_string()))?;
	let text = resp.text().map_err(|e| Error::Http(e.to_string()))?;

	serde_json::from_str(&text).map_err(|e| Error::Parse(e.to_string()))
}
