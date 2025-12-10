// lib.rs — exposed via UniFFI
#[uniffi::export]
pub fn send_lurker(
	node_url: String,   // e.g. "tcp://[200:1234::1]:3413"
	seed_hex: String,   // 32-byte master seed
	to_address: String, // user's slatepack or public key
	amount_nano: u64,
	fee_nano: u64,
) -> Result<String, String> {
	// returns tx hash or error
	let tx = build_and_sign_tx(seed_hex, to_address, amount_nano, fee_nano)?;
	let client = HTTPNodeClient::new(&node_url, None);
	client.post_tx(&tx, true).map_err(|e| e.to_string())?;
	Ok(tx.hash().to_hex())
}
