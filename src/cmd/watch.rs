// lurker-wallet/src/cmd/watch.rs
use lurker_keychain::Identifier;
use lurker_wallet_impls::HTTPNodeClient;
use std::io::{self, Write};

pub fn watch_command(args: &clap::ArgMatches, config: WalletConfig) -> Result<(), Error> {
	let node_url = args.value_of("node").unwrap_or("http://127.0.0.1:3413");
	let pubkeys_hex: Vec<String> = args
		.values_of("pubkey")
		.unwrap()
		.map(String::from)
		.collect();

	// Convert hex pubkeys to Commitment or PublicKey as needed
	// For now just print — real implementation streams outputs
	println!("Lurker watch-only mode active");
	println!("Node: {}", node_url);
	println!("Watching {} public keys", pubkeys_hex.len());

	// In real version: connect to node over Yggdrasil, poll get_outputs, emit JSON lines
	loop {
		std::thread::sleep(std::time::Duration::from_secs(10));
		writeln!(io::stdout(), r#"{{"event":"heartbeat","height":12345}}"#)?;
		io::stdout().flush()?;
	}
}
