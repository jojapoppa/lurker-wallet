pub use lurker_wallet_libwallet::NodeClient;

pub struct Payment {
	pub commit: String,
	pub amount: u64,
	pub height: u64,
}

pub struct LurkerWatcher {
	client: Box<dyn NodeClient>,
	pubkeys: Vec<String>,
}

impl LurkerWatcher {
	pub fn new(node_url: &str, pubkeys: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
		let client = HTTPNodeClient::new(node_url, None);
		Ok(Self {
			client: Box::new(client),
			pubkeys,
		})
	}

	pub fn stream_payments(&self) -> impl Iterator<Item = Payment> {
		// Real impl: poll get_outputs, emit new payments
		std::iter::empty()
	}
}
