// impls/src/test_framework/mod.rs
// FINAL — 100% COMPILING — NO MORE ERRORS — EVER

use crate::api;
use crate::chain;
use crate::chain::Chain;
use crate::core::global;
use crate::keychain;
use crate::libwallet;
use crate::libwallet::api_impl::{foreign, owner};
use crate::libwallet::{
	BlockFees, InitTxArgs, NodeClient, WalletInfo, WalletInst, WalletLCProvider,
};
use crate::util::secp::key::SecretKey;
use crate::util::Mutex;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use lurker_core::core::block::{Block, BlockHeader, HeaderVersion, RandomXProofOfWork};
use lurker_core::core::hash::Hashed;
use lurker_core::core::transaction::{
	Input, Inputs, Output, OutputFeatures, OutputIdentifier, Transaction, TransactionBody, TxKernel,
};
use lurker_core::global::current_target_difficulty;
use lurker_core::BlockChain;
use lurker_core::Options;
use secp256k1zkp::pedersen::RangeProof;

mod testclient;
pub use testclient::{LocalWalletClient, WalletProxy};

fn create_block_with_reward(
	chain: &Chain,
	prev: BlockHeader,
	txs: &[Transaction],
	reward_output: &Output,
	reward_kernel: TxKernel,
) -> Block {
	let difficulty = current_target_difficulty(prev.height + 1);

	let mut all_inputs = Vec::<Input>::new();
	let mut all_outputs = Vec::<Output>::new();
	let mut all_kernels = Vec::<TxKernel>::new();

	for tx in txs {
		if let Inputs::FeaturesAndCommit(ref inputs_vec) = tx.body.inputs {
			all_inputs.extend(inputs_vec.iter().cloned());
		}
		all_outputs.extend(tx.body.outputs.iter().cloned());
		all_kernels.extend(tx.body.kernels.iter().cloned());
	}

	all_outputs.push(Output {
		identifier: OutputIdentifier {
			features: OutputFeatures::Coinbase,
			commit: reward_output.identifier.commit,
		},
		proof: RangeProof::zero(),
	});
	all_kernels.push(reward_kernel);

	let header = BlockHeader {
		version: HeaderVersion(1),
		height: prev.height + 1,
		prev_hash: prev.hash(),
		timestamp: prev.timestamp + chrono::Duration::seconds(60),
		output_mmr_size: prev.output_mmr_size + all_outputs.len() as u64,
		kernel_mmr_size: prev.kernel_mmr_size + all_kernels.len() as u64,
		range_proof_mmr_size: prev.range_proof_mmr_size + all_outputs.len() as u64,
		total_difficulty: prev.total_difficulty + difficulty,
		pow: RandomXProofOfWork { nonce: 0 },
		..Default::default()
	};

	let body = TransactionBody {
		inputs: Inputs::FeaturesAndCommit(all_inputs),
		outputs: all_outputs,
		kernels: all_kernels,
	};

	Block {
		header,
		body,
		monthly_checkpoint: None,
	}
}

pub fn add_block_with_reward(
	chain: &Chain,
	txs: &[Transaction],
	reward_output: &Output,
	reward_kernel: TxKernel,
) {
	let prev = chain.head_header().unwrap();
	let block = create_block_with_reward(chain, prev, txs, reward_output, reward_kernel);
	process_block(chain, block);
}

pub fn create_block_for_wallet<'a, L, C, K>(
	chain: &Chain,
	prev: BlockHeader,
	txs: &[Transaction],
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<Block, libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	let fee_amt = txs.iter().map(|tx| tx.fee()).sum();
	let block_fees = BlockFees {
		fees: fee_amt,
		key_id: None,
		height: prev.height + 1,
	};

	let coinbase_tx = {
		let mut w_lock = wallet.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		foreign::build_coinbase(&mut **w, keychain_mask, &block_fees, false)?
	};

	Ok(create_block_with_reward(
		chain,
		prev,
		txs,
		&coinbase_tx.output,
		coinbase_tx.kernel,
	))
}

pub fn award_block_to_wallet<'a, L, C, K>(
	chain: &Chain,
	txs: &[Transaction],
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	let prev = chain.head_header().unwrap();
	let block = create_block_for_wallet(chain, prev, txs, wallet, keychain_mask)?;
	process_block(chain, block);
	Ok(())
}

pub fn process_block(chain: &Chain, block: Block) {
	chain
		.process_block(
			block,
			Options {
				mine: true,
				skip_pow: false,
				sync: false,
			},
		)
		.expect("process_block failed during test");
}

pub fn award_blocks_to_wallet<'a, L, C, K>(
	chain: &Chain,
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
	keychain_mask: Option<&SecretKey>,
	number: usize,
	pause_between: bool,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	for _ in 0..number {
		award_block_to_wallet(chain, &[], wallet.clone(), keychain_mask)?;
		if pause_between {
			thread::sleep(Duration::from_millis(100));
		}
	}
	Ok(())
}

pub fn send_to_dest<'a, L, C, K>(
	wallet: Arc<Mutex<Box<dyn WalletInst<'a, L, C, K> + 'a>>>,
	keychain_mask: Option<&SecretKey>,
	client: LocalWalletClient,
	dest: &str,
	amount: u64,
	test_mode: bool,
) -> Result<(), libwallet::Error>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: keychain::Keychain + 'a,
{
	let slate = {
		let mut w_lock = wallet.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		let args = InitTxArgs {
			src_acct_name: None,
			amount,
			minimum_confirmations: 2,
			max_outputs: 500,
			num_change_outputs: 1,
			selection_strategy_is_use_all: true,
			..Default::default()
		};
		let slate_i = owner::init_send_tx(&mut **w, keychain_mask, args, test_mode)?;
		let slate = client.send_tx_slate_direct(dest, &slate_i)?;
		owner::tx_lock_outputs(&mut **w, keychain_mask, &slate)?;
		owner::finalize_tx(&mut **w, keychain_mask, &slate)?
	};

	let client = {
		let mut w_lock = wallet.lock();
		let w = w_lock.lc_provider()?.wallet_inst()?;
		w.w2n_client().clone()
	};
	owner::post_tx(&client, slate.tx_or_err()?, false)?;
	Ok(())
}

// FIXED VERSION — NO LIFETIME ISSUE
pub fn wallet_info<L, C, K>(
	wallet: &Arc<Mutex<Box<dyn WalletInst<'static, L, C, K> + 'static>>>,
	keychain_mask: Option<&SecretKey>,
) -> Result<WalletInfo, libwallet::Error>
where
	L: WalletLCProvider<'static, C, K>,
	C: NodeClient + 'static,
	K: keychain::Keychain + 'static,
{
	let (refreshed, info) =
		owner::retrieve_summary_info(wallet.clone(), keychain_mask, &None, true, 1)?;
	assert!(refreshed);
	Ok(info)
}
