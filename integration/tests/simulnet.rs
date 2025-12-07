// integration/tests/simulnet.rs
// Lurker — Dandelion removed forever. Yggdrasil + RandomX = true privacy.

extern crate lurker_apiwallet as apiwallet;
extern crate lurker_libwallet as libwallet;
extern crate lurker_refwallet as wallet;
extern crate lurker_wallet_config as wallet_config;
#[macro_use]
extern crate log;

mod framework;

use self::core::core::hash::Hashed;
use self::core::global::{self, ChainTypes};
use self::libwallet::types::{WalletBackend, WalletInst};
use self::util::{Mutex, StopState};
use self::wallet::controller;
use self::wallet::lmdb_wallet::LMDBBackend;
use self::wallet::{HTTPNodeClient, HTTPWalletCommAdapter};
use self::wallet_config::WalletConfig;
use lurker_api as api;
use lurker_core as core;
use lurker_keychain as keychain;
use lurker_p2p as p2p;
use lurker_servers as servers;
use lurker_util as util;
use p2p::PeerAddr;
use std::cmp;
use std::process::exit;
use std::sync::Arc;
use std::{thread, time};

use crate::framework::{
	config, stop_all_servers, LocalServerContainerConfig, LocalServerContainerPool,
	LocalServerContainerPoolConfig,
};

/// Basic genesis mining test
#[test]
fn basic_genesis_mine() {
	util::init_test_logger();
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

	let test_name_dir = "genesis_mine";
	framework::clean_all_output(test_name_dir);

	let mut pool_config = LocalServerContainerPoolConfig::default();
	pool_config.base_name = test_name_dir.to_string();
	pool_config.run_length_in_seconds = 10;
	pool_config.base_api_port = 30000;
	pool_config.base_p2p_port = 31000;
	pool_config.base_wallet_port = 32000;

	let mut pool = LocalServerContainerPool::new(pool_config);

	let mut server_config = LocalServerContainerConfig::default();
	server_config.start_miner = true;
	server_config.start_wallet = false;
	server_config.burn_mining_rewards = true;

	pool.create_server(&mut server_config);
	let servers = pool.run_all_servers();
	stop_all_servers(servers);
}

/// Simulate network seeding
#[test]
fn simulate_seeding() {
	util::init_test_logger();
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

	let test_name_dir = "simulate_seeding";
	framework::clean_all_output(test_name_dir);

	let mut pool_config = LocalServerContainerPoolConfig::default();
	pool_config.base_name = test_name_dir.to_string();
	pool_config.run_length_in_seconds = 30;
	pool_config.base_api_port = 30020;
	pool_config.base_p2p_port = 31020;
	pool_config.base_wallet_port = 32020;

	let mut pool = LocalServerContainerPool::new(pool_config);

	let mut server_config = LocalServerContainerConfig::default();
	server_config.start_wallet = false;
	server_config.burn_mining_rewards = true;
	server_config.is_seeding = true;

	pool.create_server(&mut server_config);

	thread::sleep(time::Duration::from_millis(1_000));

	server_config.is_seeding = false;
	server_config.seed_addr = format!(
		"{}:{}",
		server_config.base_addr, server_config.p2p_server_port
	);

	for _ in 0..4 {
		pool.create_server(&mut server_config);
	}

	let servers = pool.run_all_servers();
	thread::sleep(time::Duration::from_secs(5));

	let url = format!(
		"http://{}:{}/v1/peers/connected",
		&server_config.base_addr, 30020
	);
	let peers_all = api::client::get::<Vec<p2p::types::PeerInfoDisplay>>(url.as_str(), None);
	assert!(peers_all.is_ok());
	assert_eq!(peers_all.unwrap().len(), 4);

	stop_all_servers(servers);
	thread::sleep(time::Duration::from_millis(1_000));
}

/// Simulate block propagation across the network
#[test]
fn simulate_block_propagation() {
	util::init_test_logger();
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

	let test_name_dir = "grin-prop";
	framework::clean_all_output(test_name_dir);

	let mut servers = vec![];
	for n in 0..5 {
		let s = servers::Server::new(framework::config(10 * n, test_name_dir, 0)).unwrap();
		servers.push(s);
		thread::sleep(time::Duration::from_millis(100));
	}

	let stop = Arc::new(Mutex::new(StopState::new()));
	servers[0].start_test_miner(None, stop.clone());

	let mut success = false;
	let mut time_spent = 0;
	loop {
		let mut count = 0;
		for n in 0..5 {
			if servers[n].head().height > 3 {
				count += 1;
			}
		}
		if count == 5 {
			success = true;
			break;
		}
		thread::sleep(time::Duration::from_millis(1_000));
		time_spent += 1;
		if time_spent >= 30 {
			break;
		}
		if time_spent == 8 {
			servers[0].stop_test_miner(stop.clone());
		}
	}

	for n in 0..5 {
		servers[n].stop();
	}
	assert!(success);
	thread::sleep(time::Duration::from_millis(1_000));
}

/// Full sync test (header + body sync)
#[test]
fn simulate_full_sync() {
	util::init_test_logger();
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

	let test_name_dir = "grin-sync";
	framework::clean_all_output(test_name_dir);

	let s1 = servers::Server::new(framework::config(1000, "grin-sync", 1000)).unwrap();
	let stop = Arc::new(Mutex::new(StopState::new()));
	s1.start_test_miner(None, stop.clone());
	thread::sleep(time::Duration::from_secs(8));
	s1.stop_test_miner(stop);

	let s2 = servers::Server::new(framework::config(1001, "grin-sync", 1000)).unwrap();

	let s1_header = s1.chain.head_header().unwrap();

	let mut time_spent = 0;
	while s2.head().height < s1_header.height {
		thread::sleep(time::Duration::from_millis(1_000));
		time_spent += 1;
		if time_spent >= 30 {
			break;
		}
	}

	let s2_header = s2.chain.get_block_header(&s1_header.hash()).unwrap();
	assert_eq!(s1_header, s2_header);

	s1.stop();
	s2.stop();
	thread::sleep(time::Duration::from_millis(1_000));
}

/// Fast sync test (embedded archives)
#[test]
fn simulate_fast_sync() {
	util::init_test_logger();
	global::set_local_chain_type(ChainTypes::AutomatedTesting);

	let test_name_dir = "grin-fast";
	framework::clean_all_output(test_name_dir);

	let s1 = servers::Server::new(framework::config(2000, "grin-fast", 2000)).unwrap();
	let stop = Arc::new(Mutex::new(StopState::new()));
	s1.start_test_miner(None, stop.clone());

	while s1.head().height < 20 {
		thread::sleep(time::Duration::from_millis(1_000));
	}
	s1.stop_test_miner(stop);

	let mut conf = config(2001, "grin-fast", 2000);
	conf.archive_mode = Some(false);
	let s2 = servers::Server::new(conf).unwrap();

	let s1_header = s1.chain.head_header().unwrap();

	let mut total_wait = 0;
	while s2.head().height < s1_header.height {
		thread::sleep(time::Duration::from_millis(1_000));
		total_wait += 1;
		if total_wait >= 30 {
			break;
		}
	}

	let s2_header = s2.chain.get_block_header(&s1_header.hash()).unwrap();
	assert_eq!(s1_header, s2_header);

	s1.stop();
	s2.stop();
	thread::sleep(time::Duration::from_millis(1_000));
}

// The rest (long_fork, replicate_tx_fluff_failure, etc.) are either ignored or dead
// Dandelion is gone — no need to test it
