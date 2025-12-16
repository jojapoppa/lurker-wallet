// controller/src/error.rs
// Copyright 2021 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Implementation specific error types
use crate::core::core::transaction;
use crate::core::libtx;
use crate::impls;
use crate::keychain;
use crate::libwallet;

use api_common::types::Error as ApiError;

/// Wallet errors, mostly wrappers around underlying crypto or I/O errors.
#[derive(Clone, Eq, PartialEq, Debug, thiserror::Error)]
pub enum ControllerError {
	#[error("Generic error: {0}")]
	GenericError(String),

	#[error("LibTx Error")]
	LibTX(#[from] libtx::Error),

	#[error("Impls Error")]
	Impls(#[from] impls::Error),

	#[error("LibWallet Error: {0}")]
	LibWallet(libwallet::Error),

	#[error("Keychain error")]
	Keychain(#[from] keychain::Error),

	#[error("Payment Proof parsing error: {0}")]
	PaymentProofParsing(String),

	#[error("IO error: {0}")]
	IO(String),

	#[error("Transaction error")]
	Transaction(#[from] transaction::Error),

	#[error("Secp error")]
	Secp,

	#[error("Wallet data error: {0}")]
	FileWallet(&'static str),

	#[error("Serde JSON error")]
	Format,

	#[error("Node API error")]
	Node(#[from] ApiError),

	#[error("Hyper error")]
	Hyper,

	#[error("Uri parsing error")]
	Uri,

	#[error("Duplicate transaction ID error")]
	DuplicateTransactionId,

	#[error("Wallet seed file exists: {0}")]
	WalletSeedExists(String),

	#[error("Wallet seed doesn't exist error")]
	WalletSeedDoesntExist,

	#[error("Enc/Decryption error (check password?)")]
	Encryption,

	#[error("BIP39 Mnemonic (word list) Error")]
	Mnemonic,

	#[error("{0}")]
	ArgumentError(String),

	#[error("Listener Startup Error")]
	ListenerError,
}

impl From<std::io::Error> for ControllerError {
	fn from(e: std::io::Error) -> Self {
		ControllerError::IO(e.to_string())
	}
}

impl From<ControllerError> for lurker_wallet_libwallet::Error {
	fn from(e: ControllerError) -> Self {
		lurker_wallet_libwallet::Error::GenericError(e.to_string())
	}
}
