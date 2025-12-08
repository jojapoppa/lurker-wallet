// lurker-wallet/src/foreign_rpc_impl.rs
// LURKER — NODE IMPLEMENTATION OF FOREIGN RPC

use crate::foreign::Foreign;
use api_common::ForeignRpc;

impl<'a, L, C, K> ForeignRpc for Foreign<'a, L, C, K>
where
	L: WalletLCProvider<'a, C, K>,
	C: NodeClient + 'a,
	K: Keychain + 'a,
{
	fn check_version(&self) -> Result<VersionInfo, Error> {
		Foreign::check_version(self)
	}

	fn build_coinbase(&self, block_fees: &BlockFees) -> Result<VersionedCoinbase, Error> {
		let cb: CbData = Foreign::build_coinbase(self, block_fees)?;
		Ok(VersionedCoinbase::into_version(cb, SlateVersion::V4))
	}

	fn receive_tx(
		&self,
		in_slate: VersionedSlate,
		dest_acct_name: Option<String>,
		dest: Option<String>,
	) -> Result<VersionedSlate, Error> {
		let version = in_slate.version();
		let slate_from = Slate::from(in_slate);
		let out_slate = Foreign::receive_tx(
			self,
			&slate_from,
			dest_acct_name.as_ref().map(String::as_str),
			dest,
		)?;
		Ok(VersionedSlate::into_version(out_slate, version)?)
	}

	fn finalize_tx(&self, in_slate: VersionedSlate) -> Result<VersionedSlate, Error> {
		let version = in_slate.version();
		let out_slate = Foreign::finalize_tx(self, &Slate::from(in_slate), true)?;
		Ok(VersionedSlate::into_version(out_slate, version)?)
	}
}
