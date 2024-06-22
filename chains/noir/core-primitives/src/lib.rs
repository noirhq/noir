// This file is part of Noir.

// Copyright (C) Haderech Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#![allow(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use np_runtime::{
	traits::{IdentifyAccount, VerifyMut},
	AuthorizationProof,
};

pub use np_runtime::sp_runtime::traits::BlakeTwo256;
pub use sp_core::{Bytes, H256, U256};

pub type AccountId = <AccountPublic as IdentifyAccount>::AccountId;
pub type AccountIndex = ();
pub type AccountNonce = u32;
pub type AccountPublic = <Signature as VerifyMut>::Signer;
pub type Balance = u128;
pub type BlockNumber = u32;
pub type Hash = H256;
pub type Moment = u64;
pub type Signature = AuthorizationProof;

pub mod opaque {
	use super::*;
	use np_runtime::sp_runtime::{generic, OpaqueExtrinsic};

	pub type Block = generic::Block<Header, UncheckedExtrinsic>;
	pub type BlockId = generic::BlockId<Block>;
	pub type Header = generic::Header<BlockNumber, BlakeTwo256>;
	pub type UncheckedExtrinsic = OpaqueExtrinsic;
}

#[allow(non_upper_case_globals)]
pub mod units {
	use super::*;

	/// A unit of base currency.
	pub const DOLLARS: Balance = 1_000_000_000_000_000_000;
	/// One hundredth of a dollar.
	pub const CENTS: Balance = DOLLARS / 100;

	/// Kibibytes.
	pub const KiB: u32 = 1024;
	/// Mebibytes.
	pub const MiB: u32 = 1024 * KiB;

	/// A second in milliseconds.
	pub const SECONDS: Moment = 1000;
	/// A millisecond.
	pub const MILLISECONDS: Moment = 1;
}

pub mod constants {
	pub const SS58_PREFIX: u16 = 42;
}
