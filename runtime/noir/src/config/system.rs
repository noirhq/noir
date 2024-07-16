// This file is part of Noir.

// Copyright (C) Haderech Pte. Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use crate::*;

use frame::{
	support::{
		derive_impl,
		dispatch::DispatchClass,
		traits::ConstU32,
		weights::constants::{
			BlockExecutionWeight, ExtrinsicBaseWeight, RocksDbWeight, WEIGHT_REF_TIME_PER_SECOND,
		},
	},
	system::{config_preludes::SolochainDefaultConfig, limits},
};
use noir_runtime_common::{constants::SS58_PREFIX, units::MiB};
use primitives::runtime::{traits::AccountIdLookup, Perbill};

pub const AVERAGE_ON_INITIALIZE_RATIO: Perbill = Perbill::from_percent(1);
pub const NORMAL_DISPATCH_RATIO: Perbill = Perbill::from_percent(75);
pub const MAXIMUM_BLOCK_WEIGHT: Weight =
	Weight::from_parts(WEIGHT_REF_TIME_PER_SECOND.saturating_mul(2), u64::MAX);

parameter_types! {
	pub const BlockHashCount: u32 = 4096;
	pub BlockLength: limits::BlockLength = limits::BlockLength
		::max_with_normal_ratio(5 * MiB, NORMAL_DISPATCH_RATIO);
	pub BlockWeights: limits::BlockWeights = limits::BlockWeights::builder()
		.base_block(BlockExecutionWeight::get())
		.for_class(DispatchClass::all(), |weights| {
			weights.base_extrinsic = ExtrinsicBaseWeight::get();
		})
		.for_class(DispatchClass::Normal, |weights| {
			weights.max_total = Some(NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT);
		})
		.for_class(DispatchClass::Operational, |weights| {
			weights.max_total = Some(MAXIMUM_BLOCK_WEIGHT);
			weights.reserved = Some(
				MAXIMUM_BLOCK_WEIGHT - NORMAL_DISPATCH_RATIO * MAXIMUM_BLOCK_WEIGHT,
			);
		})
		.avg_block_initialization(AVERAGE_ON_INITIALIZE_RATIO)
		.build_or_panic();
	pub const SS58Prefix: u16 = SS58_PREFIX;
	pub const Version: RuntimeVersion = VERSION;
}

#[derive_impl(SolochainDefaultConfig as frame::system::DefaultConfig)]
impl frame::system::Config for Runtime {
	type AccountData = pallet::balances::AccountData<Balance>;
	type AccountId = AccountId;
	type Block = Block;
	type BlockHashCount = BlockHashCount;
	type BlockLength = BlockLength;
	type BlockWeights = BlockWeights;
	type DbWeight = RocksDbWeight;
	type Hash = Hash;
	type Lookup = AccountIdLookup<AccountId, AccountIndex>;
	type MaxConsumers = ConstU32<16>;
	type Nonce = AccountNonce;
	type SS58Prefix = SS58Prefix;
	type Version = Version;
}
