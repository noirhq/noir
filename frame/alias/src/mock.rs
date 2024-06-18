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

#![cfg(test)]

use super::{generic::AccountAlias, pallet as pallet_alias};
use frame_support::{derive_impl, traits::ConstU32};
use frame_system::{config_preludes::TestDefaultConfig, DefaultConfig};
use np_runtime::AccountId32;
use sp_io::TestExternalities;
use sp_runtime::{traits::IdentityLookup, BuildStorage};

#[frame_support::runtime]
mod runtime {
	#[runtime::runtime]
	#[runtime::derive(RuntimeCall, RuntimeEvent, RuntimeError, RuntimeOrigin, RuntimeTask)]
	pub struct Test;

	#[runtime::pallet_index(0)]
	pub type System = frame_system;

	#[runtime::pallet_index(1)]
	pub type Alias = pallet_alias;
}

type Block = frame_system::mocking::MockBlock<Test>;
pub type AccountId = AccountId32;

#[derive_impl(TestDefaultConfig as DefaultConfig)]
impl frame_system::Config for Test {
	type Block = Block;
	type AccountId = AccountId;
	type Lookup = IdentityLookup<Self::AccountId>;
}

impl pallet_alias::Config for Test {
	type RuntimeEvent = RuntimeEvent;
	type Alias = AccountAlias;
	type AliasLinker = AccountAlias;
	type MaxAliases = ConstU32<2>;
	type WeightInfo = ();
}

pub fn new_test_ext() -> TestExternalities {
	let t = frame_system::GenesisConfig::<Test>::default().build_storage().unwrap();
	TestExternalities::new(t)
}
