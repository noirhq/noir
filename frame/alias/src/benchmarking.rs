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

#![cfg(feature = "runtime-benchmarks")]

use super::{generic::tests::dev_key, Pallet as Alias, *};
use frame_benchmarking::v2::*;
use frame_support::assert_ok;
use frame_system::RawOrigin;
use sp_core::ecdsa;
use sp_std::prelude::*;

#[benchmarks(
	where
		T::AccountId: From<ecdsa::Public>,
)]
mod benchmarks {
	use super::*;

	#[benchmark]
	fn link() -> Result<(), BenchmarkError> {
		let caller: T::AccountId = dev_key().into();
		whitelist_account!(caller);

		#[extrinsic_call]
		_(RawOrigin::Signed(caller));

		Ok(())
	}

	#[benchmark]
	fn unlink() -> Result<(), BenchmarkError> {
		let caller: T::AccountId = dev_key().into();
		whitelist_account!(caller);
		assert_ok!(Alias::<T>::link(RawOrigin::Signed(caller.clone()).into()));

		#[extrinsic_call]
		_(RawOrigin::Signed(caller));

		Ok(())
	}

	impl_benchmark_test_suite!(Alias, crate::mock::new_test_ext(), crate::mock::Test);
}
