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

use noir_runtime_common::units::SECONDS;
use sp_runtime::traits::{ConstBool, ConstU32};

pub const SLOT_DURATION: Moment = 6 * SECONDS;

impl pallet_aura::Config for Runtime {
	type AllowMultipleBlocksPerSlot = ConstBool<false>;
	type AuthorityId = AuraId;
	type DisabledValidators = ();
	type MaxAuthorities = ConstU32<32>;
	type SlotDuration = pallet_aura::MinimumPeriodTimesTwo<Self>;
}
