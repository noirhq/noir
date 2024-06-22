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

use frame::support::weights::{
	constants::ExtrinsicBaseWeight, ConstantMultiplier, WeightToFeeCoefficient,
	WeightToFeeCoefficients, WeightToFeePolynomial,
};
use noir_core_primitives::units::CENTS;
use pallet::transaction_payment::{FungibleAdapter, Multiplier, TargetedFeeAdjustment};
use primitives::runtime::{traits::Bounded, FixedPointNumber, Perbill, Perquintill};
use smallvec::smallvec;

parameter_types! {
	pub const OperationalFeeMultiplier: u8 = 5;
	pub const TransactionByteFee: Balance = (1 * CENTS) / 100;

	pub const TargetBlockFullness: Perquintill = Perquintill::from_percent(25);
	pub AdjustmentVariable: Multiplier = Multiplier::saturating_from_rational(75, 1_000_000);
	pub MinimumMultiplier: Multiplier = Multiplier::saturating_from_rational(1, 10u128);
	pub MaximumMultiplier: Multiplier = Bounded::max_value();
}

pub type SlowAdjustingFeeUpdate<R> = TargetedFeeAdjustment<
	R,
	TargetBlockFullness,
	AdjustmentVariable,
	MinimumMultiplier,
	MaximumMultiplier,
>;

pub struct WeightToFee;

impl WeightToFeePolynomial for WeightToFee {
	type Balance = Balance;
	fn polynomial() -> WeightToFeeCoefficients<Balance> {
		let p = 1 * CENTS;
		let q = 10 * Balance::from(ExtrinsicBaseWeight::get().ref_time());
		smallvec![WeightToFeeCoefficient {
			coeff_integer: p / q,
			coeff_frac: Perbill::from_rational(p % q, q),
			negative: false,
			degree: 1,
		}]
	}
}

impl pallet::transaction_payment::Config for Runtime {
	type FeeMultiplierUpdate = SlowAdjustingFeeUpdate<Self>;
	type LengthToFee = ConstantMultiplier<Balance, TransactionByteFee>;
	type OnChargeTransaction = FungibleAdapter<Balances, () /* TODO: DealWithFees */>;
	type OperationalFeeMultiplier = OperationalFeeMultiplier;
	type RuntimeEvent = RuntimeEvent;
	type WeightToFee = WeightToFee;
}
