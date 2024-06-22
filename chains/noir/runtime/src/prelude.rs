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

use noir_core_primitives::{AccountIndex, BlakeTwo256, BlockNumber, Signature};
use primitives::runtime::{generic, impl_opaque_keys, MultiAddress};

pub type Address = MultiAddress<AccountId, AccountIndex>;

pub type Block = generic::Block<Header, UncheckedExtrinsic>;

pub type Executive = frame::executive::Executive<
	Runtime,
	Block,
	frame::system::ChainContext<Runtime>,
	Runtime,
	AllPalletsWithSystem,
	Migrations,
>;

pub type Header = generic::Header<BlockNumber, BlakeTwo256>;

pub type Migrations = ();

pub type SignedExtra = (
	frame::system::CheckNonZeroSender<Runtime>,
	frame::system::CheckSpecVersion<Runtime>,
	frame::system::CheckTxVersion<Runtime>,
	frame::system::CheckGenesis<Runtime>,
	frame::system::CheckMortality<Runtime>,
	frame::system::CheckNonce<Runtime>,
	frame::system::CheckWeight<Runtime>,
	pallet::transaction_payment::ChargeTransactionPayment<Runtime>,
);

pub type SignedPayload = generic::SignedPayload<RuntimeCall, SignedExtra>;

pub type UncheckedExtrinsic =
	generic::UncheckedExtrinsic<Address, RuntimeCall, Signature, SignedExtra>;

pub use frame::system::Call as SystemCall;
pub use pallet::balances::Call as BalancesCall;

pub mod opaque {
	use super::*;

	impl_opaque_keys! {
		pub struct SessionKeys {
			pub aura: Aura,
			pub grandpa: Grandpa,
		}
	}
}
