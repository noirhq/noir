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

pub mod frame {
	pub use frame_executive as executive;
	pub use frame_support as support;
	pub use frame_system as system;
}

pub mod pallet {
	pub use pallet_aura as aura;
	pub use pallet_balances as balances;
	pub use pallet_grandpa as grandpa;
	pub use pallet_sudo as sudo;
	pub use pallet_timestamp as timestamp;
	pub use pallet_transaction_payment as transaction_payment;
}

pub mod primitives {
	pub use sp_api as api;
	pub mod consensus {
		pub use sp_consensus_aura as aura;
	}
	pub use sp_core as core;
	pub use sp_runtime as runtime;
	pub use sp_std as std;
	pub use sp_version as version;
}

pub use frame_support::parameter_types;
