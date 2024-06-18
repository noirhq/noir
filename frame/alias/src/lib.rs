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

//! # Alias Pallet

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

mod benchmarking;
pub mod generic;
mod mock;
mod tests;
pub mod traits;
pub mod weights;

pub use weights::WeightInfo;

use parity_scale_codec::{FullCodec, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_runtime::BoundedBTreeSet;
use sp_std::fmt::Debug;

#[frame_support::pallet]
pub mod pallet {
	use super::{traits::AliasLinker, *};
	use frame_support::pallet_prelude::*;
	use frame_system::pallet_prelude::*;

	/// The module's config trait.
	#[pallet::config]
	pub trait Config: frame_system::Config {
		/// The overarching event type.
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		/// Alias pointing to an account.
		type Alias: Clone + Debug + FullCodec + MaxEncodedLen + TypeInfo + Ord;

		/// Link and unlink available aliases.
		type AliasLinker: AliasLinker<Self>;

		/// Maximum number of aliases an account can have.
		type MaxAliases: Get<u32>;

		/// Weight information for extrinsics in this pallet.
		type WeightInfo: WeightInfo;
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		AliasLinked { who: T::AccountId, alias: T::Alias },
		AliasUnlinked { alias: T::Alias },
	}

	#[pallet::error]
	pub enum Error<T> {
		/// Linking alias failed.
		LinkFailed,
		/// Unlinking alias failed.
		UnlinkFailed,
	}

	#[pallet::storage]
	pub type AccountIdOf<T: Config> = StorageMap<_, Twox64Concat, T::Alias, T::AccountId>;

	#[pallet::storage]
	pub type AccountAliases<T: Config> =
		StorageMap<_, Twox64Concat, T::AccountId, BoundedBTreeSet<T::Alias, T::MaxAliases>>;

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		#[pallet::call_index(0)]
		#[pallet::weight(T::WeightInfo::link())]
		pub fn link(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			T::AliasLinker::link(&who).map_err(|_| Error::<T>::LinkFailed)?;

			Ok(())
		}

		#[pallet::call_index(1)]
		#[pallet::weight(T::WeightInfo::unlink())]
		pub fn unlink(origin: OriginFor<T>) -> DispatchResult {
			let who = ensure_signed(origin)?;

			T::AliasLinker::unlink(&who).map_err(|_| Error::<T>::UnlinkFailed)?;

			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	/// Lookup an AccountAlias to get an Id, if exists.
	pub fn lookup(alias: &T::Alias) -> Option<T::AccountId> {
		AccountIdOf::<T>::get(alias)
	}
}
