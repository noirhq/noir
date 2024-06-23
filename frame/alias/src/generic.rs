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

//! Generic implementations for aliasing an account.

use super::*;
use frame_support::ensure;
use np_core::{CosmosAddress, EthereumAddress};
use np_runtime::{traits::Property, AccountId32, Multikey};
use parity_scale_codec::{Decode, Encode, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_std::{collections::btree_set::BTreeSet, fmt::Debug};

/// Generic implementation of an account alias.
#[non_exhaustive]
#[cfg_attr(feature = "std", derive(Hash))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub enum AccountAlias {
	Ethereum(EthereumAddress),
	Cosmos(CosmosAddress),
}

impl<T> traits::AliasLinker<T> for AccountAlias
where
	T: frame_system::Config<AccountId = AccountId32> + pallet::Config<Alias = Self>,
{
	type Error = ();

	fn link(who: &AccountId32) -> Result<(), Self::Error> {
		let public = who.get().clone().ok_or(())?;

		if let Multikey::Secp256k1(public) = public {
			let mut aliases = BTreeSet::new();
			// Ethereum address
			let eth = AccountAlias::Ethereum(public.into());
			let _ = AccountIdOf::<T>::try_mutate(&eth, |account_id| -> Result<_, ()> {
				ensure!(account_id.is_none(), ());
				*account_id = Some(who.clone());
				Pallet::<T>::deposit_event(Event::AliasLinked {
					who: who.clone(),
					alias: eth.clone(),
				});
				Ok(())
			});
			aliases.insert(eth.clone());
			// Cosmos address
			let cosm = AccountAlias::Cosmos(public.into());
			let _ = AccountIdOf::<T>::try_mutate(&cosm, |account_id| -> Result<_, ()> {
				ensure!(account_id.is_none(), ());
				*account_id = Some(who.clone());
				Pallet::<T>::deposit_event(Event::AliasLinked {
					who: who.clone(),
					alias: cosm.clone(),
				});
				Ok(())
			});
			aliases.insert(cosm.clone());
			// Backlinks
			AccountAliases::<T>::insert(who, BoundedBTreeSet::try_from(aliases)?);
		}
		Ok(())
	}

	fn unlink(who: &AccountId32) -> Result<(), Self::Error> {
		let _ = AccountAliases::<T>::try_mutate(who, |aliases| aliases.take().ok_or(())).map(
			|aliases| {
				for alias in aliases {
					AccountIdOf::<T>::remove(alias.clone());
					Pallet::<T>::deposit_event(Event::AliasUnlinked { alias });
				}
			},
		);
		Ok(())
	}
}

#[cfg(any(test, feature = "runtime-benchmarks"))]
pub mod tests {
	use super::*;
	use np_core::ethereum::EthereumBip44;

	pub fn account() -> (AccountId32, AccountAlias, AccountAlias) {
		let public = EthereumBip44::default().public(0);
		let caller: AccountId32 = public.into();
		let eth = AccountAlias::Ethereum(public.into());
		let cosm = AccountAlias::Cosmos(public.into());
		(caller, eth, cosm)
	}
}
