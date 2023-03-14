// This file is part of Noir.

// Copyright (C) 2023 Haderech Pte. Ltd.
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

//! Adapter types for EVM pallet compatibility.

use frame_support::{crypto::ecdsa::ECDSAExt, dispatch::RawOrigin};
use np_crypto::ecdsa::EcdsaExt;
use pallet_account_alias_registry::AccountAlias;
use pallet_evm::{AddressMapping, EnsureAddressOrigin};
use sp_core::{ecdsa, Hasher, H160, H256};
use sp_std::marker::PhantomData;

/// Ensure that the address is truncated hash of the origin.
pub struct EnsureAddressHashed<AccountId>(PhantomData<AccountId>);

impl<OuterOrigin, AccountId> EnsureAddressOrigin<OuterOrigin> for EnsureAddressHashed<AccountId>
where
	OuterOrigin: Into<Result<RawOrigin<AccountId>, OuterOrigin>> + From<RawOrigin<AccountId>>,
	AccountId: TryInto<ecdsa::Public> + Clone,
{
	type Success = AccountId;

	fn try_address_origin(
		address: &H160,
		origin: OuterOrigin,
	) -> Result<Self::Success, OuterOrigin> {
		origin.into().and_then(|o| match o {
			RawOrigin::Signed(who) => {
				if let Ok(pubkey) = who.clone().try_into() {
					if let Ok(hashed) = pubkey.to_eth_address() {
						if &hashed == &address.0 {
							return Ok(who)
						}
					};
				};
				Err(OuterOrigin::from(RawOrigin::Signed(who)))
			},
			r => Err(OuterOrigin::from(r)),
		})
	}
}

/// Hashed address mapping.
pub struct HashedAddressMapping<T, H>(PhantomData<T>, PhantomData<H>);

impl<T, H> AddressMapping<T::AccountId> for HashedAddressMapping<T, H>
where
	T: pallet_account_alias_registry::Config,
	T::AccountId: From<H256> + EcdsaExt,
	H: Hasher<Out = H256>,
{
	fn into_account_id(address: H160) -> T::AccountId {
		let alias = AccountAlias::EthereumAddress(address.into());
		if let Some(x) = pallet_account_alias_registry::Pallet::<T>::lookup(&alias) {
			return x
		}
		let mut data = [0u8; 24];
		data[0..4].copy_from_slice(b"evm:");
		data[4..24].copy_from_slice(&address[..]);
		let hash = H::hash(&data);

		hash.into()
	}
}
