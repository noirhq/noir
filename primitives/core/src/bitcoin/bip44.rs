// This file is part of Noir.

// Copyright (C) Haderech Pte. Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! BIP44 key derivation.

#[cfg(feature = "full_crypto")]
use crate::bitcoin::bip32::{secp256k1::ExtendedPrivateKey, DeriveJunction};
#[cfg(feature = "full_crypto")]
use sp_core::{ecdsa, Pair};

#[cfg(feature = "full_crypto")]
pub type CoinType = u32;

#[cfg(feature = "full_crypto")]
pub struct Bip44<const C: CoinType>(pub ExtendedPrivateKey);

#[cfg(feature = "full_crypto")]
impl<const C: CoinType> Bip44<C> {
	pub fn from_phrase(phrase: &str, password: Option<&str>) -> Result<Self, ()> {
		let path = vec![
			DeriveJunction::from(44).harden(),
			DeriveJunction::from(C).harden(),
			DeriveJunction::from(0).harden(),
			DeriveJunction::from(0),
		];
		let master = ExtendedPrivateKey::from_phrase(phrase, password)?;
		Ok(Self(master.derive(path.into_iter())?))
	}

	pub fn pair(&self, index: u32) -> ecdsa::Pair {
		let path = DeriveJunction::from(index);
		let xpriv = self.0.derive(sp_std::iter::once(path)).unwrap();
		ecdsa::Pair::from_seed_slice(xpriv.as_ref()).unwrap()
	}

	pub fn public(&self, index: u32) -> ecdsa::Public {
		let path = DeriveJunction::from(index);
		let xpriv = self.0.derive(sp_std::iter::once(path)).unwrap();
		ecdsa::Pair::from_seed_slice(xpriv.as_ref()).unwrap().public()
	}
}

#[cfg(feature = "std")]
impl<const C: CoinType> Default for Bip44<C> {
	fn default() -> Self {
		Self::from_phrase(sp_core::crypto::DEV_PHRASE, None).unwrap()
	}
}
