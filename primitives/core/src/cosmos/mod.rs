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

//! Cosmos primitives.

use crate::{bech32::Bech32Codec, crypto::AddressBytes};
use sp_core::ecdsa;

#[doc(hidden)]
pub struct CosmosTag;

/// The byte length of encoded Cosmos address.
pub const ADDRESS_SERIALIZED_SIZE: usize = 20;

/// The Cosmos address.
pub type CosmosAddress = AddressBytes<ADDRESS_SERIALIZED_SIZE, CosmosTag>;

impl Bech32Codec for CosmosAddress {}

impl From<ecdsa::Public> for CosmosAddress {
	fn from(public: ecdsa::Public) -> Self {
		let hash = np_crypto_hashing::sha2_256(&public.0);
		let hash = np_crypto_hashing::ripemd160(&hash);
		Self::from_raw(hash)
	}
}

impl From<&ecdsa::Public> for CosmosAddress {
	fn from(public: &ecdsa::Public) -> Self {
		let hash = np_crypto_hashing::sha2_256(&public.0);
		let hash = np_crypto_hashing::ripemd160(&hash);
		Self::from_raw(hash)
	}
}

#[cfg(feature = "std")]
impl std::fmt::Display for CosmosAddress {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}", self.to_bech32())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ethereum::EthereumBip44;

	#[test]
	fn display_cosmos_address() {
		let address = CosmosAddress::from(EthereumBip44::default().public(0));
		assert_eq!(address.to_string(), "cosmos13essdahf3eajr07lhlpaawswmmfg5pr6t459pg");
	}
}
