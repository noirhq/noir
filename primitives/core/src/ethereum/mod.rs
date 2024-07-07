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

//! Ethereum primitives.

use crate::crypto::AddressBytes;
use sp_core::ecdsa;

#[doc(hidden)]
pub struct EthereumTag;

/// The byte length of encoded Ethereum address.
pub const ADDRESS_SERIALIZED_SIZE: usize = 20;

/// The Ethereum address.
pub type EthereumAddress = AddressBytes<ADDRESS_SERIALIZED_SIZE, EthereumTag>;

impl From<ecdsa::Public> for EthereumAddress {
	fn from(public: ecdsa::Public) -> Self {
		Self::from(&public)
	}
}

impl From<&ecdsa::Public> for EthereumAddress {
	fn from(public: &ecdsa::Public) -> Self {
		let uncompressed_public = crate::ecdsa::secp256k1_pubkey_serialize(&public.0, false)
			.expect("Uncompressed secp256k1 public key; qed");
		let hash = np_crypto_hashing::keccak_256(&uncompressed_public[1..]);
		Self::try_from(&hash[12..]).expect("Ethereum address; qed")
	}
}

#[cfg(feature = "std")]
impl std::fmt::Display for EthereumAddress {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		let address = array_bytes::bytes2hex("", self.0);
		let address_hash = array_bytes::bytes2hex("", sp_core::keccak_256(address.as_bytes()));

		let checksum: String =
			address
				.char_indices()
				.fold(String::from("0x"), |mut acc, (index, address_char)| {
					let n = u16::from_str_radix(&address_hash[index..index + 1], 16)
						.expect("Keccak256 hashed; qed");

					if n > 7 {
						// make char uppercase if ith character is 9..f
						acc.push_str(&address_char.to_uppercase().to_string())
					} else {
						// already lowercased
						acc.push(address_char)
					}

					acc
				});
		write!(f, "{checksum}")
	}
}

#[cfg(feature = "full_crypto")]
pub type EthereumBip44 = crate::bitcoin::bip44::Bip44<60>;

#[cfg(feature = "full_crypto")]
impl EthereumBip44 {
	pub fn address(&self, index: u32) -> EthereumAddress {
		EthereumAddress::from(self.public(index))
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn display_ethereum_address() {
		let address = EthereumAddress::from(EthereumBip44::default().public(0));
		assert_eq!(address.to_string(), "0xf24FF3a9CF04c71Dbc94D0b566f7A27B94566cac");
		assert_eq!(format!("{:?}", address), "f24ff3a9cf04c71dbc94d0b566f7a27b94566cac");
	}
}
