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

#[cfg(feature = "full_crypto")]
use crate::bip32::{secp256k1::ExtendedPrivateKey, DeriveJunction};
use crate::crypto::AddressBytes;
use sp_core::ecdsa;
#[cfg(feature = "full_crypto")]
use sp_core::Pair;

#[doc(hidden)]
pub struct EthereumTag;

/// The byte length of encoded Ethereum address.
pub const ADDRESS_SERIALIZED_SIZE: usize = 20;

/// The Ethereum address.
pub type EthereumAddress = AddressBytes<ADDRESS_SERIALIZED_SIZE, EthereumTag>;

impl From<ecdsa::Public> for EthereumAddress {
	fn from(public: ecdsa::Public) -> Self {
		let uncompressed_public = crate::ecdsa::secp256k1_pubkey_serialize(&public.0)
			.expect("Uncompressed secp256k1 public key; qed");
		let hash = np_crypto_hashing::keccak_256(&uncompressed_public);
		Self::try_from(&hash[12..]).expect("Ethereum address; qed")
	}
}

impl From<&ecdsa::Public> for EthereumAddress {
	fn from(public: &ecdsa::Public) -> Self {
		let uncompressed_public = crate::ecdsa::secp256k1_pubkey_serialize(&public.0)
			.expect("Uncompressed secp256k1 public key; qed");
		let hash = np_crypto_hashing::keccak_256(&uncompressed_public);
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
pub struct EthereumBip44(pub ExtendedPrivateKey);

#[cfg(feature = "full_crypto")]
impl EthereumBip44 {
	pub fn from_phrase(phrase: &str, password: Option<&str>) -> Result<Self, ()> {
		let xpriv = ExtendedPrivateKey::from_phrase(phrase, password)?;
		let path = DeriveJunction::parse("m/44'/60'/0'/0").unwrap();
		Ok(Self(xpriv.derive(path.into_iter())?))
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

	pub fn address(&self, index: u32) -> EthereumAddress {
		EthereumAddress::from(self.public(index))
	}
}

#[cfg(feature = "std")]
impl Default for EthereumBip44 {
	fn default() -> Self {
		Self::from_phrase(sp_core::crypto::DEV_PHRASE, None).unwrap()
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
