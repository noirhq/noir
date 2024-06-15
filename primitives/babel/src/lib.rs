// This file is part of Noir.

// Copyright (C) 2023 Haderech Pte. Ltd.
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

//! Noir core types for interoperability.

pub use address_bytes::AddressBytes;
pub use bech32::Bech32Codec;
pub use cosmos::CosmosAddress;
pub use ethereum::EthereumAddress;

use scale_info::TypeInfo;
use sp_core::{ecdsa, ByteArray, Decode, Encode, MaxEncodedLen};

#[derive(Clone, Copy, Encode, Decode, MaxEncodedLen, TypeInfo)]
pub struct CryptoBytes<const N: usize, SubTag>(pub sp_core::crypto::CryptoBytes<N, SubTag>);

impl<const N: usize, SubTag> ByteArray for CryptoBytes<N, SubTag> {
	const LEN: usize = N;
}

impl<const N: usize, SubTag> AsRef<[u8]> for CryptoBytes<N, SubTag> {
	fn as_ref(&self) -> &[u8] {
		self.0.as_ref()
	}
}

impl<const N: usize, SubTag> AsMut<[u8]> for CryptoBytes<N, SubTag> {
	fn as_mut(&mut self) -> &mut [u8] {
		self.0.as_mut()
	}
}

impl<const N: usize, SubTag> TryFrom<&[u8]> for CryptoBytes<N, SubTag> {
	type Error = ();

	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		sp_core::crypto::CryptoBytes::<N, SubTag>::try_from(data).map(Self)
	}
}

impl<const N: usize, SubTag> core::ops::Deref for CryptoBytes<N, SubTag> {
	type Target = sp_core::crypto::CryptoBytes<N, SubTag>;

	fn deref(&self) -> &Self::Target {
		&self.0
	}
}

pub mod address_bytes {
	use super::CryptoBytes;

	/// Tag used for generic address bytes.
	pub struct AddressTag;

	/// Generic encoded address.
	pub type AddressBytes<const N: usize, SubTag> = CryptoBytes<N, (AddressTag, SubTag)>;

	impl<const N: usize, SubTag> sp_std::fmt::Debug for AddressBytes<N, SubTag> {
		fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
			write!(f, "{}", array_bytes::bytes2hex("", self.0))
		}
	}
}

pub mod ethereum {
	use super::*;

	#[doc(hidden)]
	pub struct EthereumTag;

	/// The byte length of encoded Ethereum address.
	pub const ADDRESS_SERIALIZED_SIZE: usize = 20;

	/// The Ethereum address.
	pub type EthereumAddress = AddressBytes<ADDRESS_SERIALIZED_SIZE, EthereumTag>;

	impl From<ecdsa::Public> for EthereumAddress {
		fn from(public: ecdsa::Public) -> Self {
			let uncompressed_public = np_io::crypto::secp256k1_pubkey_serialize(&public.0)
				.expect("Uncompressed secp256k1 public key; qed");
			let hash = sp_io::hashing::keccak_256(&uncompressed_public);
			Self::try_from(&hash[12..]).expect("Ethereum address; qed")
		}
	}

	#[cfg(feature = "std")]
	impl std::fmt::Display for EthereumAddress {
		fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
			let address = array_bytes::bytes2hex("", &self.0);
			let address_hash = array_bytes::bytes2hex("", sp_core::keccak_256(address.as_bytes()));

			let checksum: String = address.char_indices().fold(
				String::from("0x"),
				|mut acc, (index, address_char)| {
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
				},
			);
			write!(f, "{checksum}")
		}
	}
}

pub mod cosmos {
	use super::*;

	#[doc(hidden)]
	pub struct CosmosTag;

	/// The byte length of encoded Cosmos address.
	pub const ADDRESS_SERIALIZED_SIZE: usize = 20;

	/// The Cosmos address.
	pub type CosmosAddress = AddressBytes<ADDRESS_SERIALIZED_SIZE, CosmosTag>;

	impl Bech32Codec for CosmosAddress {}

	impl From<ecdsa::Public> for CosmosAddress {
		fn from(public: ecdsa::Public) -> Self {
			let hash = sp_io::hashing::sha2_256(&public.0);
			let hash = np_io::hashing::ripemd160(&hash);
			Self(hash.into())
		}
	}

	#[cfg(feature = "std")]
	impl std::fmt::Display for CosmosAddress {
		fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
			write!(f, "{}", self.to_bech32())
		}
	}
}

pub mod bech32 {
	use super::*;
	#[cfg(feature = "serde")]
	use sp_std::sync::OnceLock;
	#[cfg(feature = "serde")]
	use subtle_encoding::bech32;

	/// Default human-readable part for Bech32 encoding.
	#[cfg(feature = "serde")]
	static DEFAULT_HRP: OnceLock<String> = OnceLock::new();

	/// Returns default human-readable part for Bech32 encoding.
	#[cfg(feature = "serde")]
	pub fn default_bech32_hrp() -> &'static str {
		DEFAULT_HRP.get_or_init(|| "cosmos".to_string()).as_str()
	}

	/// Set the default human-readable part for Bech32 encoding.
	///
	/// NOTE: This can be called only once.
	#[cfg(feature = "serde")]
	pub fn set_default_bech32_hrp(hrp: &str) {
		let _ = DEFAULT_HRP.set(hrp.to_string());
	}

	pub trait Bech32Codec: Sized + AsRef<[u8]> + ByteArray {
		#[cfg(feature = "serde")]
		fn to_bech32_with_hrp<S: AsRef<str>>(&self, hrp: S) -> String {
			bech32::encode(hrp, &self)
		}

		#[cfg(feature = "serde")]
		fn to_bech32(&self) -> String {
			self.to_bech32_with_hrp(default_bech32_hrp())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn test_public() -> ecdsa::Public {
		use np_core::bip32::{secp256k1::ExtendedPrivateKey, DeriveJunction};
		use sp_core::{crypto::DEV_PHRASE, Pair};

		let path = DeriveJunction::parse("m/44'/60'/0'/0/0").unwrap();
		let xpriv = ExtendedPrivateKey::from_phrase(DEV_PHRASE, None).unwrap();
		let xpriv = xpriv.derive(path.into_iter()).unwrap();

		ecdsa::Pair::from_seed_slice(xpriv.as_ref()).unwrap().public()
	}

	#[test]
	fn display_ethereum_address() {
		let address = EthereumAddress::from(test_public());
		assert_eq!(address.to_string(), "0xf24FF3a9CF04c71Dbc94D0b566f7A27B94566cac");
		assert_eq!(format!("{:?}", address), "f24ff3a9cf04c71dbc94d0b566f7a27b94566cac");
	}

	#[test]
	fn display_cosmos_address() {
		let address = CosmosAddress::from(test_public());
		assert_eq!(address.to_string(), "cosmos13essdahf3eajr07lhlpaawswmmfg5pr6t459pg");
	}
}
