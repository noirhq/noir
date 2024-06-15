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

//! Interoperable public key representation.

use crate::{traits::Property, AccountId32};
use np_core::p256;
use parity_scale_codec::{Decode, Encode, EncodeLike, Error as CodecError, Input, MaxEncodedLen};
use scale_info::TypeInfo;
use sp_core::{ecdsa, ed25519, sr25519, H256};
use sp_runtime::traits::IdentifyAccount;
#[cfg(not(feature = "std"))]
use sp_std::vec::Vec;

#[cfg(feature = "serde")]
use base64ct::{Base64UrlUnpadded, Encoding};
#[cfg(feature = "serde")]
use serde::{
	de::{Deserializer, Error as DeError, Visitor},
	ser::Serializer,
	Deserialize, Serialize,
};
#[cfg(all(not(feature = "std"), feature = "serde"))]
use sp_std::alloc::string::String;

/// Multicodec codes encoded with unsigned varint.
#[allow(dead_code)]
pub mod multicodec {
	/// Multicodec code for Secp256k1 public key. (0xe7)
	pub const SECP256K1_PUB: &[u8] = &[0xe7, 0x01];
	/// Multicodec code for Ed25519 public key. (0xed)
	pub const ED25519_PUB: &[u8] = &[0xed, 0x01];
	/// Multicodec code for Sr25519 public key. (0xef)
	pub const SR25519_PUB: &[u8] = &[0xef, 0x01];
	/// Multicodec code for P-256 public key. (0x1200)
	pub const P256_PUB: &[u8] = &[0x80, 0x24];
	/// Multicodec code for Blake2b-256 hash. (0xb220 + length(32))
	pub const BLAKE2B_256: &[u8] = &[0xa0, 0xe4, 0x02, 0x20];
}

#[cfg_attr(feature = "std", derive(thiserror::Error))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
	#[cfg_attr(feature = "std", error("invalid length"))]
	BadLength,
	#[cfg_attr(feature = "std", error("invalid multicodec prefix"))]
	InvalidPrefix,
	#[cfg_attr(feature = "std", error("invalid conversion"))]
	InvalidConversion,
}

/// A universal representation of a public key encoded with multicodec.
///
/// NOTE: https://www.w3.org/TR/vc-data-integrity/#multikey
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, TypeInfo)]
#[cfg_attr(feature = "std", derive(Hash))]
pub enum Multikey {
	/// Ed25519 public key.
	Ed25519(ed25519::Public),
	/// Sr25519 public key.
	Sr25519(sr25519::Public),
	/// Secp256k1 public key.
	Secp256k1(ecdsa::Public),
	/// P-256 public key.
	P256(p256::Public),
	/// Blake2b-256 hash.
	Blake2b256(H256),
}

impl IdentifyAccount for Multikey {
	type AccountId = AccountId32;

	fn into_account(self) -> Self::AccountId {
		match self {
			Multikey::Ed25519(k) => AccountId32::from(k),
			Multikey::Sr25519(k) => AccountId32::from(k),
			Multikey::Secp256k1(k) => AccountId32::from(k),
			Multikey::P256(k) => AccountId32::from(k),
			Multikey::Blake2b256(k) => AccountId32::from(k),
		}
	}
}

#[cfg(feature = "serde")]
impl Serialize for Multikey {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: Serializer,
	{
		let encoded = String::from("u") + &Base64UrlUnpadded::encode_string(&self.encode());
		serializer.serialize_str(&encoded)
	}
}

// TODO: Support other multibase formats other than base64url.
#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for Multikey {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: Deserializer<'de>,
	{
		struct MultikeyVisitor;

		impl<'de> Visitor<'de> for MultikeyVisitor {
			type Value = Multikey;

			fn expecting(&self, formatter: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
				formatter.write_str("a multibase (base64url) encoded string")
			}

			fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
			where
				E: DeError,
			{
				use sp_std::str::FromStr;

				Multikey::from_str(value).map_err(|_| E::custom("invalid multikey"))
			}
		}

		deserializer.deserialize_str(MultikeyVisitor)
	}
}

impl TryFrom<&[u8]> for Multikey {
	type Error = Error;

	fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
		Ok(Self::try_from(Vec::from(data))?)
	}
}

impl TryFrom<Vec<u8>> for Multikey {
	type Error = Error;

	fn try_from(v: Vec<u8>) -> Result<Self, Self::Error> {
		if v.len() > 0 && v.len() < 34 {
			return Err(Error::BadLength);
		}
		match &v[0..4] {
			[0xe7, 0x01, ..] =>
				ecdsa::Public::try_from(&v[2..]).map_err(|_| Error::BadLength).map(Into::into),
			[0xed, 0x01, ..] =>
				ed25519::Public::try_from(&v[2..]).map_err(|_| Error::BadLength).map(Into::into),
			[0xef, 0x01, ..] =>
				sr25519::Public::try_from(&v[2..]).map_err(|_| Error::BadLength).map(Into::into),
			[0x80, 0x24, ..] =>
				p256::Public::try_from(&v[2..]).map_err(|_| Error::BadLength).map(Into::into),
			[0xa0, 0xe4, 0x02, 0x20] => (v.len() == 36)
				.then(|| Self::Blake2b256(H256::from_slice(&v[4..])))
				.ok_or(Error::BadLength),
			_ => Err(Error::InvalidPrefix),
		}
	}
}

impl MaxEncodedLen for Multikey {
	fn max_encoded_len() -> usize {
		36
	}
}

impl Encode for Multikey {
	fn size_hint(&self) -> usize {
		match self {
			Multikey::Ed25519(_) => 34,
			Multikey::Sr25519(_) => 34,
			Multikey::Secp256k1(_) => 35,
			Multikey::P256(_) => 35,
			Multikey::Blake2b256(_) => 36,
		}
	}

	fn encode(&self) -> Vec<u8> {
		let mut res = Vec::with_capacity(self.size_hint());
		match self {
			Self::Ed25519(k) => {
				res.extend_from_slice(multicodec::ED25519_PUB);
				res.extend_from_slice(k.as_ref());
			},
			Self::Sr25519(k) => {
				res.extend_from_slice(multicodec::SR25519_PUB);
				res.extend_from_slice(k.as_ref());
			},
			Self::Secp256k1(k) => {
				res.extend_from_slice(multicodec::SECP256K1_PUB);
				res.extend_from_slice(k.as_ref());
			},
			Self::P256(k) => {
				res.extend_from_slice(multicodec::P256_PUB);
				res.extend_from_slice(k.as_ref());
			},
			Self::Blake2b256(k) => {
				res.extend_from_slice(multicodec::BLAKE2B_256);
				res.extend_from_slice(k.as_ref());
			},
		}
		res
	}
}

impl EncodeLike for Multikey {}

impl Decode for Multikey {
	fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
		let byte = input.read_byte()?;
		let expected_len = match byte {
			0xed | 0xef => 34,
			0xe7 | 0x80 => 35,
			0xa0 => 36,
			_ => return Err("unexpected first byte decoding Multikey".into()),
		};
		let mut res = Vec::new();
		res.resize(expected_len, 0);
		res[0] = byte;
		input.read(&mut res[1..])?;

		Multikey::try_from(res).map_err(|_| "Could not decode Multikey".into())
	}
}

impl From<ed25519::Public> for Multikey {
	fn from(k: ed25519::Public) -> Self {
		Self::Ed25519(k)
	}
}

impl From<sr25519::Public> for Multikey {
	fn from(k: sr25519::Public) -> Self {
		Self::Sr25519(k)
	}
}

impl From<ecdsa::Public> for Multikey {
	fn from(k: ecdsa::Public) -> Self {
		Self::Secp256k1(k)
	}
}

impl From<p256::Public> for Multikey {
	fn from(k: p256::Public) -> Self {
		Self::P256(k)
	}
}

impl From<H256> for Multikey {
	fn from(hash: H256) -> Self {
		Self::Blake2b256(hash)
	}
}

impl TryFrom<AccountId32> for Multikey {
	type Error = ();

	fn try_from(v: AccountId32) -> Result<Self, Self::Error> {
		v.get().clone().ok_or(())
	}
}

impl TryFrom<Multikey> for ed25519::Public {
	type Error = Error;

	fn try_from(k: Multikey) -> Result<Self, Self::Error> {
		match k {
			Multikey::Ed25519(k) => Ok(k),
			_ => Err(Error::InvalidConversion),
		}
	}
}

impl TryFrom<Multikey> for sr25519::Public {
	type Error = Error;

	fn try_from(k: Multikey) -> Result<Self, Self::Error> {
		match k {
			Multikey::Sr25519(k) => Ok(k),
			_ => Err(Error::InvalidConversion),
		}
	}
}

impl TryFrom<Multikey> for ecdsa::Public {
	type Error = Error;

	fn try_from(k: Multikey) -> Result<Self, Self::Error> {
		match k {
			Multikey::Secp256k1(k) => Ok(k),
			_ => Err(Error::InvalidConversion),
		}
	}
}

impl TryFrom<Multikey> for p256::Public {
	type Error = Error;

	fn try_from(k: Multikey) -> Result<Self, Self::Error> {
		match k {
			Multikey::P256(k) => Ok(k),
			_ => Err(Error::InvalidConversion),
		}
	}
}

#[cfg(feature = "serde")]
impl sp_std::str::FromStr for Multikey {
	type Err = ();

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		if s.starts_with('u') {
			Base64UrlUnpadded::decode_vec(&s[1..])
				.map(Multikey::try_from)
				.map_err(|_| ())?
				.map_err(|_| ())
		} else if s.starts_with("0x") {
			array_bytes::hex2bytes(&s[2..])
				.map(Multikey::try_from)
				.map_err(|_| ())?
				.map_err(|_| ())
		} else {
			Err(())
		}
	}
}

#[cfg(feature = "std")]
impl std::fmt::Display for Multikey {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "u{}", Base64UrlUnpadded::encode_string(&self.encode()))
	}
}

impl sp_std::fmt::Debug for Multikey {
	#[cfg(feature = "std")]
	fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		write!(f, "u{}", Base64UrlUnpadded::encode_string(&self.encode()))
	}

	#[cfg(not(feature = "std"))]
	fn fmt(&self, _: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use parity_scale_codec::{Decode, Encode, IoReader};
	use sp_std::str::FromStr;

	#[test]
	fn string_serialization_works() {
		let raw = array_bytes::hex2bytes(
			"e701023af1e1efa4d1e1ad5cb9e3967e98e901dafcd37c44cf0bfb6c216997f5ee51df",
		)
		.unwrap();

		let key = Multikey::from_str("u5wECOvHh76TR4a1cueOWfpjpAdr803xEzwv7bCFpl_XuUd8");
		assert!(key.is_ok());

		let key = key.unwrap();
		assert_eq!(key.encode(), raw);
		assert_eq!(key.to_string(), "u5wECOvHh76TR4a1cueOWfpjpAdr803xEzwv7bCFpl_XuUd8");
	}

	#[test]
	fn kind_corresponds_to_contained_public_key() {
		let pubkey = array_bytes::hex2bytes(
			"023af1e1efa4d1e1ad5cb9e3967e98e901dafcd37c44cf0bfb6c216997f5ee51df",
		)
		.unwrap();
		let pubkey = ecdsa::Public::try_from(&pubkey[..]).unwrap();
		let key = Multikey::from(pubkey);
		assert!(matches!(key, Multikey::Secp256k1(_)));
	}

	#[test]
	fn scale_serialization_works() {
		let raw = array_bytes::hex2bytes(
			"e701023af1e1efa4d1e1ad5cb9e3967e98e901dafcd37c44cf0bfb6c216997f5ee51df",
		)
		.unwrap();
		let key = Multikey::try_from(raw.clone()).expect("multikey should be created; qed");
		assert!(matches!(key, Multikey::Secp256k1(_)));

		let encoded = key.encode();
		assert_eq!(encoded, raw);

		let mut io = IoReader(&encoded[..]);
		let decoded = Multikey::decode(&mut io);
		assert!(decoded.is_ok());
		assert_eq!(decoded.unwrap(), key);
	}
}
