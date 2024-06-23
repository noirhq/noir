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

use crate::{
	traits::{Checkable, Property},
	Multikey,
};
use np_core::{p256, CosmosAddress, EthereumAddress};
use parity_scale_codec::{Decode, Encode, EncodeLike, Error, Input, MaxEncodedLen};
use scale_info::{Type, TypeInfo};
#[cfg(feature = "serde")]
use sp_core::crypto::Ss58Codec;
use sp_core::{
	crypto::{FromEntropy, UncheckedFrom},
	ecdsa, ed25519, sr25519, ByteArray, H256,
};
use sp_io::hashing::blake2_256;
#[cfg(all(feature = "serde", not(feature = "std")))]
use sp_std::alloc::{format, string::String};
use sp_std::vec::Vec;

/// An opaque 32-byte cryptographic identifier.
///
/// HACK: This type replaces Substrate AccountId32 to be passed keeping recovered public key.
/// `key` field should be ignored during serialization.
#[derive(Clone, Eq)]
pub struct AccountId32 {
	inner: [u8; 32],
	key: Option<Multikey>,
}

impl AccountId32 {
	/// Create a new instance from its raw inner byte value.
	///
	/// Equivalent to this types `From<[u8; 32]>` implementation. For the lack of const
	/// support in traits we have this constructor.
	pub const fn new(inner: [u8; 32]) -> Self {
		Self { inner, key: None }
	}
}

impl Property<Option<Multikey>> for AccountId32 {
	fn get(&self) -> &Option<Multikey> {
		&self.key
	}

	fn set(&mut self, value: Option<Multikey>) {
		self.key = value;
	}
}

impl PartialEq for AccountId32 {
	fn eq(&self, other: &Self) -> bool {
		self.inner.eq(&other.inner)
	}
}

impl Ord for AccountId32 {
	fn cmp(&self, other: &Self) -> sp_std::cmp::Ordering {
		self.inner.cmp(&other.inner)
	}
}

impl PartialOrd for AccountId32 {
	fn partial_cmp(&self, other: &Self) -> Option<sp_std::cmp::Ordering> {
		Some(self.cmp(other))
	}
}

impl Encode for AccountId32 {
	fn size_hint(&self) -> usize {
		self.inner.size_hint()
	}

	fn encode(&self) -> Vec<u8> {
		self.inner.encode()
	}
}

impl EncodeLike for AccountId32 {}

impl Decode for AccountId32 {
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		Ok(Self { inner: <[u8; 32]>::decode(input)?, key: None })
	}
}

impl MaxEncodedLen for AccountId32 {
	fn max_encoded_len() -> usize {
		32
	}
}

impl TypeInfo for AccountId32 {
	type Identity = <sp_core::crypto::AccountId32 as TypeInfo>::Identity;

	fn type_info() -> Type {
		<sp_core::crypto::AccountId32 as TypeInfo>::type_info()
	}
}

#[cfg(feature = "std")]
impl sp_std::hash::Hash for AccountId32 {
	fn hash<H: sp_std::hash::Hasher>(&self, state: &mut H) {
		self.inner.hash(state);
	}
}

impl UncheckedFrom<H256> for AccountId32 {
	fn unchecked_from(h: H256) -> Self {
		Self { inner: h.into(), key: None }
	}
}

impl ByteArray for AccountId32 {
	const LEN: usize = 32;
}

#[cfg(feature = "serde")]
impl Ss58Codec for AccountId32 {}

impl AsRef<[u8]> for AccountId32 {
	fn as_ref(&self) -> &[u8] {
		&self.inner
	}
}

impl AsMut<[u8]> for AccountId32 {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut self.inner
	}
}

impl AsRef<[u8; 32]> for AccountId32 {
	fn as_ref(&self) -> &[u8; 32] {
		&self.inner
	}
}

impl AsMut<[u8; 32]> for AccountId32 {
	fn as_mut(&mut self) -> &mut [u8; 32] {
		&mut self.inner
	}
}

impl From<[u8; 32]> for AccountId32 {
	fn from(v: [u8; 32]) -> Self {
		Self::new(v)
	}
}

impl<'a> TryFrom<&'a [u8]> for AccountId32 {
	type Error = ();

	fn try_from(v: &'a [u8]) -> Result<Self, Self::Error> {
		if v.len() == 32 {
			let mut inner = [0u8; 32];
			inner.copy_from_slice(v);
			Ok(Self::new(inner))
		} else {
			Err(())
		}
	}
}

impl From<H256> for AccountId32 {
	fn from(v: H256) -> Self {
		Self::new(v.into())
	}
}

impl From<ed25519::Public> for AccountId32 {
	fn from(v: ed25519::Public) -> Self {
		Self { inner: v.0, key: Some(v.into()) }
	}
}

impl From<sr25519::Public> for AccountId32 {
	fn from(v: sr25519::Public) -> Self {
		Self { inner: v.0, key: Some(v.into()) }
	}
}

impl From<ecdsa::Public> for AccountId32 {
	fn from(v: ecdsa::Public) -> Self {
		Self { inner: blake2_256(v.as_ref()), key: Some(v.into()) }
	}
}

impl From<&ecdsa::Public> for AccountId32 {
	fn from(v: &ecdsa::Public) -> Self {
		Self { inner: blake2_256(v), key: Some((*v).into()) }
	}
}

impl From<p256::Public> for AccountId32 {
	fn from(v: p256::Public) -> Self {
		Self { inner: blake2_256(v.as_ref()), key: Some(v.into()) }
	}
}

impl From<&p256::Public> for AccountId32 {
	fn from(v: &p256::Public) -> Self {
		Self { inner: blake2_256(v), key: Some((*v).into()) }
	}
}

impl From<AccountId32> for [u8; 32] {
	fn from(v: AccountId32) -> [u8; 32] {
		v.inner
	}
}

#[cfg(feature = "std")]
impl std::fmt::Display for AccountId32 {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		write!(f, "{}", self.to_ss58check())
	}
}

impl sp_std::fmt::Debug for AccountId32 {
	fn fmt(&self, f: &mut sp_std::fmt::Formatter) -> sp_std::fmt::Result {
		#[cfg(feature = "serde")]
		{
			let s = self.to_ss58check();
			write!(f, "{} ({}...)", sp_core::hexdisplay::HexDisplay::from(&self.inner), &s[0..8])?;
		}

		#[cfg(not(feature = "serde"))]
		write!(f, "{}", sp_core::hexdisplay::HexDisplay::from(&self.inner))?;

		Ok(())
	}
}

#[cfg(feature = "serde")]
impl serde::Serialize for AccountId32 {
	fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
	where
		S: serde::Serializer,
	{
		serializer.serialize_str(&self.to_ss58check())
	}
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AccountId32 {
	fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
	where
		D: serde::Deserializer<'de>,
	{
		Ss58Codec::from_ss58check(&String::deserialize(deserializer)?)
			.map_err(|e| serde::de::Error::custom(format!("{:?}", e)))
	}
}

#[cfg(feature = "std")]
impl sp_std::str::FromStr for AccountId32 {
	type Err = &'static str;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let hex_or_ss58_without_prefix = s.trim_start_matches("0x");
		if hex_or_ss58_without_prefix.len() == 64 {
			array_bytes::hex_n_into(hex_or_ss58_without_prefix).map_err(|_| "invalid hex address.")
		} else {
			Self::from_ss58check(s).map_err(|_| "invalid ss58 address.")
		}
	}
}

/// Creates an [`AccountId32`] from the input, which should contain at least 32 bytes.
impl FromEntropy for AccountId32 {
	fn from_entropy(
		input: &mut impl parity_scale_codec::Input,
	) -> Result<Self, parity_scale_codec::Error> {
		Ok(AccountId32::new(FromEntropy::from_entropy(input)?))
	}
}

impl Checkable<ed25519::Public> for AccountId32 {
	type Output = bool;

	fn check(&mut self, v: ed25519::Public) -> Self::Output {
		(self.inner == v.0)
			.then(|| {
				self.key = Some(v.into());
			})
			.is_some()
	}
}

impl Checkable<sr25519::Public> for AccountId32 {
	type Output = bool;

	fn check(&mut self, v: sr25519::Public) -> Self::Output {
		(self.inner == v.0)
			.then(|| {
				self.key = Some(v.into());
			})
			.is_some()
	}
}

impl Checkable<ecdsa::Public> for AccountId32 {
	type Output = bool;

	fn check(&mut self, v: ecdsa::Public) -> Self::Output {
		(self.inner == blake2_256(v.as_ref()))
			.then(|| {
				self.key = Some(v.into());
			})
			.is_some()
	}
}

impl Checkable<p256::Public> for AccountId32 {
	type Output = bool;

	fn check(&mut self, v: p256::Public) -> Self::Output {
		(self.inner == blake2_256(v.as_ref()))
			.then(|| {
				self.key = Some(v.into());
			})
			.is_some()
	}
}

impl TryFrom<&AccountId32> for EthereumAddress {
	type Error = ();

	fn try_from(v: &AccountId32) -> Result<Self, Self::Error> {
		if let Some(v) = v.get() {
			if let Ok(pubkey) = ecdsa::Public::try_from(v.clone()) {
				return Ok(EthereumAddress::from(&pubkey));
			}
		}
		Err(())
	}
}

impl TryFrom<&AccountId32> for CosmosAddress {
	type Error = ();

	fn try_from(v: &AccountId32) -> Result<Self, Self::Error> {
		if let Some(v) = v.get() {
			if let Ok(pubkey) = ecdsa::Public::try_from(v.clone()) {
				return Ok(CosmosAddress::from(&pubkey));
			}
		}
		Err(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn accountid_32_from_str_works() {
		use std::str::FromStr;
		assert!(AccountId32::from_str("5G9VdMwXvzza9pS8qE8ZHJk3CheHW9uucBn9ngW4C1gmmzpv").is_ok());
		assert!(AccountId32::from_str(
			"5c55177d67b064bb5d189a3e1ddad9bc6646e02e64d6e308f5acbb1533ac430d"
		)
		.is_ok());
		assert!(AccountId32::from_str(
			"0x5c55177d67b064bb5d189a3e1ddad9bc6646e02e64d6e308f5acbb1533ac430d"
		)
		.is_ok());

		assert_eq!(
			AccountId32::from_str("99G9VdMwXvzza9pS8qE8ZHJk3CheHW9uucBn9ngW4C1gmmzpv").unwrap_err(),
			"invalid ss58 address.",
		);
		assert_eq!(
			AccountId32::from_str(
				"gc55177d67b064bb5d189a3e1ddad9bc6646e02e64d6e308f5acbb1533ac430d"
			)
			.unwrap_err(),
			"invalid hex address.",
		);
		assert_eq!(
			AccountId32::from_str(
				"0xgc55177d67b064bb5d189a3e1ddad9bc6646e02e64d6e308f5acbb1533ac430d"
			)
			.unwrap_err(),
			"invalid hex address.",
		);

		// valid hex but invalid length will be treated as ss58.
		assert_eq!(
			AccountId32::from_str(
				"55c55177d67b064bb5d189a3e1ddad9bc6646e02e64d6e308f5acbb1533ac430d"
			)
			.unwrap_err(),
			"invalid ss58 address.",
		);
	}
}
