// This file is part of Noir.

// Copyright (c) Haderech Pte. Ltd.
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

extern crate alloc;

use crate::{
	traits::{Checkable, Property},
	Multikey,
};
#[cfg(all(feature = "serde", not(feature = "std")))]
use alloc::{format, string::String};
use buidl::FixedBytes;
use np_core::{ecdsa::EcdsaExt, p256};
#[cfg(feature = "serde")]
use sp_core::crypto::{PublicError, Ss58AddressFormat, Ss58Codec};
use sp_core::{
	crypto::{AccountId32 as SubstrateAccountId32, UncheckedFrom},
	ecdsa, ed25519, sr25519, H160, H256,
};
use sp_io::hashing::blake2_256;

/// An opaque 32-byte cryptographic identifier.
///
/// HACK: This type replaces Substrate AccountId32 to be passed keeping recovered public key.
/// `key` field should be ignored during serialization.
#[derive(FixedBytes)]
#[buidl(substrate)]
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

impl Property for AccountId32 {
	type Value = Option<Multikey>;

	fn get(&self) -> &Self::Value {
		&self.key
	}

	fn set(&mut self, value: Self::Value) {
		self.key = value;
	}
}

impl UncheckedFrom<H256> for AccountId32 {
	fn unchecked_from(h: H256) -> Self {
		Self { inner: h.into(), key: None }
	}
}

#[cfg(feature = "serde")]
impl Ss58Codec for AccountId32 {
	fn from_ss58check_with_version(s: &str) -> Result<(Self, Ss58AddressFormat), PublicError> {
		SubstrateAccountId32::from_ss58check_with_version(s)
			.map(|(inner, format)| (Self { inner: inner.into(), key: None }, format))
	}

	fn to_ss58check_with_version(&self, version: Ss58AddressFormat) -> String {
		SubstrateAccountId32::new(self.inner).to_ss58check_with_version(version)
	}
}

impl From<H256> for AccountId32 {
	fn from(h: H256) -> Self {
		Self::new(h.into())
	}
}

impl From<ed25519::Public> for AccountId32 {
	fn from(k: ed25519::Public) -> Self {
		Self { inner: k.0, key: Some(k.into()) }
	}
}

impl From<sr25519::Public> for AccountId32 {
	fn from(k: sr25519::Public) -> Self {
		Self { inner: k.0, key: Some(k.into()) }
	}
}

impl From<ecdsa::Public> for AccountId32 {
	fn from(k: ecdsa::Public) -> Self {
		Self { inner: blake2_256(k.as_ref()), key: Some(k.into()) }
	}
}

impl From<p256::Public> for AccountId32 {
	fn from(k: p256::Public) -> Self {
		Self { inner: blake2_256(k.as_ref()), key: Some(k.into()) }
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

impl Checkable<ed25519::Public> for AccountId32 {
	type Output = bool;

	fn check(&mut self, k: ed25519::Public) -> Self::Output {
		(self.inner == k.0)
			.then(|| {
				self.key = Some(k.into());
			})
			.is_some()
	}
}

impl Checkable<sr25519::Public> for AccountId32 {
	type Output = bool;

	fn check(&mut self, k: sr25519::Public) -> Self::Output {
		(self.inner == k.0)
			.then(|| {
				self.key = Some(k.into());
			})
			.is_some()
	}
}

impl Checkable<ecdsa::Public> for AccountId32 {
	type Output = bool;

	fn check(&mut self, k: ecdsa::Public) -> Self::Output {
		(self.inner == blake2_256(k.as_ref()))
			.then(|| {
				self.key = Some(k.into());
			})
			.is_some()
	}
}

impl Checkable<p256::Public> for AccountId32 {
	type Output = bool;

	fn check(&mut self, k: p256::Public) -> Self::Output {
		(self.inner == blake2_256(k.as_ref()))
			.then(|| {
				self.key = Some(k.into());
			})
			.is_some()
	}
}

impl EcdsaExt for AccountId32 {
	fn to_eth_address(&self) -> Option<H160> {
		self.key.as_ref().and_then(EcdsaExt::to_eth_address)
	}

	fn to_cosm_address(&self) -> Option<H160> {
		self.key.as_ref().and_then(EcdsaExt::to_cosm_address)
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
