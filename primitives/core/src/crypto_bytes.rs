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

use scale_info::TypeInfo;
use sp_core::{ByteArray, Decode, Encode, MaxEncodedLen};

pub use address_bytes::*;

/// Extension to [`sp_core::crypto::CryptoBytes`].
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

mod address_bytes {
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
