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

//! Cryptographic utilities.

pub use crate::crypto_bytes::{CryptoBytes, PublicBytes, SignatureBytes};

pub use address_bytes::*;

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
