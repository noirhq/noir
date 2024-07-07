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

//! Wrapper for Bech32 encoding and decoding.

#[cfg(feature = "serde")]
pub use bech32::Hrp;

#[cfg(feature = "serde")]
use bech32::Bech32;
#[cfg(all(not(feature = "std"), feature = "serde"))]
use sp_std::alloc::string::String;

#[cfg(all(feature = "std", feature = "serde"))]
use parking_lot::Mutex;
#[cfg(all(not(feature = "std"), feature = "serde"))]
use spin::Mutex;

/// Default human-readable part for Bech32 encoding.
#[cfg(feature = "serde")]
static DEFAULT_HRP: Mutex<Hrp> = Mutex::new(Hrp::parse_unchecked("cosmos"));

/// Returns default human-readable part for Bech32 encoding.
#[cfg(feature = "serde")]
pub fn default_bech32_hrp() -> Hrp {
	DEFAULT_HRP.lock().clone()
}

/// Set the default human-readable part for Bech32 encoding.
#[cfg(feature = "serde")]
pub fn set_default_bech32_hrp(hrp: Hrp) {
	*DEFAULT_HRP.lock() = hrp;
}

/// Data that can be encoded to/from Bech32.
pub trait Bech32Codec: Sized + AsRef<[u8]> + sp_core::ByteArray {
	/// Returns the bech32 encoded string.
	#[cfg(feature = "serde")]
	fn to_bech32_with_hrp(&self, hrp: Hrp) -> Result<String, ()> {
		bech32::encode::<Bech32>(hrp, self.as_ref()).map_err(|_| ())
	}

	/// Returns the bech32 encoded string.
	#[cfg(feature = "serde")]
	fn to_bech32(&self) -> Result<String, ()> {
		self.to_bech32_with_hrp(default_bech32_hrp())
	}
}
