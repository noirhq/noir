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
#[cfg(feature = "serde")]
use sp_runtime::RuntimeString;
#[cfg(feature = "serde")]
use sp_std::vec::Vec;

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

#[cfg(feature = "serde")]
struct VecWriter(pub Vec<u8>);

#[cfg(feature = "serde")]
impl sp_std::fmt::Write for VecWriter {
	fn write_str(&mut self, s: &str) -> core::fmt::Result {
		self.0.extend_from_slice(s.as_bytes());
		Ok(())
	}
}

/// Data that can be encoded to/from Bech32.
pub trait Bech32Codec: Sized + AsRef<[u8]> + sp_core::ByteArray {
	/// Returns the bech32 encoded string.
	#[cfg(feature = "serde")]
	fn to_bech32_with_hrp(&self, hrp: Hrp) -> RuntimeString {
		let mut f = VecWriter(Vec::new());
		bech32::encode_to_fmt::<Bech32, _>(&mut f, hrp, self.as_ref()).unwrap();
		#[cfg(not(feature = "std"))]
		{
			RuntimeString::Owned(f.0)
		}

		#[cfg(feature = "std")]
		{
			RuntimeString::Owned(String::from_utf8(f.0).unwrap())
		}
	}

	/// Returns the bech32 encoded string.
	#[cfg(feature = "serde")]
	fn to_bech32(&self) -> RuntimeString {
		self.to_bech32_with_hrp(default_bech32_hrp())
	}
}
