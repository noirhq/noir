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

//! Hashing functions.

use ripemd::{Digest, Ripemd160};

pub use sp_crypto_hashing::*;

/// Do a Ripemd160 hash and return result.
pub fn ripemd160(data: &[u8]) -> [u8; 20] {
	Ripemd160::digest(data).into()
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_ripemd160() {
		let msg = b"hello world";
		let hash = ripemd160(msg);
		assert_eq!(
			hash,
			[
				0x98, 0xc6, 0x15, 0x78, 0x4c, 0xcb, 0x5f, 0xe5, 0x93, 0x6f, 0xbc, 0x0c, 0xbe, 0x9d,
				0xfd, 0xb4, 0x08, 0xd9, 0x2f, 0x0f,
			]
		);
	}
}
