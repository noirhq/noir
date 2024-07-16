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

extern crate alloc;
use alloc::vec::Vec;
use parity_scale_codec::{Decode, Encode, Error as CodecError, Input};

pub mod multicodec {
	pub const SECP256K1_PUB: u64 = 0xe7;
	pub const ED25519_PUB: u64 = 0xed;
	pub const SR25519_PUB: u64 = 0xef;
	pub const P256_PUB: u64 = 0x1200;

	/// Multicodec codes encoded with unsigned varint.
	pub mod unrolled {
		use crate::multiformats::UnsignedVarint;

		/// Multicodec code for Secp256k1 public key. (0xe7)
		pub const SECP256K1_PUB: [u8; 2] = UnsignedVarint(super::SECP256K1_PUB).const_encode();
		/// Multicodec code for Ed25519 public key. (0xed)
		pub const ED25519_PUB: [u8; 2] = UnsignedVarint(super::ED25519_PUB).const_encode();
		/// Multicodec code for Sr25519 public key. (0xef)
		pub const SR25519_PUB: [u8; 2] = UnsignedVarint(super::SR25519_PUB).const_encode();
		/// Multicodec code for P-256 public key. (0x1200)
		pub const P256_PUB: [u8; 2] = UnsignedVarint(super::P256_PUB).const_encode();
	}
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct UnsignedVarint(pub u64);

impl UnsignedVarint {
	pub const fn encoded_size(&self) -> usize {
		match self.0 {
			0x0000000000000000..=0x000000000000007f => 1,
			0x0000000000000080..=0x0000000000003fff => 2,
			0x0000000000004000..=0x00000000001fffff => 3,
			0x0000000000200000..=0x000000000fffffff => 4,
			0x0000000010000000..=0x00000007ffffffff => 5,
			0x0000000800000000..=0x000003ffffffffff => 6,
			0x0000040000000000..=0x0001ffffffffffff => 7,
			0x0002000000000000..=0x00ffffffffffffff => 8,
			0x0100000000000000..=0x7fffffffffffffff => 9,
			0x8000000000000000..=0xffffffffffffffff => 10,
		}
	}

	pub const fn const_encode<const N: usize>(&self) -> [u8; N] {
		assert!(N == self.encoded_size());
		let mut bytes = [0; N];
		let mut value = self.0;
		let mut i = 0;
		loop {
			let mut byte = (value & 0x7f) as u8;
			value >>= 7;
			if value != 0 {
				byte |= 0x80;
			}
			bytes[i] = byte;
			i += 1;
			if value == 0 {
				break
			}
		}
		bytes
	}
}

impl Encode for UnsignedVarint {
	fn size_hint(&self) -> usize {
		self.encoded_size()
	}

	fn encode(&self) -> Vec<u8> {
		let mut bytes = Vec::with_capacity(self.size_hint());
		let mut value = self.0;
		loop {
			let mut byte = (value & 0x7f) as u8;
			value >>= 7;
			if value != 0 {
				byte |= 0x80;
			}
			bytes.push(byte);
			if value == 0 {
				break
			}
		}
		bytes
	}
}

impl Decode for UnsignedVarint {
	fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
		let mut value = 0;
		let mut i = 0;
		loop {
			let byte = input.read_byte()?;
			value |= ((byte & 0x7f) as u64) << (7 * i);
			i += 1;
			if byte & 0x80 == 0 {
				break
			}
		}
		let value = UnsignedVarint(value);
		if i > 10 || i != value.encoded_size() {
			return Err(CodecError::from("unsigned varint: non-canonical encoding"))
		}
		Ok(value)
	}
}
