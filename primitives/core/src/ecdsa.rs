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

//! Simple ECDSA secp256k1 API.

use sp_core::H160;

/// Extension trait to sp_core::ecdsa (alternative to frame_support::crypto::ECDSAExt)
pub trait EcdsaExt {
	/// Convert to ethereum address, if available.
	fn to_eth_address(&self) -> Option<H160>;
	/// Convert to cosmos address, if available.
	fn to_cosm_address(&self) -> Option<H160>;
}

/// Decompress secp256k1 public key.
pub fn secp256k1_pubkey_serialize(pubkey: &[u8; 33]) -> Option<[u8; 64]> {
	#[cfg(not(feature = "std"))]
	{
		use k256::PublicKey;

		let pubkey = PublicKey::from_sec1_bytes(&pubkey[..]).ok()?;
		<[u8; 64]>::try_from(&pubkey.to_encoded_point(false).as_bytes()[1..]).ok()
	}

	#[cfg(feature = "std")]
	{
		use secp256k1::PublicKey;

		let pubkey = PublicKey::from_slice(&pubkey[..]).ok()?;
		let mut res = [0u8; 64];
		res.copy_from_slice(&pubkey.serialize_uncompressed()[1..]);
		Some(res)
	}
}
