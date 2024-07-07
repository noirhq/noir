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

use sp_std::vec::Vec;

/// Decompress secp256k1 public key.
pub fn secp256k1_pubkey_serialize(pubkey: &[u8], compressed: bool) -> Result<Vec<u8>, ()> {
	#[cfg(not(feature = "std"))]
	{
		use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};

		let pubkey = PublicKey::from_sec1_bytes(&pubkey[..]).map_err(|_| ())?;
		Ok(pubkey.to_encoded_point(compressed).as_bytes().to_vec())
	}

	#[cfg(feature = "std")]
	{
		use secp256k1::PublicKey;

		let pubkey = PublicKey::from_slice(&pubkey[..]).map_err(|_| ())?;
		if compressed {
			Ok(pubkey.serialize().to_vec())
		} else {
			Ok(pubkey.serialize_uncompressed().to_vec())
		}
	}
}

/// Verify a non-recoverable secp256k1 ECDSA signature (64 bytes).
#[cfg(feature = "std")]
pub fn secp256k1_ecdsa_verify(sig: &[u8], msg: &[u8], pub_key: &[u8]) -> bool {
	use secp256k1::{ecdsa::Signature, Message, PublicKey};

	let sig = match Signature::from_compact(sig) {
		Ok(v) => v,
		Err(_) => return false,
	};
	let msg = match Message::from_digest_slice(msg) {
		Ok(v) => v,
		Err(_) => return false,
	};
	let pub_key = match PublicKey::from_slice(pub_key) {
		Ok(v) => v,
		Err(_) => return false,
	};

	sig.verify(&msg, &pub_key).is_ok()
}
