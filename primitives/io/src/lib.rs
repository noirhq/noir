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

//! I/O host interface for Noir runtime.

#![warn(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

use np_core::{ecdsa, p256, webauthn};
use sp_runtime_interface::runtime_interface;

#[cfg(feature = "std")]
use secp256k1::{ecdsa::Signature, Message, PublicKey};

/// Interfaces for working with crypto related types from within the runtime.
#[runtime_interface]
pub trait Crypto {
	/// Verify P-256 signature.
	fn p256_verify(sig: &p256::Signature, msg: &[u8], pubkey: &p256::Public) -> bool {
		p256::Pair::verify_prehashed(sig, &sp_io::hashing::sha2_256(msg), pubkey)
	}

	/// Verify and recover a P-256 signature.
	fn p256_recover_compressed(sig: &[u8; 65], msg: &[u8; 32]) -> Option<[u8; 33]> {
		p256::Signature::from_raw(*sig).recover_prehashed(msg).map(|pubkey| pubkey.0)
	}

	/// Verify WebAuthn ES256 signature.
	fn webauthn_verify(sig: &webauthn::Signature, msg: &[u8], pubkey: &webauthn::Public) -> bool {
		sig.verify(msg, pubkey)
	}

	/// Verify WebAuthn ES256 signature.
	fn webauthn_recover(sig: &webauthn::Signature, msg: &[u8]) -> Option<[u8; 33]> {
		sig.recover(msg).map(|pubkey| pubkey.0)
	}

	/// Decompress secp256k1 public key.
	fn secp256k1_pubkey_serialize(pubkey: &[u8; 33]) -> Option<[u8; 64]> {
		ecdsa::secp256k1_pubkey_serialize(pubkey)
	}

	/// Verify a non-recoverable secp256k1 ECDSA signature (64 bytes).
	fn secp256k1_ecdsa_verify(sig: &[u8], msg: &[u8], pub_key: &[u8]) -> bool {
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
}

/// Interface that provides functions for hashing with different algorithms.
#[runtime_interface]
pub trait Hashing {
	/// Hash with ripemd160.
	fn ripemd160(data: &[u8]) -> [u8; 20] {
		np_crypto_hashing::ripemd160(data)
	}
}
