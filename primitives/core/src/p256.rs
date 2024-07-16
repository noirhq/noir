// This file is part of Noir.

// Copyright (C) Haderech Pte. Ltd.
// Copyright (C) 2017-2022 Parity Technologies (UK) Ltd.
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

//! Simple ECDSA secp256r1 API.

use crate::crypto::{PublicBytes, SignatureBytes};

use ecdsa::RecoveryId;
use p256::{
	ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey},
	elliptic_curve::{scalar::IsHigh, sec1::ToEncodedPoint},
	PublicKey,
};
use sp_core::crypto::{
	ByteArray, CryptoType, CryptoTypeId, DeriveError, DeriveJunction, Pair as TraitPair,
	SecretStringError,
};
#[cfg(not(feature = "std"))]
use sp_std::vec::Vec;

/// An identifier used to match public keys against ecdsa P-256 keys
pub const CRYPTO_ID: CryptoTypeId = CryptoTypeId(*b"p256");

/// The byte length of public key
pub const PUBLIC_KEY_SERIALIZED_SIZE: usize = 33;

/// The byte length of signature
pub const SIGNATURE_SERIALIZED_SIZE: usize = 65;

#[doc(hidden)]
pub struct P256Tag;

/// The secret seed.
///
/// The raw secret seed, which can be used to create the `Pair`.
type Seed = [u8; 32];

/// The ECDSA compressed public key.
pub type Public = PublicBytes<PUBLIC_KEY_SERIALIZED_SIZE, P256Tag>;

impl Public {
	/// Create a new instance from the given full public key.
	///
	/// This will convert the full public key into the compressed format.
	pub fn from_full(full: &[u8]) -> Result<Self, ()> {
		let pubkey = if full.len() == 64 {
			let mut tagged_full = [0u8; 65];
			// Tag it as uncompressed public key.
			tagged_full[0] = 0x04;
			tagged_full[1..].copy_from_slice(full);
			PublicKey::from_sec1_bytes(&tagged_full)
		} else {
			PublicKey::from_sec1_bytes(full)
		};
		match pubkey {
			Ok(k) => Self::try_from(k.to_encoded_point(true).to_bytes().as_ref()),
			Err(..) => Err(()),
		}
	}
}

#[cfg(feature = "full_crypto")]
impl From<Pair> for Public {
	fn from(x: Pair) -> Self {
		x.public()
	}
}

/// A signature (a 512-bit value, plus 8 bits for recovery ID).
pub type Signature = SignatureBytes<SIGNATURE_SERIALIZED_SIZE, P256Tag>;

#[cfg(feature = "full_crypto")]
impl From<(EcdsaSignature, RecoveryId)> for Signature {
	fn from((sig, rid): (EcdsaSignature, RecoveryId)) -> Signature {
		let mut data = [0u8; SIGNATURE_SERIALIZED_SIZE];
		data[..64].copy_from_slice(&sig.to_bytes());
		data[64] = rid.to_byte();
		Signature::from_raw(data)
	}
}

impl Signature {
	/// A new instance from ASN.1 DER encoded bytes.
	/*
	#[cfg(feature = "std")]
	pub fn from_der(data: &[u8]) -> Option<Self> {
		match EcdsaSignature::from_der(data) {
			Ok(sig) => Some(Self(sig.to_bytes().into())),
			Err(..) => None,
		}
	}
	*/

	/// Recover the public key from this signature and a message.
	pub fn recover<M: AsRef<[u8]>>(&self, message: M) -> Option<Public> {
		self.recover_prehashed(&np_crypto_hashing::blake2_256(message.as_ref()))
	}

	/// Recover the public key from this signature and a pre-hashed message.
	pub fn recover_prehashed(&self, message: &[u8; 32]) -> Option<Public> {
		let rid = RecoveryId::from_byte(self.0[64])?;
		let sig = EcdsaSignature::from_bytes(self.0[..64].into()).ok()?;
		if sig.s().is_high().into() {
			return None
		}

		VerifyingKey::recover_from_prehash(&message[..], &sig, rid)
			.ok()
			.and_then(|pubkey| Public::from_slice(pubkey.to_encoded_point(true).as_bytes()).ok())
	}
}

/// Derive a single hard junction.
fn derive_hard_junction(secret_seed: &Seed, cc: &[u8; 32]) -> Seed {
	use parity_scale_codec::Encode;
	("Secp256r1HDKD", secret_seed, cc).using_encoded(np_crypto_hashing::blake2_256)
}

/// A key pair.
#[derive(Clone)]
pub struct Pair {
	public: Public,
	secret: SigningKey,
}

impl TraitPair for Pair {
	type Public = Public;
	type Seed = Seed;
	type Signature = Signature;

	/// Make a new key pair from secret seed material. The slice must be 32 bytes long or it
	/// will return `None`.
	///
	/// You should never need to use this; generate(), generate_with_phrase
	fn from_seed_slice(seed_slice: &[u8]) -> Result<Pair, SecretStringError> {
		let secret =
			SigningKey::from_slice(seed_slice).map_err(|_| SecretStringError::InvalidSeed)?;
		let public = PublicKey::from(secret.verifying_key());
		let public = Public::from_slice(public.to_encoded_point(true).as_bytes()).unwrap();
		Ok(Pair { public, secret })
	}

	/// Derive a child key from a series of given junctions.
	fn derive<Iter: Iterator<Item = DeriveJunction>>(
		&self,
		path: Iter,
		_seed: Option<Seed>,
	) -> Result<(Pair, Option<Seed>), DeriveError> {
		let mut acc = self.seed();
		for j in path {
			match j {
				DeriveJunction::Soft(_cc) => return Err(DeriveError::SoftKeyInPath),
				DeriveJunction::Hard(cc) => acc = derive_hard_junction(&acc, &cc),
			}
		}
		Ok((Self::from_seed(&acc), Some(acc)))
	}

	/// Get the public key.
	fn public(&self) -> Public {
		self.public
	}

	/// Sign a message.
	#[cfg(feature = "full_crypto")]
	fn sign(&self, message: &[u8]) -> Signature {
		self.sign_prehashed(&np_crypto_hashing::blake2_256(message))
	}

	/// Verify a signature on a message. Returns true if the signature is good.
	fn verify<M: AsRef<[u8]>>(sig: &Signature, message: M, public: &Public) -> bool {
		sig.recover(message).map(|actual| actual == *public).unwrap_or_default()
	}

	/// Return a vec filled with raw data.
	fn to_raw_vec(&self) -> Vec<u8> {
		self.seed().to_vec()
	}
}

impl Pair {
	/// Get the seed for this key.
	pub fn seed(&self) -> Seed {
		Seed::from(self.secret.to_bytes())
	}

	/// Sign a pre-hashed message
	#[cfg(feature = "full_crypto")]
	pub fn sign_prehashed(&self, message: &[u8; 32]) -> Signature {
		let (mut sig, mut rid) = self.secret.sign_prehash_recoverable(message).unwrap();
		if sig.s().is_high().into() {
			sig = sig.normalize_s().unwrap();
			rid = RecoveryId::from_byte(rid.to_byte() ^ 1).unwrap();
		}
		Signature::from((sig, rid))
	}

	/// Verify a signature on a pre-hashed message. Return `true` if the signature is valid
	/// and thus matches the given `public` key.
	pub fn verify_prehashed(sig: &Signature, message: &[u8; 32], pubkey: &Public) -> bool {
		match sig.recover_prehashed(message) {
			Some(actual) => actual == *pubkey,
			None => false,
		}
	}
}

impl CryptoType for Public {
	type Pair = Pair;
}

impl CryptoType for Signature {
	type Pair = Pair;
}

impl CryptoType for Pair {
	type Pair = Pair;
}

#[cfg(test)]
mod tests {
	use super::*;
	use sp_core::crypto::{
		set_default_ss58_version, PublicError, Ss58AddressFormat, Ss58AddressFormatRegistry,
		Ss58Codec, DEV_PHRASE,
	};

	#[test]
	fn default_phrase_should_be_used() {
		assert_eq!(
			Pair::from_string("//Alice///password", None).unwrap().public(),
			Pair::from_string(&format!("{}//Alice", DEV_PHRASE), Some("password"))
				.unwrap()
				.public(),
		);
	}

	#[test]
	fn seed_and_derive_should_work() {
		let seed = array_bytes::hex2array_unchecked(
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		);
		let pair = Pair::from_seed(&seed);
		assert_eq!(pair.seed(), seed);
		let path = vec![DeriveJunction::Hard([0u8; 32])];
		let derived = pair.derive(path.into_iter(), None).ok().unwrap();
		assert_eq!(
			derived.0.seed(),
			array_bytes::hex2array_unchecked(
				"7ef571a7bc8f2e0c4b641e30d55018a6058b6003506967150fcc4349c1af4cbb"
			)
		);
	}

	#[test]
	fn test_vector_should_work() {
		let pair = Pair::from_seed(&array_bytes::hex2array_unchecked(
			"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
		));
		let public = pair.public();
		assert_eq!(
			public,
			Public::from_full(
				&array_bytes::hex2bytes_unchecked("667fef5f7578a801037ed144092dcf7c7c44e3bf3e09cfc8a67fcf70fcd8123a3a29739e598824b33aef8068c6057a2f9fa1661253f1ea799e6ef7ce89a00438"),
			).unwrap(),
		);
		let message = b"";
		let signature = array_bytes::hex2array_unchecked("97a98171d9c2ba5a566f51c246ba8390b817d8664d00eb9edace9e042f26e333433bafa6a9ac4ed52a4b68d429ad95a447fa6157ad76bef561cbe76f498c00c000");
		let signature = Signature::from_raw(signature);
		assert!(pair.sign(&message[..]) == signature);
		assert!(Pair::verify(&signature, &message[..], &public));
	}

	#[test]
	fn test_vector_by_string_should_work() {
		let pair = Pair::from_string(
			"0x9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
			None,
		)
		.unwrap();
		let public = pair.public();
		assert_eq!(
			public,
			Public::from_full(
				&array_bytes::hex2bytes_unchecked("667fef5f7578a801037ed144092dcf7c7c44e3bf3e09cfc8a67fcf70fcd8123a3a29739e598824b33aef8068c6057a2f9fa1661253f1ea799e6ef7ce89a00438"),
			).unwrap(),
		);
		let message = b"";
		let signature = array_bytes::hex2array_unchecked("97a98171d9c2ba5a566f51c246ba8390b817d8664d00eb9edace9e042f26e333433bafa6a9ac4ed52a4b68d429ad95a447fa6157ad76bef561cbe76f498c00c000");
		let signature = Signature::from_raw(signature);
		assert!(pair.sign(&message[..]) == signature);
		assert!(Pair::verify(&signature, &message[..], &public));
	}

	#[test]
	fn generated_pair_should_work() {
		let (pair, _) = Pair::generate();
		let public = pair.public();
		let message = b"Something important";
		let signature = pair.sign(&message[..]);
		assert!(Pair::verify(&signature, &message[..], &public));
		assert!(!Pair::verify(&signature, b"Something else", &public));
	}

	#[test]
	fn seeded_pair_should_work() {
		let pair = Pair::from_seed(b"12345678901234567890123456789012");
		let public = pair.public();
		assert_eq!(
			public,
			Public::from_full(
				&array_bytes::hex2bytes_unchecked("6223e55c8ab75407c630ca15cc0281db060bcb47b99fd9d89239806c1088741b7763fc4f252598cd63a29d72507f9f1c161781b8a3174218e1f3c0edb419b831"),
			).unwrap(),
		);
		let message = array_bytes::hex2bytes_unchecked("2f8c6129d816cf51c374bc7f08c3e63ed156cf78aefb4a6550d97b87997977ee00000000000000000200d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a4500000000000000");
		let signature = pair.sign(&message[..]);
		println!("Correct signature: {:?}", signature);
		assert!(Pair::verify(&signature, &message[..], &public));
		assert!(!Pair::verify(&signature, "Other message", &public));
	}

	#[test]
	fn generate_with_phrase_recovery_possible() {
		let (pair1, phrase, _) = Pair::generate_with_phrase(None);
		let (pair2, _) = Pair::from_phrase(&phrase, None).unwrap();

		assert_eq!(pair1.public(), pair2.public());
	}

	#[test]
	fn generate_with_password_phrase_recovery_possible() {
		let (pair1, phrase, _) = Pair::generate_with_phrase(Some("password"));
		let (pair2, _) = Pair::from_phrase(&phrase, Some("password")).unwrap();

		assert_eq!(pair1.public(), pair2.public());
	}

	#[test]
	fn generate_with_phrase_should_be_recoverable_with_from_string() {
		let (pair, phrase, seed) = Pair::generate_with_phrase(None);
		let repair_seed = Pair::from_seed_slice(seed.as_ref()).expect("seed slice is valid");
		assert_eq!(pair.public(), repair_seed.public());
		assert_eq!(pair.secret, repair_seed.secret);
		let (repair_phrase, reseed) =
			Pair::from_phrase(phrase.as_ref(), None).expect("seed slice is valid");
		assert_eq!(seed, reseed);
		assert_eq!(pair.public(), repair_phrase.public());
		assert_eq!(pair.secret, repair_phrase.secret);
		let repair_string = Pair::from_string(phrase.as_str(), None).expect("seed slice is valid");
		assert_eq!(pair.public(), repair_string.public());
		assert_eq!(pair.secret, repair_string.secret);
	}

	#[test]
	fn password_does_something() {
		let (pair1, phrase, _) = Pair::generate_with_phrase(Some("password"));
		let (pair2, _) = Pair::from_phrase(&phrase, None).unwrap();

		assert_ne!(pair1.public(), pair2.public());
		assert_ne!(pair1.secret, pair2.secret);
	}

	#[test]
	fn ss58check_roundtrip_works() {
		let pair = Pair::from_seed(b"12345678901234567890123456789012");
		let public = pair.public();
		let s = public.to_ss58check();
		println!("Correct: {}", s);
		let cmp = Public::from_ss58check(&s).unwrap();
		assert_eq!(cmp, public);
	}

	#[test]
	fn ss58check_format_check_works() {
		let pair = Pair::from_seed(b"12345678901234567890123456789012");
		let public = pair.public();
		let format = Ss58AddressFormatRegistry::Reserved46Account.into();
		let s = public.to_ss58check_with_version(format);
		assert_eq!(Public::from_ss58check_with_version(&s), Err(PublicError::FormatNotAllowed));
	}

	#[test]
	fn ss58check_full_roundtrip_works() {
		let pair = Pair::from_seed(b"12345678901234567890123456789012");
		let public = pair.public();
		let format = Ss58AddressFormatRegistry::PolkadotAccount.into();
		let s = public.to_ss58check_with_version(format);
		let (k, f) = Public::from_ss58check_with_version(&s).unwrap();
		assert_eq!(k, public);
		assert_eq!(f, format);

		let format = Ss58AddressFormat::custom(64);
		let s = public.to_ss58check_with_version(format);
		let (k, f) = Public::from_ss58check_with_version(&s).unwrap();
		assert_eq!(k, public);
		assert_eq!(f, format);
	}

	#[test]
	fn ss58check_custom_format_works() {
		// We need to run this test in its own process to not interfere with other tests running in
		// parallel and also relying on the ss58 version.
		if std::env::var("RUN_CUSTOM_FORMAT_TEST") == Ok("1".into()) {
			use sp_core::crypto::Ss58AddressFormat;
			// temp save default format version
			let default_format = sp_core::crypto::default_ss58_version();
			// set current ss58 version is custom "200" `Ss58AddressFormat::Custom(200)`

			set_default_ss58_version(Ss58AddressFormat::custom(200));
			// custom addr encoded by version 200
			let addr = "4pbsSkWcBaYoFHrKJZp5fDVUKbqSYD9dhZZGvpp3vQ5ysVs5ybV";
			Public::from_ss58check(addr).unwrap();

			set_default_ss58_version(default_format);
			// set current ss58 version to default version
			let addr = "KWAfgC2aRG5UVD6CpbPQXCx4YZZUhvWqqAJE6qcYc9Rtr6g5C";
			Public::from_ss58check(addr).unwrap();

			println!("CUSTOM_FORMAT_SUCCESSFUL");
		} else {
			let executable = std::env::current_exe().unwrap();
			let output = std::process::Command::new(executable)
				.env("RUN_CUSTOM_FORMAT_TEST", "1")
				.args(&["--nocapture", "ss58check_custom_format_works"])
				.output()
				.unwrap();

			let output = String::from_utf8(output.stdout).unwrap();
			assert!(output.contains("CUSTOM_FORMAT_SUCCESSFUL"));
		}
	}

	#[test]
	fn signature_serialization_works() {
		let pair = Pair::from_seed(b"12345678901234567890123456789012");
		let message = b"Something important";
		let signature = pair.sign(&message[..]);
		let serialized_signature = serde_json::to_string(&signature).unwrap();
		// Signature is 65 bytes, so 130 chars + 2 quote chars
		assert_eq!(serialized_signature.len(), SIGNATURE_SERIALIZED_SIZE * 2 + 2);
		let signature = serde_json::from_str(&serialized_signature).unwrap();
		assert!(Pair::verify(&signature, &message[..], &pair.public()));
	}

	#[test]
	fn signature_serialization_doesnt_panic() {
		fn deserialize_signature(text: &str) -> Result<Signature, serde_json::error::Error> {
			serde_json::from_str(text)
		}
		assert!(deserialize_signature("Not valid json.").is_err());
		assert!(deserialize_signature("\"Not an actual signature.\"").is_err());
		// Poorly-sized
		assert!(deserialize_signature("\"abc123\"").is_err());
	}

	#[test]
	fn sign_prehashed_works() {
		let (pair, _, _) = Pair::generate_with_phrase(Some("password"));

		// `msg` shouldn't be mangled
		let msg = [0u8; 32];
		let sig1 = pair.sign_prehashed(&msg);
		let sig2: Signature = {
			let (mut sig, mut rid) = pair.secret.sign_prehash_recoverable(&msg).unwrap();
			if sig.s().is_high().into() {
				sig = sig.normalize_s().unwrap();
				rid = RecoveryId::from_byte(rid.to_byte() ^ 1).unwrap();
			}
			Signature::from((sig, rid))
		};
		assert_eq!(sig1, sig2);

		// signature is actually different
		let sig2 = pair.sign(&msg);
		assert_ne!(sig1, sig2);

		// using pre-hashed `msg` works
		let msg = b"this should be hashed";
		let sig1 = pair.sign_prehashed(&np_crypto_hashing::blake2_256(msg));
		let sig2 = pair.sign(msg);
		assert_eq!(sig1, sig2);
	}

	#[test]
	fn verify_prehashed_works() {
		let (pair, _, _) = Pair::generate_with_phrase(Some("password"));

		// `msg` and `sig` match
		let msg = np_crypto_hashing::blake2_256(b"this should be hashed");
		let sig = pair.sign_prehashed(&msg);
		assert!(Pair::verify_prehashed(&sig, &msg, &pair.public()));

		// `msg` and `sig` don't match
		let msg = np_crypto_hashing::blake2_256(b"this is a different message");
		assert!(!Pair::verify_prehashed(&sig, &msg, &pair.public()));
	}

	#[test]
	fn recover_prehashed_works() {
		let (pair, _, _) = Pair::generate_with_phrase(Some("password"));

		// recovered key matches signing key
		let msg = np_crypto_hashing::blake2_256(b"this should be hashed");
		let sig = pair.sign_prehashed(&msg);
		let key = sig.recover_prehashed(&msg).unwrap();
		assert_eq!(pair.public(), key);

		// recovered key is useable
		assert!(Pair::verify_prehashed(&sig, &msg, &key));

		// recovered key and signing key don't match
		let msg = np_crypto_hashing::blake2_256(b"this is a different message");
		let key = sig.recover_prehashed(&msg).unwrap();
		assert_ne!(pair.public(), key);
	}
}
