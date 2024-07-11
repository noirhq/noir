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

//! Cryptography extensions for Noir.

#![cfg_attr(not(feature = "std"), no_std)]

mod crypto_bytes;

pub mod crypto;
pub mod ecdsa;
pub mod p256;
pub mod webauthn;

pub mod bitcoin;
pub mod cosmos;
pub mod ethereum;
pub mod multiformats;

pub use cosmos::CosmosAddress;
pub use ethereum::EthereumAddress;
