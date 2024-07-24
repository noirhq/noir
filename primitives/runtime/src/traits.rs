// This file is part of Noir.

// Copyright (c) Haderech Pte. Ltd.
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

pub use sp_runtime::traits::{IdentifyAccount, Lazy};

/// Means of signature verification.
pub trait VerifyMut {
	/// Type of the signer.
	type Signer: IdentifyAccount;
	/// Verify a signature.
	///
	/// Return `true` if signature is valid for the value.
	fn verify_mut<L: Lazy<[u8]>>(
		&self,
		msg: L,
		signer: &mut <Self::Signer as IdentifyAccount>::AccountId,
	) -> bool;
}
