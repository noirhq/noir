// This file is part of Noir.

// Copyright (C) Haderech Pte. Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#![cfg(test)]

use super::{generic::tests::*, mock::*, *};
use frame_support::{assert_noop, assert_ok};
use sp_std::collections::btree_set::BTreeSet;

#[test]
fn link_works() {
	new_test_ext().execute_with(|| {
		let (caller, eth, cosm) = account();
		let aliases = BTreeSet::from_iter([eth.clone(), cosm.clone()])
			.try_into()
			.expect("aliases set; qed");
		assert_noop!(Alias::link(RuntimeOrigin::signed([0; 32].into())), Error::<Test>::LinkFailed);
		assert_ok!(Alias::link(RuntimeOrigin::signed(caller.clone())));
		assert_eq!(AccountIdOf::<Test>::get(&eth), Some(caller.clone()));
		assert_eq!(AccountIdOf::<Test>::get(&cosm), Some(caller.clone()));
		assert_eq!(AccountAliases::<Test>::get(&caller), Some(aliases));
	});
}

#[test]
fn unlink_works() {
	new_test_ext().execute_with(|| {
		let (caller, eth, cosm) = account();
		assert_ok!(Alias::link(RuntimeOrigin::signed(caller.clone())));
		assert_ok!(Alias::unlink(RuntimeOrigin::signed(caller.clone())));
		assert_eq!(AccountIdOf::<Test>::get(&eth), None);
		assert_eq!(AccountIdOf::<Test>::get(&cosm), None);
		assert_eq!(AccountAliases::<Test>::get(&caller), None);
	});
}
