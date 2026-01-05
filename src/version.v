// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// TLS 1.3 Protocol version
module tls13

import arrays
import encoding.binary

// sort does sorting of Version arrays in descending order, from biggest to the lowest version.
@[direct_array_access]
fn (mut tv []Version) sort() []Version {
	tv.sort_with_compare(fn (v1 &Version, v2 &Version) int {
		if v1 < v2 {
			return 1
		}
		if v1 > v2 {
			return -1
		}
		return 0
	})
	return tv
}

// choose_supported_version chooses TLS 1.3 version from arrays of version in tv
@[direct_array_access]
fn choose_supported_version(tv []Version) !Version {
	// choose the max version available in list
	// RFC mandates its in sorted form.
	max_ver := arrays.max(tv)!
	// we currently only support v1.3
	if max_ver != .v13 {
		return error('nothing version in list was supported')
	}
	return max_ver
}
