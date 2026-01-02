// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// TLS 1.3 Protocol version
module tls13

import arrays
import encoding.binary

// maximum size of arrays of TLS version, ie, 255
const max_tlversionlist_size = max_u8
const min_tlsversionlist_size = 1

// TLS 1.3 ProtocolVersion;
//
// This document describes TLS 1.3, which uses the version 0x0304.
// This version value is historical, deriving from the use of 0x0301 for TLS 1.0 and 0x0300 for SSL 3.0.
// In order to maximize backward compatibility, a record containing an initial ClientHello SHOULD have
// version 0x0301 (reflecting TLS 1.0) and a record containing a second
// ClientHello or a ServerHello MUST have version 0x0303 (reflecting TLS 1.2).
type Version = u16

const tls_v13 = Version(0x0304)
const tls_v12 = Version(0x0303)
const tls_v11 = Version(0x0302)
const tls_v10 = Version(0x0301)
const tls_v00 = Version(0x0300)

// str represents TLS version as a common name string
fn (v Version) str() string {
	match v {
		0x0304 { return 'TLS 1.3' }
		0x0303 { return 'TLS 1.2' }
		0x0302 { return 'TLS 1.1' }
		0x0301 { return 'TLS 1.0' }
		0x0300 { return 'SSL 3.0' } // TLS 0.0
		else { panic('unsupported version') }
	}
}

// pack serializes version into bytes array.
@[inline]
fn (v Version) pack() ![]u8 {
	mut out := []u8{len: 2}
	binary.big_endian_put_u16(mut out, v)
	return out
}

// tlsversion_parse parses (deserializes) bytes array into Version
@[direct_array_access; inline]
fn tlsversion_parse(b []u8) !Version {
	if b.len != 2 {
		return error('Bad Version buffer len')
	}
	v := binary.big_endian_u16(b)
	return new_tlsversion(v)!
}

// new_tlsversion creates TLS version from u16 value
@[inline]
fn new_tlsversion(val u16) !Version {
	match val {
		u16(0x0300) {
			return tls_v00
		}
		u16(0x0301) {
			return tls_v10
		}
		u16(0x0302) {
			return tls_v11
		}
		u16(0x0303) {
			return tls_v12
		}
		u16(0x0304) {
			return tls_v13
		}
		else {
			return error('unsupported Version value')
		}
	}
}

// TlsVersionList is an array of TLS version
type TlsVersionList = []Version

// packlen returns the length of serialized array of version
fn (tv []Version) packlen() int {
	return 1 + 2 * tv.len
}

// append adds version v into array of TLS version tv.
@[direct_array_access]
fn (mut tv []Version) append(v Version) {
	// if v is already on the list, do nothing
	if v in tv {
		return
	}
	tv << v
}

// pack encodes array of TLS version into bytes array.
@[inline]
fn (tv []Version) pack() ![]u8 {
	// the length of this version array should not exceed 255-item
	length := tv.len * 2
	if length > max_tlversionlist_size {
		return error('bad []Version length')
	}
	// output capacity = 1-byte length + the length itself.
	mut out := []u8{cap: 1 + length}

	// serializes the length of the array
	out << u8(length)
	// serializes every version item
	for v in tv {
		out << v.pack()!
	}

	return out
}

// tlsverlist_parse parses bytes into array of TLS version.
// includes parses the length
@[direct_array_access; inline]
fn tlsverlist_parse(b []u8) ![]Version {
	if b.len < 2 {
		return error('Bad TlsVersionList length')
	}
	mut r := new_buffer(b)!
	length := r.read_u8()!
	vers := r.read_at_least(int(length))!

	return tlsverlist_from_bytes(vers)!
}

// tlsverlist_from_bytes creates array of version from bytes array.
// The bytes length should be even
@[direct_array_access; inline]
fn tlsverlist_from_bytes(bytes []u8) ![]Version {
	// the single version was 2-bytes length, so its must have even length
	if bytes.len % 2 != 0 {
		return error('TlsVersionList length tidak genap')
	}
	mut i := 0
	mut pv := []Version{cap: bytes.len / 2}
	for i < length {
		v := tlsversion_parse(bytes[i..i + 2])!
		pv.append(v)
		i += v.packlen()
	}

	return pv
}

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
	if max_ver != tls_v13 {
		return error('nothing version in list was supported')
	}
	return max_ver
}
