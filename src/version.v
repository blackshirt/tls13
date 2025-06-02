module tls13

import arrays
import encoding.binary
import blackshirt.buffer

// uint16 ProtocolVersion;
type ProtocolVersion = u16

const u16size = 2

// vfmt off
const tls_v13 = ProtocolVersion(0x0304)
const tls_v12 = ProtocolVersion(0x0303)
const tls_v11 = ProtocolVersion(0x0302)
const tls_v10 = ProtocolVersion(0x0301)
// vfmt on

// pack serializes ProtocolVersion into bytes array.
fn (v ProtocolVersion) pack() ![]u8 {
	if v > max_u16 {
		return error('ProtocolVersion exceed limit')
	}
	mut out := []u8{len: u16size}
	binary.big_endian_put_u16(mut out, v)
	return out
}

fn (v ProtocolVersion) packed_length() int {
	return u16size
}

// unpack deserializes bytes array into ProtocolVersion
fn ProtocolVersion.unpack(b []u8) !ProtocolVersion {
	if b.len != u16size {
		return error('Bad ProtocolVersion buffer len')
	}
	v := binary.big_endian_u16(b)
	return ProtocolVersion.from_u16(v)!
}

fn ProtocolVersion.from_u16(val u16) !ProtocolVersion {
	if val <= u16(0) || val > max_u16 {
		return error('Bad values for ProtocolVersion')
	}
	match val {
		// vfmt off
		u16(0x0301) { return tls_v10 }
		u16(0x0302) { return tls_v11 }
		u16(0x0303) { return tls_v12 }
		u16(0x0304) { return tls_v13 }
		else {
			return error('unsupported ProtocolVersion value')
		}
		// vfmt on
	}
}

fn (mut pvl []ProtocolVersion) append(v ProtocolVersion) {
	if v in pvl {
		return
	}
	pvl << v
}

fn (pvl []ProtocolVersion) pack() ![]u8 {
	length := pvl.len * 2
	if length > max_u8 {
		return error('bad length')
	}
	mut out := []u8{}
	out << u8(length)

	for v in pvl {
		o := v.pack()!
		out << o
	}

	return out
}

fn (pvl []ProtocolVersion) packed_length() int {
	mut n := 0
	n += 1
	n += pvl.len * 2

	return n
}

type ProtocolVersionList = []ProtocolVersion

fn ProtocolVersionList.unpack(b []u8) !ProtocolVersionList {
	if b.len < 1 {
		return error('Bad ProtocolVersionList length')
	}
	mut r := buffer.new_reader(b)
	length := r.read_byte()!
	vers := r.read_at_least(int(length))!

	if vers.len % 2 != 0 {
		return error('ProtocolVersionList length tidak genap')
	}
	mut i := 0
	mut pv := []ProtocolVersion{}
	for i < length {
		v := ProtocolVersion.unpack(vers[i..i + 2])!
		pv.append(v)
		i += v.packed_length()
	}

	pvl := ProtocolVersionList(pv)
	return pvl
}

// Utility function
//
// sort does sorting of ProtocolVersion arrays in descending order, from biggest to the lowest version.
fn (mut vls []ProtocolVersion) sort() []ProtocolVersion {
	vls.sort_with_compare(fn (v1 &ProtocolVersion, v2 &ProtocolVersion) int {
		if v1 < v2 {
			return 1
		}
		if v1 > v2 {
			return -1
		}
		return 0
	})
	return vls
}

fn choose_supported_version(vls []ProtocolVersion) !ProtocolVersion {
	// choose the max version available in list
	// RFC mandates its in sorted form.
	max_ver := arrays.max(vls)!
	// we currently only support v1.3
	if max_ver != tls_v13 {
		return error('nothing version in list was supported')
	}
	return max_ver
}
