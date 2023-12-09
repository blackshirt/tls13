module tls13

import math
import arrays
import encoding.binary
import blackshirt.buffer

type ProtoVersion = u16

const u16size = 2
const tls_v13 = ProtoVersion(0x0304)
const tls_v12 = ProtoVersion(0x0303)
const tls_v11 = ProtoVersion(0x0302)
const tls_v10 = ProtoVersion(0x0301)

fn (v ProtoVersion) pack() ![]u8 {
	if int(v) > int(math.max_u16) {
		return error('ProtoVersion exceed limit')
	}
	mut out := []u8{len: tls13.u16size}
	binary.big_endian_put_u16(mut out, v)
	return out
}

fn (v ProtoVersion) packed_length() int {
	return tls13.u16size
}

// unpack deserializes bytes arrays to ProtoVersion
fn ProtoVersion.unpack(b []u8) !ProtoVersion {
	if b.len != 2 {
		return error('Bad ProtoVersion buffer len')
	}

	v := binary.big_endian_u16(b)
	return ProtoVersion(v)
}

fn ProtoVersion.from(val int) !ProtoVersion {
	if val > int(math.max_u16) {
		return error('Value exceed for ProtoVersion')
	}
	match val {
		0x0301 {
			return tls13.tls_v10
		}
		0x0302 {
			return tls13.tls_v11
		}
		0x0303 {
			return tls13.tls_v12
		}
		0x0304 {
			return tls13.tls_v13
		}
		else {
			return error('bad value')
		}
	}
}

fn (mut pvl []ProtoVersion) append(v ProtoVersion) {
	if v in pvl {
		return
	}
	pvl << v
}

fn (pvl []ProtoVersion) pack() ![]u8 {
	length := pvl.len * 2
	if length > math.max_u8 {
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

fn (pvl []ProtoVersion) packed_length() int {
	mut n := 0
	n += 1
	n += pvl.len * 2

	return n
}

type ProtocolVersionList = []ProtoVersion

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
	mut pv := []ProtoVersion{}
	for i < length {
		v := ProtoVersion.unpack(vers[i..i + 2])!
		pv.append(v)
		i += v.packed_length()
	}

	pvl := ProtocolVersionList(pv)
	return pvl
}

// Utility function
// sort does sorting of ProtoVersion arrays in descending order, from biggest to the lowest version.
fn (mut vls []ProtoVersion) sort() []ProtoVersion {
	vls.sort_with_compare(fn (v1 &ProtoVersion, v2 &ProtoVersion) int {
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

fn choose_supported_version(vls []ProtoVersion) !ProtoVersion {
	// choose the max version available in list
	// RFC mandates its in sorted form.
	max_ver := arrays.max(vls)!
	// we currently only support v1.3
	if max_ver != tls13.tls_v13 {
		return error('nothing version in list was supported')
	}
	return max_ver
}
