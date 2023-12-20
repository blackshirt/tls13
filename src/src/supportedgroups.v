module tls13

import math
import encoding.binary
import blackshirt.buffer
import blackshirt.ecdhe

// NamedGroup = u16
enum NamedGroup {
	secp256r1 = 0x0017
	secp384r1 = 0x0018
	secp521r1 = 0x0019
	x25519    = 0x001D
	x448      = 0x001E
	ffdhe2048 = 0x0100
	ffdhe3072 = 0x0101
	ffdhe4096 = 0x0102
	ffdhe6144 = 0x0103
	ffdhe8192 = 0x0104
}

fn (ng NamedGroup) packed_length() int {
	return u16size
}

fn (ng NamedGroup) pack() ![]u8 {
	if int(ng) > int(math.max_u16) {
		return error('NamedGroup exceed limit')
	}
	mut out := []u8{len: u16size}

	binary.big_endian_put_u16(mut out, u16(ng))
	return out
}

fn NamedGroup.unpack(b []u8) !NamedGroup {
	if b.len != 2 {
		return error('bad NamedGroup data')
	}

	v := binary.big_endian_u16(b)
	out := unsafe { NamedGroup(v) }
	return out
}

fn NamedGroup.from(val u16) !NamedGroup {
	match val {
		0x0017 { return NamedGroup.secp256r1 }
		0x0018 { return NamedGroup.secp384r1 }
		0x0019 { return NamedGroup.secp521r1 }
		0x001D { return NamedGroup.x25519 }
		0x001E { return NamedGroup.x448 }
		0x0100 { return NamedGroup.ffdhe2048 }
		0x0101 { return NamedGroup.ffdhe3072 }
		0x0102 { return NamedGroup.ffdhe4096 }
		0x0103 { return NamedGroup.ffdhe6144 }
		0x0104 { return NamedGroup.ffdhe8192 }
		else { return error('Unknown NamedGroup:${val}') }
	}
}

// NamedGroupList = NamedGroup named_group_list<2..2^16-1>;
type NamedGroupList = []NamedGroup

fn (mut gl NamedGroupList) append(g NamedGroup) {
	if g in gl {
		return
	}
	gl << g
}

fn (gl NamedGroupList) packed_length() int {
	mut n := 0
	n += 2
	n += gl.len * 2 // length of NamedGroupList contents in bytes

	return n
}

fn (gl NamedGroupList) pack() ![]u8 {
	if gl.len < 1 {
		return error('Bad NamedGroupList length: underflow')
	}
	length := gl.len * u16size
	if length > int(math.max_u16) {
		return error('Bad NamedGroupList length: overflow')
	}
	mut out := []u8{}

	mut bol := []u8{len: u16size}
	binary.big_endian_put_u16(mut bol, u16(length))
	out << bol

	// writes underlying namedgroup list
	for g in gl {
		item := g.pack()!
		out << item
	}
	return out
}

fn NamedGroupList.unpack(b []u8) !NamedGroupList {
	if b.len < 4 {
		return error('Bad NamedGroupList: underflow')
	}
	mut r := buffer.new_reader(b)

	// read length part
	len := r.read_u16()!
	if r.remainder() < int(len) {
		return error('remainder small than length')
	}
	bytes := r.read_at_least(len)!

	// read []NamedGroup contents
	mut ngl := NamedGroupList([]NamedGroup{})
	mut i := 0
	for i < bytes.len {
		buf := bytes[i..i + u16size]
		ng := NamedGroup.unpack(buf)!
		ngl.append(ng)
		i += u16size
	}
	return ngl
}

fn (gl NamedGroupList) pack_to_extension() !Extension {
	payload := gl.pack()!
	ext := Extension{
		tipe: .supported_groups
		length: payload.len
		data: payload
	}
	return ext
}

fn (gl NamedGroupList) pack_to_extension_bytes() ![]u8 {
	ext := gl.pack_to_extension()!
	out := ext.pack()!
	return out
}

fn NamedGroupList.unpack_from_extension_bytes(b []u8) !NamedGroupList {
	ext := Extension.unpack(b)!
	if ext.tipe != .supported_groups {
		return error('Wrong NamedGroupList extension type')
	}
	groups := NamedGroupList.unpack(ext.data)!

	return groups
}

// Utilify function
fn (g NamedGroup) curve() !ecdhe.Curve {
	match g {
		.secp256r1 {
			return ecdhe.Curve.secp256r1
		}
		.secp384r1 {
			return ecdhe.Curve.secp384r1
		}
		.secp521r1 {
			return ecdhe.Curve.secp521r1
		}
		.x25519 {
			return ecdhe.Curve.x25519
		}
		.x448 {
			return ecdhe.Curve.x448
		}
		.ffdhe2048 {
			return ecdhe.Curve.ffdhe2048
		}
		.ffdhe3072 {
			return ecdhe.Curve.ffdhe3072
		}
		.ffdhe4096 {
			return ecdhe.Curve.ffdhe4096
		}
		.ffdhe6144 {
			return ecdhe.Curve.ffdhe6144
		}
		.ffdhe8192 {
			return ecdhe.Curve.ffdhe8192
		}
	}
}
