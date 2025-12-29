module tls13

import encoding.binary
import ecdhe

// TLS 1.3 NamedGroup
enum NamedGroup as u16 {
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

@[inline]
fn (g NamedGroup) packlen() int {
	return 2
}

@[inline]
fn (g NamedGroup) pack() ![]u8 {
	if u16(g) > max_u16 {
		return error('NamedGroup exceed limit')
	}
	mut out := []u8{len: 2}
	binary.big_endian_put_u16(mut out, u16(g))
	return out
}

@[direct_array_access; inline]
fn ngroup_parse(b []u8) !NamedGroup {
	if b.len != 2 {
		return error('bad NamedGroup data')
	}

	v := binary.big_endian_u16(b)
	return new_group(v)!
}

@[inline]
fn new_group(val u16) !NamedGroup {
	match val {
		0x0017 { return .secp256r1 }
		0x0018 { return .secp384r1 }
		0x0019 { return .secp521r1 }
		0x001D { return .x25519 }
		0x001E { return .x448 }
		0x0100 { return .ffdhe2048 }
		0x0101 { return .ffdhe3072 }
		0x0102 { return .ffdhe4096 }
		0x0103 { return .ffdhe6144 }
		0x0104 { return .ffdhe8192 }
		else { return error('unknown NamedGroup value') }
	}
}

// NamedGroupList = NamedGroup named_group_list<2..2^16-1>;
type NamedGroupList = []NamedGroup

// constant of namedgroup list size, in bytes
const min_nglist_size = 2
const max_nglist_size = max_u16

fn (mut gl NamedGroupList) append(g NamedGroup) {
	if g in gl {
		return
	}
	gl << g
}

fn (gl NamedGroupList) packlen() int {
	mut n := 0
	n += 2
	n += gl.len * 2 // length of NamedGroupList contents in bytes

	return n
}

fn (gl NamedGroupList) pack() ![]u8 {
	if gl.len < 1 {
		return error('Bad NamedGroupList length: underflow')
	}
	length := gl.len * 2
	if length > max_nglist_size {
		return error('Bad NamedGroupList length: overflow')
	}
	mut out := []u8{}

	mut bol := []u8{len: 2}
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
	mut r := Buffer.new(b)!

	// read length part
	len := r.read_u16()!
	bytes := r.read_at_least(int(len))!

	// read []NamedGroup contents
	mut ngl := NamedGroupList([]NamedGroup{})
	mut i := 0
	for i < bytes.len {
		buf := bytes[i..i + 2]
		g := ngroup_parse(buf)!
		ngl.append(g)
		i += 2
	}
	return ngl
}

fn (gl NamedGroupList) pack_to_extension() !Extension {
	payload := gl.pack()!
	ext := Extension{
		tipe:   .supported_groups
		length: payload.len
		data:   payload
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
//
fn (g NamedGroup) curve() !ecdhe.Curve {
	match g {
		// vfmt off
		.secp256r1 { return ecdhe.Curve.secp256r1 }
		.secp384r1 { return ecdhe.Curve.secp384r1 }
		.secp521r1 { return ecdhe.Curve.secp521r1 }
		.x25519 { return ecdhe.Curve.x25519 }
		.x448 { return ecdhe.Curve.x448 }
		.ffdhe2048 { return ecdhe.Curve.ffdhe2048 }
		.ffdhe3072 { return ecdhe.Curve.ffdhe3072 }
		.ffdhe4096 { return ecdhe.Curve.ffdhe4096 }
		.ffdhe6144 { return ecdhe.Curve.ffdhe6144 }
		.ffdhe8192 { return ecdhe.Curve.ffdhe8192 }
		// vfmt on
	}
}
