module tls13

import encoding.binary
import ecdhe

// NamedGroupList = NamedGroup named_group_list<2..2^16-1>;
type NamedGroupList = []NamedGroup

// constant of namedgroup list size, in bytes
const min_nglist_size = 2
const max_nglist_size = max_u16

fn (mut gl []NamedGroup) append(g NamedGroup) {
	if g in gl {
		return
	}
	gl << g
}

fn (gl []NamedGroup) packlen() int {
	mut n := 0
	n += 2
	n += gl.len * 2 // length of []NamedGroup contents in bytes

	return n
}

fn (gl []NamedGroup) pack() ![]u8 {
	if gl.len < 1 {
		return error('Bad []NamedGroup length: underflow')
	}
	length := gl.len * 2
	if length > max_nglist_size {
		return error('Bad []NamedGroup length: overflow')
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

fn NamedGroupList.unpack(b []u8) ![]NamedGroup {
	if b.len < 4 {
		return error('Bad []NamedGroup: underflow')
	}
	mut r := Buffer.new(b)!

	// read length part
	len := r.read_u16()!
	bytes := r.read_at_least(int(len))!

	// read []NamedGroup contents
	mut ngl := []NamedGroup{}
	mut i := 0
	for i < bytes.len {
		buf := bytes[i..i + 2]
		g := ngroup_parse(buf)!
		ngl.append(g)
		i += 2
	}
	return ngl
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
