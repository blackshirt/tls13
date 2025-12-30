// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// TLS 1.3 SignatureScheem
module tls13

import encoding.binary

// SignatureSchemeList is an array of SignatureScheme
type SignatureSchemeList = []SignatureScheme

// serialized array of SignatureScheme, includes prepended length
fn (sg []SignatureScheme) packlen() int {
	return 2 + sg.len * 2
}

// append adds s into sg
fn (mut sg []SignatureScheme) append(s SignatureScheme) {
	if s in sg {
		return
	}
	sg << s
}

// serializes sg into bytes array
fn (sg []SignatureScheme) pack() ![]u8 {
	// non-empty signature scheme was unallowed
	if sg.len < 1 {
		return error('SignatureSchemeList length: underflow')
	}
	length := sg.len * 2
	if length > max_u16 {
		return error("SignatureSchemeList length: overflow'")
	}

	mut out := []u8{cap: 2 + length}

	// write 2 byte length
	mut bol := []u8{len: 2}
	binary.big_endian_put_u16(mut bol, u16(length))
	out << bol

	// write SignatureScheme arrays
	for s in sg {
		out << s.pack()!
	}
	return res
}

// sigschemelist_parse parse bytes into array of SignatureScheme, includes the length part.
@[direct_array_access; inline]
fn sigschemelist_parse(b []u8) ![]SignatureScheme {
	// SignatureSchemeList supported_signature_algorithms<2..2^16-2>;
	// tells us that its should contain minimal one signature algorithm or more.
	if b.len < 4 {
		return error('negative len or unfullfilled minimal length')
	}
	mut r := new_buffer(b)!

	// read length part
	length := r.read_u16()!
	bytes := r.read_at_least(int(length))!

	return sigschemelist_from_bytes(bytes)!
}

// sigschemelist_from_bytes parses bytes into array of SignatureScheme, without the length part.
@[direct_array_access]
fn sigschemelist_from_bytes(bytes []u8) ![]SignatureScheme {
	if bytes.len % 2 != 0 {
		return error('even bytes length was needed')
	}
	mut sg := []SignatureScheme{}
	mut i := 0
	for i < bytes.len {
		s := sigscheme_parse(bytes[i..i + 2])!
		sg.append(s)
		i += 2
	}
	return sg
}
