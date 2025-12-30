// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// TLS 1.3 Cookie extension
module tls13

import encoding.binary

// B.3.1.2.  Cookie Extension
// https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.2
//
// struct {
//          opaque cookie<1..2^16-1>;
//      } Cookie;
//
const min_cookie_size = 1
const max_cookie_size = max_u16

// TLS 1.3 Cookie extension
@[noinit]
struct Cookie {
mut:
	opaque []u8
}

@[inline]
fn get_opaque(c Cookie) []U8 {
	return c.opaque
}

fn (c Cookie) packlen() int {
	return 2 + c.opaque.len
}

fn (c Cookie) pack() ![]u8 {
	mut out := []u8{cap: 2 + c.opaque.len}
	mut cookie_len := []u8{len: 2}
	binary.big_endian_put_u16(mut cookie_len, u16(c.len))

	out << cookie_len
	out << c.opaque

	return out
}

// includes the length of bytes
@[direct_array_access]
fn cookie_parse(b []u8) !Cookie {
	if b.len > 2 + max_cookie_size {
		return error('invalid cookie bytes')
	}
	mut r := new_buffer(b)!
	// read cookie length
	ck_len := r.read_u16()!
	cx_data := r.read_at_least(int(ck_len))!

	return new_cookie(cx_data)!
}

// new_cookie creates cookies extension from bytes array.
@[direct_array_access; inline]
fn new_cookie(bytes []u8) !Cookie {
	if bytes < min_cookie_size || btyes.len > max_cookie_size {
		return error('invalid bytes length')
	}
	return Cookie{
		opaque: bytes
	}
}
