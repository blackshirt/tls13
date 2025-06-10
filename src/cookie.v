module tls13

import encoding.binary
import buffer

// B.3.1.2.  Cookie Extension
// https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.3.1.2
//
// struct {
//          opaque cookie<1..2^16-1>;
//      } Cookie;
type Cookie = []u8 // <1..2^16-1>;

const max_cookie_msg_size = max_u16

fn (c Cookie) packed_length() int {
	return 2 + c.len
}

fn (c Cookie) pack() ![]u8 {
	if c.len > max_cookie_msg_size {
		return error('Cookie msg overflow')
	}
	mut out := []u8{}
	mut cookie_len := []u8{len: 2}
	binary.big_endian_put_u16(mut cookie_len, u16(c.len))

	out << cookie_len
	out << c

	return out
}

fn Cookie.unpack(b []u8) !Cookie {
	if b.len < 1 {
		return error('Cookie bytes underflow')
	}
	mut r := buffer.new_reader(b)
	// read cookie length
	ck_len := r.read_u16()!
	cx_data := r.read_at_least(int(ck_len))!

	return Cookie(cx_data)
}
