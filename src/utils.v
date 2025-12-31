// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Utility helpers used across module
module tls13

import encoding.binary

// 1. Helpers for u8-size opaques.
//
// Some of TLS 1.3 structures types, like ContentType, HandshakeType,  NameType, etc mostly was u8-size opaque.
// This type of opaque commonly defined as `type SomeOpaque = u8`

// pack_u8list encodes array of u8-sized opaque in ts into bytes array.
@[direct_array_access; inline]
fn pack_u8list[T](ts []T) []u8 {
	mut out := []u8{cap: ts.len}
	for item in ts {
		out << u8(item)
	}
	return out
}

// pack_u8list_withlen encodes array of u8-sized opaque in ts into bytes array
// prepended with their length specified in n.
@[direct_array_access]
fn pack_u8list_withlen[T](ts []T, n int) ![]u8 {
	c := cap_u8list[T](ts, n)
	mut out := []u8{cap: c}
	match n {
		1 {
			if ts.len > max_u8 {
				return error('exceed max_u8')
			}
			out << u8(ts.len)
		}
		2 {
			if ts.len > max_u16 {
				return error('exceed max_u16')
			}
			out << pack_u16item[int](ts.len)
		}
		else {
			return error('unsupported length')
		}
	}
	out << pack_u8list[T](ts)
	return out
}

// parse_u8item decodes first bytes as T
@[direct_array_access]
fn parse_u8item[T](bytes []8, cb_make fn (u8) !T) !T {
	if bytes.len < 1 {
		return error('need more bytes')
	}
	value := bytes[0]
	return cb_make(value)!
}

// cap_u8list gets the capacities needed with specified length for ts.
@[direct_array_access; inline]
fn cap_u8list[T](ts []T, n int) int {
	match n {
		1 { return 1 + ts.len }
		2 { return 2 + ts.len }
		else { panic('invalid length') }
	}
}

// 2. Helpers for u16-sized opaque.
//
// Some opaques, like TLS 1.3 NamedGroup, CipherSuite, Version etc was u16-sized entity.
// This module contains some helpers in the mean of serializer (and deserializer) for that
// entities. It will panic if entity was non u16-sized opaque.
// Its also contains another utilities.
// This type of opaque commonly defined as `type SomeOpaque = u16`

// pack_u16item encodes an u16-sized item T into bytes array.
@[inline]
fn pack_u16item[T](t T) []u8 {
	mut out := []u8{len: 2}
	// we directly translated T into u16 type.
	// TODO: add support for another u16-construct with callback
	binary.big_endian_put_u16(mut out, u16(t))
	return out
}

// pack_u16list encodes arrays of u16-sized opaque T in ts into bytes array.
@[direct_array_access]
fn pack_u16list[T](ts []T) []u8 {
	mut out := []u8{cap: 2 * t.len}
	for t in ts {
		x := pack_u16item[T](t)
		out << x
	}
	return out
}

// pack_u16list_withlen encodes the array of item T in ts prepended with n-byte(s) length into bytes array.
// Its only supports with 1 or 2 bytes-length, otherwise returns an error.
@[direct_array_access]
fn pack_u16list_withlen[T](ts []T, n int) ![]u8 {
	// get the bytes capacities for the output length
	c := cap_u16list_withlen[T](ts, n)
	mut out := []u8{cap: c}
	match n {
		1 {
			// check the arrays length
			if ts.len > max_u8 {
				return error('length exceed max_u8')
			}
			// appends one-byte length into output
			out << u8(ts.len)
		}
		2 {
			// check the arrays length
			if 2 * ts.len > max_u16 {
				return error('length exceed max_u16')
			}
			// serializes two-bytes length into output
			out << pack_u16item[int](2 * ts.len)
		}
		else {
			return error('unsupported length')
		}
	}
	// serializes the items
	out << pack_u16list[T](ts)

	return out
}

// pack_u16len returns the length of serialized u16-sized opaque T.
@[inline]
fn pack_u16len[T](t T) int {
	return 2
}

// append_u16item adds an item into arrays of item ts.
@[direct_array_access]
fn append_u16item[T](mut ts []T, item T) {
	// if item already on there, do nothing
	if item in ts {
		return
	}
	ts << item
}

// parse_u16item decodes bytes into T with cb_make was a constructor of T from u16 value.
@[inline]
fn parse_u16item[T](bytes []u8, cb_make fn (u16) !T) !T {
	if bytes.len != 2 {
		return error('bad bytes.len for u16-opaque')
	}
	v := binary.big_endian_u16(bytes)
	return cb_make(v)!
}

// parse_u16list decodes bytes into arrays of item T with cb_make was a constructor of T from u16 value.
// Its done without parsing the prepended length.
@[inline]
fn parse_u16list[T](bytes []u8, cb_make fn (u16) !T) ![]T {
	if bytes.len % 2 != 0 {
		return error('even bytes length was needed')
	}
	mut items := []T{cap: bytes.len / 2}
	mut i := 0
	for i < bytes.len {
		item := parse_u16item[T](bytes[i..i + 2], cb_make)!
		append_u16item[T](mut items, item)
		i += 2
	}
	return items
}

// parse_u16list_withlen decodes bytes into arrays of item T with cb_make was a constructor of T from u16 value.
// Its also parsing prepended length of array of item.
@[direct_array_access]
fn parse_u16list_withlen[T](bytes []u8, cb_make fn (u16) !T, n int) ![]T {
	mut r := new_buffer(bytes)!

	// gets the length part, its only supports 1 or 2 bytes-length
	mut length := 0
	match n {
		1 { length = int(r.read_u8()!) }
		2 { length = int(r.read_u16()!) }
		else { return error('unsupported length') }
	}
	src := r.read_at_least(length)!

	return parse_u16list[T](src, cb_make)!
}

// cap_u16list_withlen tells the length of capacities needed to serialize the list ts with prepended n-bytes length
@[inline]
fn cap_u16list_withlen[T](ts []T, n int) int {
	match n {
		1 { return 1 + 2 * ts.len }
		2 { return 2 + 2 * ts.len }
		else { panic('unsupported length') }
	}
}

// 3. Raw-bytes opaque, ie, []u8  helpers
//
// Some TLS 1.3 likes Cookie extension, Hostname , key exchange payload was defined as raw bytes
// limited by some length.
// This type of opaque commonly defined as `type SomeOpaque = []u8`

@[direct_array_access; inline]
fn pack_raw_withlen(r []u8, n int) ![]u8 {
	mut out := []u8{cap: packlen_raw(r, n)}
	match n {
		1 {
			if r.len > max_u8 {
				return error('exceed max_u8')
			}
			out << u8(r.len)
		}
		2 {
			if r.len > max_u16 {
				return error('exceed max_u16')
			}
			out << pack_u16item[int](r.len)
		}
		3 {
			if r.len > max_u24 {
				return error('exceed max_u24')
			}
			bol3 := u24_from_int(r.len)!
			out << bol3.bytes()!
		}
		else {
			return error('invalid length')
		}
	}
	// get the raw bytes item, and append into output
	out << r

	return out
}

// packlen_raw tells needed capacities of serializes r prepended with n-bytes length.
@[inline]
fn packlen_raw(r []u8, n int) int {
	match n {
		1 { return r.len + 1 }
		2 { return r.len + 2 }
		3 { return r.len + 3 }
		else { panic('unsupported length') }
	}
}

// 4. Helpers for an opaque with 24-bits size
//
const max_u24 = 1 << 24 - 1 // 0x00FF_FFFF
const mask_u24 = u32(0x00FF_FFFF)

// Uint24 was a simple type of 24-length unsigned integer to represent handshake message length.
// Its represented as u32 value and by default serialized in big-endian order.
@[noinit]
struct Uint24 {
mut:
	// masked underlying u32 value
	value u32
}

// An option for reading Uint24
@[params]
struct Uint24Options {
pub mut:
	endian u8 // 0 = big, 1 = little
}

// u24_from_u32 creates Uint24 from u32 values.
@[inline]
fn u24_from_u32(val u32) !Uint24 {
	if val > max_u24 {
		return error('u24_from_u32: exceed value provided')
	}
	return Uint24{
		value: val & mask_u24
	}
}

// u24_from_int creates Uint24 from int value.
@[inline]
fn u24_from_int(val int) !Uint24 {
	if val < 0 || val > max_u24 {
		return error('u24_from_int: out of range value')
	}
	return Uint24{
		value: val & mask_u24
	}
}

// u24_from_bytes creates Uint24 from arrays of 3-bytes values.
@[direct_array_access]
fn u24_from_bytes(b []u8, opt Uint24Options) !Uint24 {
	if b.len != 3 {
		return error('u24_from_bytes: bad length')
	}
	// big-endian form
	val := u32(b[2]) | (u32(b[1]) << u32(8)) | (u32(b[0]) << u32(16))

	// Its should never happen
	if val > max_u24 {
		return error('u24_from_bytes: exceed value')
	}
	return Uint24{
		value: val & mask_u24
	}
}

// bytes serializes Uint24 as a bytes array.
fn (v Uint24) bytes(opt Uint24Options) ![]u8 {
	mut b := []u8{len: 3}
	match opt.endian {
		0x00 {
			b[0] = u8(v >> u32(16))
			b[1] = u8(v >> u32(8))
			b[2] = u8(v)
			return b
		}
		0x01 {
			b[0] = u8(v)
			b[1] = u8(v >> u32(8))
			b[2] = u8(v >> u32(16))
			return b
		}
		else {
			return error('Unsupported endian format')
		}
	}
}

// 5. Simple bytes reader
//
// Buffer was a simple and general purposes bytes reader
//
const max_buffer_size = max_i64

@[noinit]
struct Buffer {
	// read only buffer of underlying data being wrapped
	buf []u8
mut:
	// current offset
	off i64
}

@[params]
struct BufferOptions {
}

// An option for reading the buffer.
@[params]
struct ReadBufferOpts {
mut:
	update_offset bool
}

// new creates a new Buffer from non-null length of bytes b.
@[direct_array_access; inline]
fn new_buffer(b []u8, opt BufferOptions) !Buffer {
	if b.len == 0 {
		return error('new_buffer: unallowed null-length bytes')
	}
	return Buffer{
		buf: b // we dont touch the buffer directly
	}
}

// offset returns current offset within buffer
fn (b Buffer) offset() i64 {
	return b.off
}

// seek_byte seeks one byte from buffer at current offset.
// When you set update_offset into true, its increases current offset by 1 value
@[direct_array_access; inline]
fn (mut b Buffer) seek_byte(opt ReadBufferOpts) !u8 {
	// there are remaining bytes to look
	if b.off >= b.buf.len {
		return error('Buffer.seek_byte: exhausting bytes')
	}
	val := b.buf[b.off]
	if opt.update_offset {
		b.off += 1
	}

	return val
}

// read one byte at current offset from the buffer
@[direct_array_access; inline]
fn (mut b Buffer) read_byte() !u8 {
	return b.seek_byte(update_offset: true)!
}

fn (mut b Buffer) peek_u8() !u8 {
	return b.seek_byte(update_offset: false)!
}

fn (mut b Buffer) read_u8() !u8 {
	return b.read_byte()!
}

@[direct_array_access; inline]
fn (mut b Buffer) seek_bytes(size int, opt ReadBufferOpts) ![]u8 {
	if size == 0 {
		// return empty bytes
		return []u8{}
	}
	if size < 0 {
		return error('Buffer.seek_bytes: negative size')
	}
	// there are remaining bytes to look
	if b.off >= b.buf.len {
		return error('Buffer.seek_bytes: exhausting bytes')
	}
	// check if the size does not exceeds current availables size
	if size > b.buf.len || b.off + i64(size) > b.buf.len {
		return error('Buffer.seek_bytes: not enough bytes')
	}
	// returns bytes from current offset to offset + size
	bytes := b.buf[b.off..b.off + size]
	// if update_offset was set, updates the current offset
	if opt.update_offset {
		b.off += size
	}
	return bytes
}

// peek_bytes takes bytes from buffer without updates the offset
fn (mut b Buffer) peek_bytes(size int) ![]u8 {
	return b.seek_bytes(size, update_offset: false)
}

// read_bytes read bytes from buffer and updates the offset with the new value
fn (mut b Buffer) read_bytes(size int) ![]u8 {
	return b.seek_bytes(size, update_offset: true)!
}

// read_at_least read amount of bytes from buffer and updates the offset with the new value
fn (mut b Buffer) read_at_least(amount int) ![]u8 {
	return b.read_bytes(amount)!
}

// read_u16 read 2 bytes from buffer and represented it in big-endian order of u16 value
// Its updates the current offset with the new value.
fn (mut b Buffer) read_u16() !u16 {
	buf := b.read_bytes(2)!
	return binary.big_endian_u16(buf)
}

// peek_u16 takes 2 bytes from buffer and represented it in big-endian order of u16 value
// It does not updates the current offset.
fn (mut b Buffer) peek_u16() !u16 {
	buf := b.peek_bytes(2)!
	return binary.big_endian_u16(buf)
}

// read_u24 read 3 bytes from buffer and represented it in big-endian order of Uint24 value
// Its updates the current offset with the new value.
fn (mut b Buffer) read_u24() !Uint24 {
	buf := b.read_bytes(3)!
	return u24_from_bytes(buf, endian: u8(0x00))!
}

// peek_u24 takes 3 bytes from buffer and represented it in big-endian order of Uint24 value
// It does not updates the current offset.
fn (mut b Buffer) peek_u24() !Uint24 {
	buf := b.peek_bytes(3)!
	return u24_from_bytes(buf, endian: u8(0x00))!
}

// read_u32 read 4 bytes from buffer and represented it in big-endian order of u32 value
// Its updates the current offset with the new value.
fn (mut b Buffer) read_u32() !u32 {
	buf := b.read_bytes(4)!
	return binary.big_endian_u32(buf)
}

// peek_u32 takes 4 bytes from buffer and represented it in big-endian order of u32 value
// It does not updates the current offset.
fn (mut b Buffer) peek_u32() !u32 {
	buf := b.peek_bytes(4)!
	return binary.big_endian_u32(buf)
}

// read_u64 read 8 bytes from buffer and represented it in big-endian order of u64 value
// Its updates the current offset with the new value.
fn (mut b Buffer) read_u64() !u64 {
	buf := b.read_bytes(8)!
	return binary.big_endian_u64(buf)
}

// peek_u64 takes 8 bytes from buffer and represented it in big-endian order of u64 value
// It does not updates the current offset.
fn (mut b Buffer) peek_u64() !u64 {
	buf := b.peek_bytes(8)!
	return binary.big_endian_u64(buf)
}
