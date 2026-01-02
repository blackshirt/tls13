// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Utility helpers used across module
module tls13

import encoding.binary

// an enum tells the size of bytes needed to encode an object,
// to be prepended on the output.
enum SizeT {
	size0 = 0 // left untouched
	size1 = 1 // prepended with 1-byte length
	size2 = 2 // prepended with 2-bytes length
	size3 = 3 // prepended with 3-bytes length
}

// 1. Helpers for an opaque with u8-sized characteristic.
//
// Some of TLS 1.3 types, like ContentType, HandshakeType,  NameType, etc mostly was u8-sized opaque.
// This type of opaque commonly defined as `type SomeOpaque = u8` or similar thing.

// pack_u8item packs single u8-sized item into bytes array
@[inline]
fn pack_u8item[T](t T) []u8 {
	return [u8(t)]
}

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
// prepended with the length specified in n.
@[direct_array_access]
fn pack_u8list_withlen[T](ts []T, n SizeT) ![]u8 {
	c := size_u8list_withlen[T](ts, n)
	mut out := []u8{cap: c}
	match n {
		0 {
			// do nothing
		}
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
	// encodes the contents, and return the result
	out << pack_u8list[T](ts)
	return out
}

// size_u8list_withlen gets the capacities needed with specified length for ts.
@[direct_array_access; inline]
fn size_u8list_withlen[T](ts []T, n SizeT) int {
	return ts.len + int(n)
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
fn pack_u16list_withlen[T](ts []T, n SizeT) ![]u8 {
	// get the bytes capacities for the output length
	c := size_u16list_withlen[T](ts, n)
	mut out := []u8{cap: c}
	match n {
		.size0 {
			// do nothing, directly encodes the payload
		}
		.size1 {
			// check the arrays length
			if 2 * ts.len > max_u8 {
				return error('length exceed max_u8')
			}
			// appends one-byte length into output
			out << u8(2 * ts.len)
		}
		.size2 {
			// check the arrays length
			if 2 * ts.len > max_u16 {
				return error('length exceed max_u16')
			}
			// serializes two-bytes length into output
			out << pack_u16item[int](2 * ts.len)
		}
		.size3 {
			// 3-bytes length should not exceed max_u24 value
			if 2 * ts.len > max_u24 {
				return error('exceed max_u24')
			}
			bol3 := u24_from_int(2 * ts.len)!
			out << bol3.bytes()!
		}
		else {
			return error('unsupported length')
		}
	}
	// serializes the items
	out << pack_u16list[T](ts)

	return out
}

// size_u16list_withlen tells the size needed to encode the list ts prepended with n-bytes length
@[inline]
fn size_u16list_withlen[T](ts []T, n SizeT) int {
	return int(n) + 2 * ts.len
}

// size_u16item returns the length of serialized u16-sized opaque T.
@[inline]
fn size_u16item[T](t T) int {
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

// 3. Raw-bytes opaque, ie, []u8  helpers
//
// Some TLS 1.3 likes Cookie extension, Hostname , key exchange payload was defined as raw bytes
// limited by some length. Its also can be applied into raw bytes fields.
// This type of opaque commonly defined as `type SomeOpaque = []u8` or similar thing.

// pack_raw_withlen encodes raw bytes r prepended with the n-bytes length.
@[direct_array_access; inline]
fn pack_raw_withlen(r []u8, n SizeT) ![]u8 {
	mut out := []u8{cap: size_raw_withlen(r, n)}
	match n {
		.size0 {
			// do nothing
		}
		.size1 {
			// 1-byte length should not exceed max_u8 value
			if r.len > max_u8 {
				return error('exceed max_u8')
			}
			out << u8(r.len)
		}
		.size2 {
			// 2-bytes length should not exceed max_u16 value
			if r.len > max_u16 {
				return error('exceed max_u16')
			}
			out << pack_u16item[int](r.len)
		}
		.size3 {
			// 3-bytes length should not exceed max_u24 value
			if r.len > max_u24 {
				return error('exceed max_u24')
			}
			bol3 := u24_from_int(r.len)!
			out << bol3.bytes()!
		}
		// TODO: support for more long bytes length
	}
	// get the raw bytes item, and append into output
	out << r

	return out
}

// size_raw_withlen tells the capacities needed to serialize r prepended with n-bytes length.
@[inline]
fn size_raw_withlen(r []u8, n SizeT) int {
	return r.len + int(n)
}

// 4. Helpers for another arbitrary object
//
// Some complex structures, like handshake message, Extension, TLS Record etc
// need some special handling.

// size_objlist returns the size of serialized ts object array, with callback to get size
// for single item of object T was defined in cb_objsize. For complex structures, you should
// provide this callback.
@[direct_array_access; inline]
fn size_objlist[T](ts []T, cb_objsize fn (T) int) int {
	mut n := 0
	for t in ts {
		n += cb_objsize(t)
	}
	return n
}

// size_objlist_withlen returns the size of encoded arrays of T in ts with prepended n-bytes length.
// Its accepts a callback cb_objsize for returning the size of encoded single item of T.
@[direct_array_access; inline]
fn size_objlist_withlen[T](ts []T, cb_objsize fn (T) int, n SizeT) int {
	return size_objlist[T](ts, cb_objsize) + int(n)
}

// pack_objlist encodes arrays of object T in ts into bytes array.
// Its accepts two's callback to help for determining correct behaviour, ie,
// - cb_objsize, a callback for determining the size of encoded single item of object T
// - cb_objpack, a callback for serializing single item of object T into bytes array
@[direct_array_access; inline]
fn pack_objlist[T](ts []T, cb_objpack fn (T) ![]u8, cb_objsize fn (T) int) ![]u8 {
	mut out := []u8{cap: size_objlist[T](ts, cb_objsize)}
	for item in ts {
		out << cb_objpack(item)!
	}
	return out
}

// pack_objlist_withlen  encodes arrays of object T in ts into bytes array prepended with n-bytes length.
// See `pack_objlist` docs for the detail.
@[direct_array_access; inline]
fn pack_objlist_withlen[T](ts []T, cb_objpack fn (T) ![]u8, cb_objsize fn (T) int, n SizeT) ![]u8 {
	// the length of array of object, in bytes
	length := size_objlist[T](ts, cb_objsize)
	// setup buffer capacities
	mut out := []u8{cap: length + int(n)}
	match n {
		.size0 {
			// do nothing
		}
		.size1 {
			if length > max_u8 {
				return error('length []T payload exceeds max_u8')
			}
			out << u8(length)
		}
		.size2 {
			if length > max_u16 {
				return error('length []T payload exceeds max_u16')
			}
			out << pack_u16item[int](length)
		}
		.size3 {
			if length > max_u24 {
				return error('length []T payload exceeds max_u24')
			}
			bol3 := u24_from_int(length)!
			out << bol3.bytes()!
		}
	}
	// encodes the object list payload
	out << pack_objlist[T](ts, cb_objpack, cb_objsize)!

	return out
}

// 5. Helpers for an opaque with 24-bits size
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

// 6. Simple bytes reader
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
