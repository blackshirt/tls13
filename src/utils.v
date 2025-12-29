// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
module tls13

import encoding.binary

const max_uint24 = 1 << 24 - 1 // 0x00FF_FFFF
const mask_uint24 = u32(0x00FF_FFFF)

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
	if val > max_uint24 {
		return error('u24_from_u32: exceed value provided')
	}
	return Uint24{
		value: val & mask_uint24
	}
}

// u24_from_int creates Uint24 from int value.
@[inline]
fn u24_from_int(val int) !Uint24 {
	if val < 0 || val > max_uint24 {
		return error('u24_from_int: out of range value')
	}
	return Uint24{
		value: val & mask_uint24
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
	if val > max_uint24 {
		return error('u24_from_bytes: exceed value')
	}
	return Uint24{
		value: val & mask_uint24
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

// Buffer was a simple and general purposes bytes reader
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
