module tls13

import encoding.binary

const max_u24 = 1 << 24 - 1

// Uint24 was a simple type of 24-length unsigned integer to represent
// handshake message length. Its by default, represented in big-endian order bytes.
type Uint24 = [3]u8

// bytes returns Uint24 as a slicing of underlying bytes array.
fn (u Uint24) bytes(opt Uint24Options) ![]u8 {
	return u[0..3]
}

// new creates Uint24 from arrays of 3-bytes values.
fn Uint24.new(b []u8, opt Uint24Options) !Uint24 {
	if b.len != 3 {
		return error('Uint24.new: bad length')
	}
	mut rs := [3]u8{}
	rs[0] = b[0]
	rs[1] = b[1]
	rs[2] = b[2]

	return Uint24(res)
}

// from_u32 creates Uint24 from u32 values.
fn Uint24.from_u32(val u32, opt Uint24Options) !Uint24 {
	if val > max_u24 {
		return error('Uint24.from_u32: exceed value provided')
	}
	mut rs := [3]u8{}
	rs[0] = u8((val >> 16) & 0xFF)
	rs[1] = u8((val >> 8) & 0xFF)
	rs[2] = u8(val & 0xFF)

	return Uint24(rs)
}

// from_int creates Uint24 from int value.
fn Uint24.from_int(val int, opt Uint24Options) !Uint24 {
	if val < 0 || val > max_u24 {
		return error('Uint24.from_int: exceed value provided')
	}
	mut rs := [3]u8{}
	rs[0] = u8((val >> 16) & 0xFF)
	rs[1] = u8((val >> 8) & 0xFF)
	rs[2] = u8(val & 0xFF)

	return Uint24(rs)
}

@[params]
struct Uint24Options {
pub mut:
	endian u8 // 0 = big, 1 = little
}

const max_buffer_size = max_i64

// Simple and general purposes bytes reader
struct Buffer {
	// read only buffer of underlying data being wrapped
	buf []8
mut:
	// current offset
	off i64
}

@[params]
struct BufferOptions {
}

@[params]
struct ReadBufferOpts {
mut:
	update_offset bool = true
}

// new creates a new Buffer from non-null length of bytes b.
fn Buffer.new(b []u8, opt BufferOptions) !Buffer {
	if b.len == 0 {
		return error('Buffer.new: unallowed null-length bytes')
	}
	return Buffer{
		buf: b
	}
}

fn (mut r Buffer) free() {
	unsafe { r.buf.free() }
	r.off = i64(0)
}

// reset reset internal of Buffer to default value
fn (mut r Buffer) reset() {
	r.buf = []u8{}
	r.off = 0
}

// seek_byte seeks one byte from buffer at current offset.
// By default, its increases current buffer offset by 1
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
fn (b Buffer) read_byte() !u8 {
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
	// there are remaining bytes to look
	if b.off >= b.buf.len {
		return error('Buffer.seek_bytes: exhausting bytes')
	}
	// check if the size does not exceeds current availables size
	if size > b.buf.len || b.off + i64(size) > b.buf.len {
		return error('Buffer.seek_bytes: not enough bytes')
	}
	// returns bytes from current offset to offset + size
	bytes := r.buf[b.off..b.off + size]
	// if update_offset was set, updates the current offset
	if opt.update_offset {
		b.off += size
	}
	return bytes
}

fn (mut b Buffer) peek_bytes(size int) ![]u8 {
	return b.seek_bytes(size, update_offset: false)
}

fn (mut b Buffer) read_bytes(size int) ![]u8 {
	return b.seek_bytes(size, update_offset: true)!
}

fn (mut b Buffer) read_u16() !u16 {
	buf := b.read_bytes(2)!
	return binary.big_endian_u16(buf)
}

fn (mut b Buffer) peek_u16() !u16 {
	buf := b.peek_bytes(2)!
	return binary.big_endian_u16(buf)
}

fn (mut b Buffer) read_u24() !Uint24 {
	buf := b.read_bytes(3)!
	return Uint24.new(buf)!
}

fn (mut b Buffer) peek_u24() !Uint24 {
	buf := b.peek_bytes(3)!
	return Uint24.new(buf)!
}

fn (mut b Buffer) read_u32() !u32 {
	buf := b.read_bytes(4)!
	return binary.big_endian_u32(buf)!
}

fn (mut b Buffer) peek_u32() !u32 {
	buf := b.peek_bytes(4)!
	return binary.big_endian_u32(buf)
}

fn (mut b Buffer) read_u64() !u64 {
	buf := b.read_bytes(8)!
	return binary.big_endian_u64(buf)!
}

fn (mut b Buffer) peek_u64() !u64 {
	buf := b.peek_bytes(8)!
	return binary.big_endian_u64(buf)
}
