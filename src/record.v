module tls13

import rand
import encoding.binary

// TLS 1.3 Record
//
const min_tls13_record_length = 5

// TlsRecord is a general purposes structure represents TLS 1.3 Record
// This struct doesn't representing encrypted record or not, for this typical use
// TlsPlaintext or TlsCiphertext structure
@[noinit]
struct TlsRecord {
mut:
	ctype   ContentType
	version Version = .v12
	// Should this length to be relaxed, so its can handle fragmented record ?
	length  int // u16
	payload []u8
}

@[inline]
fn (r TlsRecord) packed_length() int {
	return 5 + r.payload.len
}

fn (rc TlsRecord) expect_type(tp ContentType) bool {
	return rc.ctype == tp
}

fn (mut r TlsRecord) set_record_version(ver Version) {
	r.version = ver
}

@[inline]
fn (r TlsRecord) pack() ![]u8 {
	ctype := r.ctype.pack()!
	version := r.version.pack()!
	mut bytes_len := []u8{len: 2}
	if r.length != r.payload.len {
		return error('unmatched record lemgth')
	}
	if r.length > max_u16 {
		return error('record length exceed')
	}
	binary.big_endian_put_u16(mut bytes_len, u16(r.length))

	mut out := []u8{}
	out << ctype
	out << version
	out << bytes_len
	out << r.payload

	return out
}

@[direct_array_access; inline]
fn TlsRecord.unpack(b []u8) !TlsRecord {
	if b.len < min_tls13_record_length {
		return error('tls record underflow')
	}
	mut r := Buffer.new(b)!
	t := r.read_u8()!
	ctype := ContentType.from_u8(t)!
	v := r.read_u16()!
	version := Version.from_u16(v)!
	length := r.read_u16()!
	payload := r.read_at_least(int(length))!

	rec := TlsRecord{
		ctype:   ctype
		version: version
		length:  int(length)
		payload: payload
	}
	return rec
}

// from_handshake creates TlsRecord from Handshake message.
// It's doesn't do fragmentation of payload, but return error instead if packed handshake length
// was exceeding record length
// TODO: add support for fragmented record
fn TlsRecord.from_handshake(h Handshake) !TlsRecord {
	// we dont set version here, we default to tls 1.2.
	// if we want set version, call .set_record_version(ver) with appropriate version.
	// handshake message length is 3 bytes length, so maybe its exceeds the record length
	payload := h.pack()!
	if payload.len > max_u16 {
		return error('handshake pack length exceed tls record limit')
	}
	rec := TlsRecord{
		ctype:   .handshake
		version: .v12
		length:  payload.len
		payload: payload
	}
	return rec
}

// to_plaintext interpretes TlsRecord as a plain TlsPlaintext record
fn (r TlsRecord) to_plaintext() TlsPlaintext {
	pl := TlsPlaintext{
		ctype:    r.ctype
		version:  r.version
		length:   r.length
		fragment: r.payload
	}
	return pl
}

// to_ciphertext interpretes TlsRecord as a encrypted TlsCiphertext record
fn (r TlsRecord) to_ciphertext() TlsCiphertext {
	cxt := TlsCiphertext{
		otype:   r.ctype
		version: r.version
		length:  r.length
		payload: r.payload
	}
	return cxt
}

// TlsPlaintext represents unencrypted, aka, plain TLS 1.3 record
struct TlsPlaintext {
mut:
	ctype   ContentType = .invalid
	version Version     = .v12
	// fragment was max of u16-sized length
	fragment []u8
}

// size_plaintext return the size of this plaintext record
@[inline]
fn size_plaintext(p TlsPlaintext) int {
	mut n := 0
	n += 1
	n += 2
	n += 2 + p.fragment.len
	return n
}

// pack_plaintext encodes plaintext record p into bytes array
@[inline]
fn pack_plaintext(p TlsPlaintext) ![]u8 {
	mut out := []u8{cap: size_plaintext(p)}

	out << u8(p.ctype)
	out << pack_u16item[Version](p.version)
	out << pack_u16item[int](p.fragment.len)
	out << p.fragment

	return out
}

fn (pl TlsPlaintext) expect_type(tp ContentType) bool {
	return pl.ctype == tp
}

fn (mut pl TlsPlaintext) set_version(ver Version) ! {
	if ver !in [tls_v11, .v12, tls_v13] {
		return error('version not supported')
	}
	if pl.version == ver {
		return
	}
	pl.version = ver
}

// from_handshake creates plain TlsPlaintext from Handshake msg
fn TlsPlaintext.from_handshake(h Handshake) !TlsPlaintext {
	payload := h.pack()!
	if payload.len > max_u16 {
		return error('Handshake payload need to fragment, its exceed')
	}
	mut rec := TlsPlaintext{
		ctype:    .handshake
		length:   payload.len
		fragment: payload
	}

	return rec
}

// from_alert creates plaintext record with type Alert with default tls v1.2 version
fn TlsPlaintext.from_alert(a Alert) !TlsPlaintext {
	payload := a.pack()!
	mut rec := TlsPlaintext{
		ctype:    .alert
		version:  .v12
		length:   payload.len
		fragment: payload
	}
	return rec
}

// serializes arrays of plaintext to bytes
fn (pxt_list []TlsPlaintext) pack() ![]u8 {
	mut out := []u8{}
	for pxt in pxt_list {
		obj := pxt.pack()!
		out << obj
	}
	return out
}

// from_ccs creates plain TlsPlaintext from ChangeCipherSpec message
fn TlsPlaintext.from_ccs(c ChangeCipherSpec) !TlsPlaintext {
	payload := c.pack()!
	mut rec := TlsPlaintext{
		ctype:    .change_cipher_spec
		version:  .v12
		length:   payload.len
		fragment: payload
	}

	return rec
}

pub fn (p TlsPlaintext) str() string {
	return 'TlsPlaintext:type=${p.ctype}:length=${p.length}:fragment=${p.fragment.bytestr()}'
}

fn (p TlsPlaintext) to_tls_record() TlsRecord {
	return TlsRecord{
		ctype:   p.ctype
		version: p.version
		length:  p.length
		payload: p.fragment
	}
}

fn (p TlsPlaintext) pack() ![]u8 {
	if p.length != p.fragment.len {
		return error('Unmatched fragment length')
	}
	if p.fragment.len > (1 << 14) {
		return error('Fragment length exceed limit')
	}
	mut out := []u8{}
	ctn := p.ctype.pack()!
	ver := p.version.pack()!
	mut bol := []u8{len: 2}
	binary.big_endian_put_u16(mut bol, u16(p.length))

	out << ctn
	out << ver
	out << bol
	out << p.fragment

	return out
}

fn TlsPlaintext.unpack(b []u8) !TlsPlaintext {
	if b.len < 5 {
		return error('TlsPlaintext bytes: underflow')
	}
	mut r := Buffer.new(b)!
	ctn := r.read_u8()!
	ctype := ContentType.from_u8(ctn)!
	ver := r.read_u16()!
	version := Version.from_u16(ver)!
	length := r.read_u16()!
	if length > (1 << 14) {
		return error('Malformed TlsPlaintext fragment: overflow')
	}
	fragment := r.read_at_least(int(length))!

	pl := TlsPlaintext{
		ctype:    ctype
		version:  version
		length:   int(length)
		fragment: fragment
	}

	return pl
}

fn (pxt_list []TlsPlaintext) packed_length() int {
	mut n := 0
	for p in pxt_list {
		n += p.packed_length()
	}
	return n
}

// to_inner_plaintext transform TlsPlaintext to TLSInnerPlaintext structure.
// Its default was using no padding policy to the result, if you want more control to the
// padding mode, see `to_innerplaintext_with_padmode`
fn (p TlsPlaintext) to_innerplaintext() !TLSInnerPlaintext {
	pxt := p.to_innerplaintext_with_padmode(.nopad)!
	return pxt
}

// to_innerplaintext_with_padmode transforms TlsPlaintext to TLSInnerPlaintext structure.
// You can pass padding mode to one of `.nopad`, `.random`. or `.full` of enum value of `PaddingMode`
// By default is to use `.nopad` policy in RecordLayer.
fn (p TlsPlaintext) to_innerplaintext_with_padmode(padm PaddingMode) !TLSInnerPlaintext {
	if p.fragment.len > 1 << 14 {
		return error('fragment overflow')
	}
	pad := pad_for_fragment(p.fragment, padm)!
	if !is_zero(pad) {
		return error('Bad padding, contains non null byte')
	}
	if p.fragment.len + pad.len > 1 << 14 {
		return error('Fragment and pad length: overflow')
	}
	inner := TLSInnerPlaintext{
		content:       p.fragment
		ctype:         p.ctype
		zeros_padding: pad
	}
	return inner
}

struct TLSInnerPlaintext {
	// content is the TlsPlaintext.fragment value
	content []u8
	// inner ctype is a TlsPlaintext.ctype value where its
	// containing the actual content type of the record.
	ctype ContentType
	// zeros_padding is an arbitrary-length run of zero-valued bytes.
	// Its shoul valid bytes arrays contains zeros bytes that does not exceed record limit,
	zeros_padding []u8
}

fn (inner TLSInnerPlaintext) to_plaintext() !TlsPlaintext {
	if inner.content.len >= 1 << 14 {
		return error('inner.content length exceed limit')
	}
	plain := TlsPlaintext{
		ctype:    inner.ctype
		version:  .v12
		length:   inner.content.len
		fragment: inner.content
	}
	return plain
}

fn (ip TLSInnerPlaintext) pack() ![]u8 {
	// check if padding is all zeros bytes
	if !is_zero(ip.zeros_padding) {
		return error('Bad padding, contains non null byte')
	}
	// check for sure, its not overflow record payload limit
	if ip.content.len + 1 + ip.zeros_padding.len > 1 << 14 {
		return error('Bad content and pad length; overflow')
	}
	mut out := []u8{}
	// TODD: is it should add content.len?
	out << ip.content
	out << ip.ctype.pack()!
	out << ip.zeros_padding

	return out
}

fn (ip TLSInnerPlaintext) packed_length() int {
	mut n := 0

	n += ip.content.len
	n += 1
	n += ip.zeros_padding.len

	return n
}

fn TLSInnerPlaintext.unpack(b []u8) !TLSInnerPlaintext {
	// read padding first
	pos := find_content_type_position(b)!
	mut padding := []u8{}
	// if pos is the last position, set padding to remaining bytes
	if pos < b.len - 1 {
		padding = b[pos + 1..].clone()
	}
	// make sure the padding is zero's bytes
	assert is_zero(padding)
	ctype := b[pos]
	content := b[0..pos]

	inner := TLSInnerPlaintext{
		content:       content
		ctype:         ContentType.from_u8(ctype)!
		zeros_padding: padding
	}
	return inner
}

// The outer otype field of a TlsCiphertext record is always set to the value 23 (application_data)
// for outward compatibility with middleboxes accustomed to parsing previous versions of TLS.
// The actual content type of the record is found in TLSInnerPlaintext.type after decryption
@[noinit]
struct TlsCiphertext {
	otype ContentType = .application_data
mut:
	// legacy version
	version Version = .v12
	// u16-sized payload
	payload []u8
}

fn (tc TlsCiphertext) packed_length() int {
	mut n := 0
	n += 1
	n += 2
	n += 2
	n += tc.payload.len

	return n
}

fn (tc TlsCiphertext) pack() ![]u8 {
	// The length MUST NOT exceed 2^14 + 256 bytes
	if tc.length != tc.payload.len || tc.payload.len > 1 << 14 + 256 {
		return error('Bad TlsCiphertext length: overflow or unmatched')
	}
	mut out := []u8{}
	out << tc.otype.pack()!
	out << tc.version.pack()!

	mut length := []u8{len: 2}
	binary.big_endian_put_u16(mut length, u16(tc.length))
	out << length
	out << tc.payload

	return out
}

fn TlsCiphertext.unpack(b []u8) !TlsCiphertext {
	if b.len < 5 {
		return error('Bad TlsCiphertext bytes: underflow')
	}
	mut r := Buffer.new(b)!
	opq := r.read_u8()!
	otype := ContentType.from_u8(opq)!
	if otype != .application_data {
		return error('Bad TlsCiphertext ContentType')
	}
	ver := r.read_u16()!
	version := Version.from_u16(ver)!
	if version != .v12 {
		return error('Bad TlsCiphertext Version ')
	}
	length := r.read_u16()!
	if length > 1 << 14 + 256 {
		return error('Bad TlsCiphertext length: overflow')
	}
	payload := r.read_at_least(int(length))!

	tc := TlsCiphertext{
		otype:   otype
		version: version
		length:  int(length)
		payload: payload
	}
	return tc
}

fn (c TlsCiphertext) to_tls_record() TlsRecord {
	return TlsRecord{
		ctype:   c.otype
		version: c.version
		length:  int(c.length)
		payload: c.payload
	}
}

// Utility function
//
// is_zero returns whether seed is all zeroes in constant time.
fn is_zero(seed []u8) bool {
	mut acc := u8(0)
	for b in seed {
		acc |= b
	}
	return acc == 0
}

// find_content_type_position find first non null byte start from the last position.
// Its return position in the bytes arrays.
fn find_content_type_position(b []u8) !int {
	// this check makes sure b is a valid bytes
	if b.len < 1 {
		return error('bad b.len')
	}
	// arrays length should not exceed record's limit
	if b.len > 1 << 14 {
		return error('Provided bytes exceed record limit')
	}
	// make sure, its non all zero bytes
	if is_zero(b) {
		return error('${@FN}: bad all zeros bytes')
	}

	// set i to the last index of the bytes data
	mut i := b.len - 1
	for i >= 0 {
		// start check from the last value, and check if its a null byte
		// if yes, continue and decrease index, otherwise its a first non null
		// byte represent ContentType so we return position (index).
		if b[i] != u8(0x00) {
			return i
		}
		// decrease index
		i -= 1
	}
	// If a receiving implementation does not find a non-zero octet in the cleartext,
	// it MUST terminate the connection with an "unexpected_message" alert.
	return error('${@FN} not found non-null byte')
}

// padding policy for handling of the record's padding
enum PaddingMode {
	nopad  = 0x00 // no padding
	random = 0x01 // random padding
	full   = 0x02 // full padding
}

// pad_for_fragment build zeros padding for fragment bytes
fn pad_for_fragment(fragment []u8, padm PaddingMode) ![]u8 {
	match padm {
		.nopad {
			return nullbytes
		}
		.random {
			pad_limit := 1 << 14 - fragment.len
			n := rand.u32n(u32(pad_limit))!
			pad := []u8{len: int(n), init: u8(0x00)}
			return pad
		}
		.full {
			if fragment.len >= 1 << 14 {
				return nullbytes
			}
			rem := 1 << 14 - fragment.len
			pad := []u8{len: rem, init: u8(0x00)}
			return pad
		}
	}
}
