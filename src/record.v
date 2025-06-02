module tls13

import math
import rand
import encoding.binary
import blackshirt.buffer

// ContentType is content type of TLS 1.3 record
// ContentType = u8
enum ContentType {
	invalid            = 0
	change_cipher_spec = 20
	alert              = 21
	handshake          = 22
	application_data   = 23
	heartbeat          = 24
}

fn (c ContentType) pack() ![]u8 {
	if int(c) > int(math.max_u8) {
		return error('ContentType exceed limit')
	}
	return [u8(c)]
}

fn ContentType.unpack(b []u8) !ContentType {
	if b.len != 1 {
		return error('Bad ContentType bytes')
	}
	return unsafe { ContentType(b[0]) }
}

fn ContentType.from(v u8) !ContentType {
	match v {
		u8(0x14) {
			return ContentType.change_cipher_spec
		}
		u8(0x15) {
			return ContentType.alert
		}
		u8(0x16) {
			return ContentType.handshake
		}
		u8(0x17) {
			return ContentType.application_data
		}
		u8(0x18) {
			return ContentType.heartbeat
		}
		u8(0x00) {
			return ContentType.invalid
		}
		// otherwise, return as is or an error ?
		else {
			return error('Bad ContentType value:${v}')
		}
	}
}

// ChangeCipherSpec type = u8
enum CcsType {
	ccs = 0x01
}

fn (c CcsType) pack() ![]u8 {
	if int(c) > math.max_u8 {
		return error('CcsType exceed')
	}
	val := u8(c)
	return [val]
}

fn CcsType.unpack(b []u8) !CcsType {
	if b.len != 1 {
		return error('bad b.len')
	}
	c := b[0]
	if c != u8(0x01) {
		return error('we only support ccs type')
	}
	return unsafe { CcsType(c) }
}

// ChangeCipherSpec
struct ChangeCipherSpec {
	ccs_type CcsType
}

fn (c ChangeCipherSpec) pack() ![]u8 {
	out := c.ccs_type.pack()!
	return out
}

fn ChangeCipherSpec.unpack(b []u8) !ChangeCipherSpec {
	cct := CcsType.unpack(b)!
	ccs := ChangeCipherSpec{
		ccs_type: cct
	}
	return ccs
}

// TLSRecord is a general purposes structure represents TLS 1.3 Record
// This struct doesn't representing encrypted record or not, for this typical use
// TLSPlaintext or TLSCiphertext structure
struct TLSRecord {
mut:
	ctn_type ContentType
	version  ProtoVersion = tls_v12
	// Should this length to be relaxed, so its can handle fragmented record ?
	length  int // u16
	payload []u8
}

pub fn (rec TLSRecord) str() string {
	return 'TLSRecord:type=${rec.ctn_type}:length=${rec.length}:payload=${rec.payload.bytestr()}'
}

fn (r TLSRecord) packed_length() int {
	mut n := 0
	n += 1
	n += 2
	n += 2
	n += r.payload.len
	return n
}

fn (rc TLSRecord) expect_type(exptype ContentType) bool {
	return rc.ctn_type == exptype
}

fn (mut r TLSRecord) set_record_version(ver ProtoVersion) {
	r.version = ver
}

fn (r TLSRecord) pack() ![]u8 {
	ctn_type := r.ctn_type.pack()!
	version := r.version.pack()!
	mut bytes_len := []u8{len: 2}
	if r.length != r.payload.len {
		return error('unmatched record lemgth')
	}
	if r.length > math.max_u16 {
		return error('record length exceed')
	}
	binary.big_endian_put_u16(mut bytes_len, u16(r.length))

	mut out := []u8{}
	out << ctn_type
	out << version
	out << bytes_len
	out << r.payload

	return out
}

fn TLSRecord.unpack(b []u8) !TLSRecord {
	if b.len < 5 {
		return error('tls record underflow')
	}
	mut r := buffer.new_reader(b)
	t := r.read_byte()!
	ctn_type := unsafe { ContentType(t) }
	v := r.read_u16()!
	version := unsafe { ProtoVersion(v) }
	length := r.read_u16()!
	payload := r.read_at_least(int(length))!

	rec := TLSRecord{
		ctn_type: ctn_type
		version:  version
		length:   int(length)
		payload:  payload
	}
	return rec
}

// from_handshake creates TLSRecord from Handshake message.
// It's doesn't do fragmentation of payload, but return error instead if packed handshake length
// was exceeding record length
// TODO: add support for fragmented record
fn TLSRecord.from_handshake(h Handshake) !TLSRecord {
	// we dont set version here, we default to tls 1.2.
	// if we want set version, call .set_record_version(ver) with appropriate version.
	// handshake message length is 3 bytes length, so maybe its exceeds the record length
	payload := h.pack()!
	if payload.len > math.max_u16 {
		return error('handshake pack length exceed tls record limit')
	}
	rec := TLSRecord{
		ctn_type: .handshake
		version:  tls_v12
		length:   payload.len
		payload:  payload
	}
	return rec
}

// to_plaintext interpretes TLSRecord as a plain TLSPlaintext record
fn (r TLSRecord) to_plaintext() TLSPlaintext {
	pl := TLSPlaintext{
		ctn_type:       r.ctn_type
		legacy_version: r.version
		length:         r.length
		fragment:       r.payload
	}
	return pl
}

// to_ciphertext interpretes TLSRecord as a encrypted TLSCiphertext record
fn (r TLSRecord) to_ciphertext() TLSCiphertext {
	cxt := TLSCiphertext{
		opaque_type:      r.ctn_type
		legacy_version:   r.version
		length:           r.length
		encrypted_record: r.payload
	}
	return cxt
}

// TLSPlaintext represents unencrypted, aka, plain TLS 1.3 record
struct TLSPlaintext {
mut:
	ctn_type       ContentType  = .invalid
	legacy_version ProtoVersion = tls_v12
	length         int // u16
	fragment       []u8
}

fn (pl TLSPlaintext) expect_type(exptype ContentType) bool {
	return pl.ctn_type == exptype
}

fn (mut pl TLSPlaintext) set_version(ver ProtoVersion) ! {
	if ver !in [tls_v11, tls_v12, tls_v13] {
		return error('version not supported')
	}
	if pl.legacy_version == ver {
		return
	}
	pl.legacy_version = ver
}

// from_handshake creates plain TLSPlaintext from Handshake msg
fn TLSPlaintext.from_handshake(h Handshake) !TLSPlaintext {
	payload := h.pack()!
	if payload.len > math.max_u16 {
		return error('Handshake payload need to fragment, its exceed')
	}
	mut rec := TLSPlaintext{
		ctn_type: .handshake
		length:   payload.len
		fragment: payload
	}

	return rec
}

// from_alert creates plaintext record with type Alert with default tls v1.2 version
fn TLSPlaintext.from_alert(a Alert) !TLSPlaintext {
	payload := a.pack()!
	mut rec := TLSPlaintext{
		ctn_type:       .alert
		legacy_version: tls_v12
		length:         payload.len
		fragment:       payload
	}
	return rec
}

// serializes arrays of plaintext to bytes
fn (pxt_list []TLSPlaintext) pack() ![]u8 {
	mut out := []u8{}
	for pxt in pxt_list {
		obj := pxt.pack()!
		out << obj
	}
	return out
}

// from_ccs creates plain TLSPlaintext from ChangeCipherSpec message
fn TLSPlaintext.from_ccs(c ChangeCipherSpec) !TLSPlaintext {
	payload := c.pack()!
	mut rec := TLSPlaintext{
		ctn_type:       .change_cipher_spec
		legacy_version: tls_v12
		length:         payload.len
		fragment:       payload
	}

	return rec
}

pub fn (p TLSPlaintext) str() string {
	return 'TLSPlaintext:type=${p.ctn_type}:length=${p.length}:fragment=${p.fragment.bytestr()}'
}

fn (p TLSPlaintext) to_tls_record() TLSRecord {
	return TLSRecord{
		ctn_type: p.ctn_type
		version:  p.legacy_version
		length:   p.length
		payload:  p.fragment
	}
}

fn (p TLSPlaintext) packed_length() int {
	mut n := 0
	n += 1
	n += 2
	n += 2
	n += p.fragment.len
	return n
}

fn (p TLSPlaintext) pack() ![]u8 {
	if p.length != p.fragment.len {
		return error('Unmatched fragment length')
	}
	if p.fragment.len > (1 << 14) {
		return error('Fragment length exceed limit')
	}
	mut out := []u8{}
	ctn := p.ctn_type.pack()!
	ver := p.legacy_version.pack()!
	mut bol := []u8{len: 2}
	binary.big_endian_put_u16(mut bol, u16(p.length))

	out << ctn
	out << ver
	out << bol
	out << p.fragment

	return out
}

fn TLSPlaintext.unpack(b []u8) !TLSPlaintext {
	if b.len < 5 {
		return error('TLSPlaintext bytes: underflow')
	}
	mut r := buffer.new_reader(b)
	ctn := r.read_u8()!
	ctn_type := unsafe { ContentType(ctn) }
	ver := r.read_u16()!
	version := unsafe { ProtoVersion(ver) }
	length := r.read_u16()!
	if length > (1 << 14) {
		return error('Malformed TLSPlaintext fragment: overflow')
	}
	fragment := r.read_at_least(int(length))!

	pl := TLSPlaintext{
		ctn_type:       ctn_type
		legacy_version: version
		length:         int(length)
		fragment:       fragment
	}

	return pl
}

fn (pxt_list []TLSPlaintext) packed_length() int {
	mut n := 0
	for p in pxt_list {
		n += p.packed_length()
	}
	return n
}

// to_inner_plaintext transform TLSPlaintext to TLSInnerPlaintext structure.
// Its default was using no padding policy to the result, if you want more control to the
// padding mode, see `to_innerplaintext_with_padmode`
fn (p TLSPlaintext) to_innerplaintext() !TLSInnerPlaintext {
	pxt := p.to_innerplaintext_with_padmode(.nopad)!
	return pxt
}

// to_innerplaintext_with_padmode transforms TLSPlaintext to TLSInnerPlaintext structure.
// You can pass padding mode to one of `.nopad`, `.random`. or `.full` of enum value of `PaddingMode`
// By default is to use `.nopad` policy in RecordLayer.
fn (p TLSPlaintext) to_innerplaintext_with_padmode(padm PaddingMode) !TLSInnerPlaintext {
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
		ctn_type:      p.ctn_type
		zeros_padding: pad
	}
	return inner
}

struct TLSInnerPlaintext {
	// content is the TLSPlaintext.fragment value
	content []u8
	// inner ctn_type is a TLSPlaintext.ctn_type value where its
	// containing the actual content type of the record.
	ctn_type ContentType
	// zeros_padding is an arbitrary-length run of zero-valued bytes.
	// Its shoul valid bytes arrays contains zeros bytes that does not exceed record limit,
	zeros_padding []u8
}

fn (inner TLSInnerPlaintext) to_plaintext() !TLSPlaintext {
	if inner.content.len >= 1 << 14 {
		return error('inner.content length exceed limit')
	}
	plain := TLSPlaintext{
		ctn_type:       inner.ctn_type
		legacy_version: tls_v12
		length:         inner.content.len
		fragment:       inner.content
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
	out << ip.ctn_type.pack()!
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
	ctn_type := b[pos]
	content := b[0..pos]

	inner := TLSInnerPlaintext{
		content:       content
		ctn_type:      unsafe { ContentType(ctn_type) }
		zeros_padding: padding
	}
	return inner
}

// The outer opaque_type field of a TLSCiphertext record is always set to the value 23 (application_data)
// for outward compatibility with middleboxes accustomed to parsing previous versions of TLS.
// The actual content type of the record is found in TLSInnerPlaintext.type after decryption
struct TLSCiphertext {
	opaque_type      ContentType  = .application_data
	legacy_version   ProtoVersion = ProtoVersion(0x0303)
	length           int // u16
	encrypted_record []u8
}

fn (tc TLSCiphertext) packed_length() int {
	mut n := 0
	n += 1
	n += 2
	n += 2
	n += tc.encrypted_record.len

	return n
}

fn (tc TLSCiphertext) pack() ![]u8 {
	// The length MUST NOT exceed 2^14 + 256 bytes
	if tc.length != tc.encrypted_record.len || tc.encrypted_record.len > 1 << 14 + 256 {
		return error('Bad TLSCiphertext length: overflow or unmatched')
	}
	mut out := []u8{}
	out << tc.opaque_type.pack()!
	out << tc.legacy_version.pack()!

	mut length := []u8{len: 2}
	binary.big_endian_put_u16(mut length, u16(tc.length))
	out << length
	out << tc.encrypted_record

	return out
}

fn TLSCiphertext.unpack(b []u8) !TLSCiphertext {
	if b.len < 5 {
		return error('Bad TLSCiphertext bytes: underflow')
	}
	mut r := buffer.new_reader(b)
	opq := r.read_byte()!
	opaque_type := unsafe { ContentType(opq) }
	if opaque_type != .application_data {
		return error('Bad TLSCiphertext ContentType')
	}
	ver := r.read_u16()!
	version := unsafe { ProtoVersion(ver) }
	if version != tls_v12 {
		return error('Bad TLSCiphertext ProtoVersion ')
	}
	length := r.read_u16()!
	if length > 1 << 14 + 256 {
		return error('Bad TLSCiphertext length: overflow')
	}
	encrypted_record := r.read_at_least(int(length))!

	tc := TLSCiphertext{
		opaque_type:      opaque_type
		legacy_version:   version
		length:           int(length)
		encrypted_record: encrypted_record
	}
	return tc
}

fn (c TLSCiphertext) to_tls_record() TLSRecord {
	return TLSRecord{
		ctn_type: c.opaque_type
		version:  c.legacy_version
		length:   int(c.length)
		payload:  c.encrypted_record
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
