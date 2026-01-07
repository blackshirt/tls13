module tls13

import rand
import encoding.binary

// TLS 1.3 Record
//
const min_record_size = 5

// TlsRecord is a general purposes structure represents TLS 1.3 Record
@[noinit]
struct TlsRecord {
mut:
	// for plaintext record, its a higher-level protocol used to process
	// the enclosed fragment or application_data if this was ciphertext record.
	ctype ContentType
	// The legacy_record_version field is always 0x0303
	version Version = .v12
	// Should this length to be relaxed, so its can handle fragmented record ?
	// the fragment length for plaintext record was limited under 1 << 14 bytes
	// when this record is an encrypted record, the size fragment payload was increased
	// by expansion size of underlying aead cipher used.
	fragment []u8
}

// size_record return the size of encoded record r
@[inline]
fn size_record(r TlsRecord) int {
	return min_record_size + r.fragment.len
}

// pack_record encodes record r into bytes array
@[inline]
fn pack_record(r TlsRecord) ![]u8 {
	mut out := []u8{cap: size_record(r)}

	out << u8(p.ctype)
	out << pack_u16item[Version](r.version)
	out << pack_u16item[int](r.fragment.len)
	out << p.fragment

	return out
}

fn (r TlsRecord) expect_type(tp ContentType) bool {
	return r.ctype == tp
}

fn (mut r TlsRecord) set_version(ver Version) ! {
	if ver !in [tls_v11, .v12, tls_v13] {
		return error('version not supported')
	}
	if r.version == ver {
		return
	}
	r.version = ver
}

// into_inner_with_padmode treats TlsRecord as plaintext record and transforms into TlsInnerText structure.
// You can pass padding mode to one of `.nopad`, `.random`. or `.full` of enum value of `PaddingMode`
// By default is to use `.nopad` policy in RecordLayer.
fn (r TlsRecord) into_inner_with_padmode(pm PaddingMode) !TlsInnerText {
	pad := pad_for_fragment(p.fragment, pm)!
	if !is_zero(pad) {
		return error('Bad padding, contains non null byte')
	}
	// when this record treated as plaintext record, The fragment length MUST NOT exceed 2^14 bytes.
	// event its padded with the zeros padding
	if p.fragment.len + pad.len > max_fragment_size {
		return error('Fragment and pad length: overflow')
	}
	return TlsInnerText{
		content: p.fragment
		ctype:   p.ctype
		zeros:   pad
	}
}

// TlsInnerText
//
// struct {
//        opaque content[TLSPlaintext.length];
//        ContentType type;
//        uint8 zeros[length_of_padding];
//    } TlsInnerText;
//
const min_innertext_size = 3

// TlsInnerText was used to transform plaintext TlsRecord into TlsCiphertext structure
@[noinit]
struct TlsInnerText {
mut:
	// content is the TlsRecord.fragment value, its a u16-sized length
	content []u8
	// inner ctype is a TlsRecord.ctype value where its containing the actual content type of the record.
	ctype ContentType
	// zeros is an arbitrary-length run of zero-valued bytes acts as padding
	// Its should valid bytes arrays contains zeros bytes that does not exceed record limit,
	zeros []u8
}

// size_innertext the size of this TlsInnerText
@[inline]
fn size_innertext(p TlsInnerText) int {
	// without length
	return p.content.len + 1 + zeros.len
}

// pack transforms TlsInnerText into bytes
@[inline]
fn (p TlsInnerText) pack() ![]u8 {
	// check if padding is all zeros bytes
	if !is_zero(p.zeros) {
		return error('Bad padding, contains non null byte')
	}
	// check for sure, its not overflow record payload limit
	if p.content.len + 1 + p.zeros.len > max_fragment_size {
		return error('Bad content and pad length; overflow')
	}
	mut out := []u8{cap: size_innertext(p)}
	// TODD: is it should add a content.len?
	out << p.content
	out << pack_u8item[ContentType](p.ctype)
	out << p.zeros

	return out
}

// parse_innertext parses bytes b into TlsInnerText structure
@[direct_array_access; inline]
fn parse_innertext(b []u8) !TlsInnerText {
	// read padding first
	pos := find_ctntype_offset(b)!
	mut padding := []u8{}
	// if pos is the last position, set padding to remaining bytes
	if pos < b.len - 1 {
		padding = b[pos + 1..].clone()
	}
	// make sure the padding is zero's bytes
	assert is_zero(padding)
	ctype := b[pos]
	content := b[0..pos]

	return TlsInnerText{
		content: content
		ctype:   new_ctntype(ctype)!
		zeros:   padding
	}
}

// The outer otype field of a TlsCiphertext record is always set to the value 23 (application_data)
// for outward compatibility with middleboxes accustomed to parsing previous versions of TLS.
// The actual content type of the record is found in TlsInnerText.type after decryption
//
const min_ciphertext_size = 5
const max_payload_size = 1 << 14 + 256

// TlsCiphertext
//
@[noinit]
struct TlsCiphertext {
mut:
	// opaque type
	otype ContentType = .application_data
	// legacy version
	version Version = .v12
	// The payload length was the sum of the lengths of the content and the padding,
	// plus one for the inner content type, plus any expansion added by the AEAD algorithm.
	// The length  MUST NOT exceed 2^14 + 256 bytes
	payload []u8
}

// size_ciphertext returns the size of encoded TlsCiphertext c, in bytes
@[inline]
fn size_ciphertext(c TlsCiphertext) int {
	return 5 + c.payload.len
}

// pack_ciphertext encodes TlsCiphertext c into bytes array
@[inline]
fn pack_ciphertext(c TlsCiphertext) ![]u8 {
	// The length MUST NOT exceed 2^14 + 256 bytes
	if tc.payload.len > max_payload_size {
		return error('Bad TlsCiphertext overflow payload')
	}
	mut out := []u8{cap: size_ciphertext(c)}
	out << pack_u8item[ContentType](c.ctype)
	out << pack_u16item[Version](c.version)!
	out << pack_raw_withlen(c.payload, .size2)!

	return out
}

// parse_ciphertext decodes bytes into TlsCiphertext
@[direct_array_access; inline]
fn parse_ciphertext(bytes []u8) !TlsCiphertext {
	if bytes.len < min_ciphertext_size {
		return error('Bad TlsCiphertext bytes: underflow')
	}
	mut r := new_buffer(b)!
	// Get opaque type
	opq := r.read_u8()!
	otype := new_ctntype(opq)!
	// The outer opaque_type field of a TLSCiphertext record is always set to the value 23 (application_data)
	// for outward compatibility with middleboxes accustomed to parsing previous versions of TLS.
	if otype != .application_data {
		return error('Bad TlsCiphertext ContentType')
	}
	// read version, we dont check the parsed version
	ver := r.read_u16()!
	version := new_version(ver)!

	// read the length of payload
	length := r.read_u16()!
	if length > max_payload_size {
		return error('Bad TlsCiphertext length: overflow')
	}

	return TlsCiphertext{
		otype:   otype
		version: version
		payload: r.read_at_least(int(length))!
	}
}

// Utility function
//
// is_zero tells whether seed is all zeroes in constant time.
@[direct_array_access; inline]
fn is_zero(seed []u8) bool {
	mut acc := u8(0)
	for b in seed {
		acc |= b
	}
	return acc == 0
}

// find_ctntype_offset find first non null byte start from the last position.
// Its return position in the bytes arrays.
@[direct_array_access; inline]
fn find_ctntype_offset(b []u8) !int {
	// this check makes sure b is a valid bytes
	if b.len < 1 {
		return error('bad b.len')
	}
	// arrays length should not exceed record's limit
	if b.len > max_fragment_size {
		return error('Provided bytes exceed record limit')
	}
	// make sure, its non all zero bytes
	if is_zero(b) {
		return error('bad all zeros bytes')
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
	return error('not found non-null byte')
}

// padding policy for handling of the record's padding
enum PaddingMode {
	nopad  = 0x00 // no padding
	random = 0x01 // random padding
	full   = 0x02 // full padding
}

const null_bytes = []u8{}
const max_fragment_size = 1 << 14

// pad_for_fragment build zeros padding for fragment bytes
@[direct_array_access; inline]
fn pad_for_fragment(fragment []u8, pm PaddingMode) ![]u8 {
	match pm {
		.nopad {
			return null_bytes
		}
		.random {
			pad_limit := max_fragment_size - fragment.len
			n := rand.int_in_range(0, pad_limit)!
			return []u8{len: n, init: 0x00}
		}
		.full {
			if fragment.len >= max_fragment_size {
				return null_bytes
			}
			rem := max_fragment_size - fragment.len
			return []u8{len: rem, init: 0x00}
		}
	}
}
