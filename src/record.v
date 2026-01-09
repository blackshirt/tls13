// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
module tls13

import rand
import encoding.binary
import x.crypto.chacha20poly1305

// AEAD encrypter
interface AeadEncrypter {
	encrypt(plaintext []u8, key []u8, nonce []u8, ad []u8) ![]u8
	decrypt(ciphertext []u8, key []u8, nonce []u8, ad []u8) ![]u8
}

// Default chacha20poly1305 AEAD encrypter
@[noini]
struct DefaultAead {
mut:
	c CipherSuite = .tls_chacha20poly1305_sha256
}

// new_default creates a new default chacha20poly1305 AEAD encrypter
@[inline]
fn new_default() &AeadEncrypter {
	return &DefaultAead{}
}

fn (d DefaultAead) encrypt(plaintext []u8, key []u8, nonce []u8, ad []u8) ![]u8 {
	return chacha20poly1305.encrypt(plaintext, key, nonce, ad)!
}

fn (d DefaultAead) decrypt(ciphertext []u8, key []u8, nonce []u8, ad []u8) ![]u8 {
	return chacha20poly1305.decrypt(ciphertext, key, nonce, ad)!
}

// record protection layer
//
@[noinit]
struct RContext {
mut:
	// default cipher suite used in aead part, set on creation
	c CipherSuite = .tls_chacha20poly1305_sha256
	// flag that marked this instance of context was alreade reset
	done bool
	// record payload aead encrypter
	aead &AeadEncrypter = new_default()
	// padding policy used, default for no padding
	pm PaddingMode = .nopad
	// current write sequence
	cw_seq u64
	// current read sequence
	cr_seq u64
}

// new_rcontext creates record protection context from ciphersuite c and padding policy pm.
// Its only support for tls_chacha20poly1305_sha256 ciphersuite for now.
@[inline]
fn new_rcontext(c CipherSuite, pm PaddingMode) !RContext {
	match c {
		.tls_chacha20poly1305_sha256 {
			return RContext{
				c: .tls_chacha20poly1305_sha256
				pm: pm
			}
		}
		else {
			return error('unsupported ciphersuite for record context')
		}
	}
}

@[inline]
fn (mut r RContext) inc_wseq() {
	r.cw_seq += 1
	if r.cw_seq == 0 {
		panic('u64bit wirte sequence has overflow')
	}
}

@[inline]
fn (mut r RContext) inc_rseq() {
	r.cr_seq += 1
	if r.cr_seq == 0 {
		panic('u64bit read sequence has overflow')
	}
}

// set_padmode sets padding mode of this record context r
@[inline]
fn (mut r RContext) set_padmode(pm PaddingMode) {
	r.pm = pm
}

// make_wrnonce makes a write nonce
@[direct_array_access; inline]
fn (mut r RContext) make_wrnonce(wiv []u8) []u8 {
	// recommended nonce size 
	mut wnonce := []u8{len: nonce_size(r.c)}
	// The 64-bit record sequence number is encoded in network byte
	// order and padded to the left with zeros to iv_length.
	binary.big_endian_put_u64_end(mut wnonce, r.cw_seq)
	// The padded sequence number is XORed with either the static
	// client_write_iv or server_write_iv (depending on the role).
	for i := 0; i < wnonce.len; i++ {
		wnonce[i] = wnonce[i] ^ wiv[i]
	}
	return wnonce
}

// make_rdnonce make a read nonce
@[direct_array_access; inline]
fn (mut r RContext) make_rdnonce(riv []u8) []u8 {
	mut rdnonce := []u8{len: nonce_size(r.c)}
	binary.big_endian_put_u64_end(mut rdnonce, r.cr_seq)
	// The padded sequence number is XORed with either the static
	// client_write_iv or server_write_iv (depending on the role).
	for i := 0; i < rdnonce.len; i++ {
		rdnonce[i] = rdnonce[i] ^ riv[i]
	}

	return rdnonce
}

// treats TlsRecord r as a plaintext record and encrypt them
@[direct_array_access]
fn (mut r RContext) encrypt_rec(rec TlsRecord, wkey []u8, wiv []u8) !TlsCiphertext {
	// transforms plaintext record r into TlsInnerText structure
	inner := rec.into_inner_with_padmode(r.pm)!
	// The plaintext input to the AEAD algorithm is the encoded TLSInnerPlaintext structure.
	plaintext := inner.pack()!

	// calculates encrypted length, The length MUST NOT exceed 2^14 + 256 bytes
	length := plaintext.len + tag_size(r.c)
	if length > max_payload_size {
		return error('record_overflow alert.')
	}

	// build additional_data, ie, TlsCiphertext header
	ad_data := make_adata(.application_data, .v12, length)!
	//
	wr_nonce := r.make_wrnonce(wiv)

	// aead encrypt
	ciphertext, tag := r.aead.encrypt(plaintext, wkey, wr_nonce, ad_data)!

	// build encrypted payload 
	mut encrypted_text := []u8{len: ciphertext.len + tag.len}
	encrypted_text << ciphertext
	encrypted_text << tag

	// increases write seq number
	r.inc_wseq()

	return TlsCiphertext{
		otype:   ContentType.application_data
		version: .v12
		payload: encrypted_text
	}
}

// Record protection mechansim helpers
//

// make_adata builds additional data, where additional_data
//		= TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version || TLSCiphertext.length
@[inline]
fn make_adata(ctype ContentType, ver Version, length int) ![]u8 {
	if length > max_u16 {
		return error('length exceed max_u16')
	}
	mut ad := []u8{cap: min_ciphertext_size}
	ad << pack_u8item[ContentType](ctype)
	ad << pack_u16item[Version](ver)
	ad << pack_u16item[int](length)

	return ad
}

// TLS 1.3 Record
//
const min_record_size = 5

// TlsRecord is a general purposes structure represents TLS 1.3 Record
//
@[noinit]
struct TlsRecord {
mut:
	// for plaintext record, its a higher-level protocol used to process the enclosed fragment
	// or .application_data if this was ciphertext record.
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

// expect_type checks whether this record has a ContentType tp
@[inline]
fn (r TlsRecord) expect_type(tp ContentType) bool {
	return r.ctype == tp
}

// set_version sets the record version
@[inline]
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
	// build the zeros padding with padding mode in pm
	pad := pad_for_fragment(p.fragment, pm)!
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
	// content is the TlsRecord.fragment value, should be lower than 1 << 14 length
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
	// check for sure, its not overflowing plaintext record payload limit
	size := size_innertext(p)
	if size > max_fragment_size {
		return error('Bad content and pad length; overflow')
	}
	mut out := []u8{cap: size}
	// TODD: is it should add a content.len?
	out << p.content
	out << pack_u8item[ContentType](p.ctype)
	out << p.zeros

	return out
}

// parse_innertext parses bytes b into TlsInnerText structure
@[direct_array_access; inline]
fn parse_innertext(b []u8) !TlsInnerText {
	// get non-null bytes position from the bytes b and error if its not found
	pos := find_ctntype_offset(b)
	if pos < 0 {
		err_from_offset(pos)!
	}
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

// error constants return values for find_ctntype_offset
//
const err_invalid_length = -1
const err_exceed_limit = -2
const err_zeros_bytes = -3
const err_nonnull_notfound = -4

@[inline]
fn err_from_offset(n int) ! {
	match n {
		-1 { return error('err_invalid_length') }
		-2 { return error('err_exceed_limit') }
		-3 { return error('err_zeros_bytes') }
		-4 { return error('err_nonnull_notfound') }
		else { return error('invalid result error number') }
	}
}

// find_ctntype_offset find first non null byte start from the last position.
// Its return position in the bytes arrays.
@[direct_array_access; inline]
fn find_ctntype_offset(b []u8) int {
	// this check makes sure b is a valid bytes
	if b.len < 1 {
		return err_invalid_length
	}
	// arrays length should not exceed record's limit
	if b.len > max_fragment_size {
		return err_exceed_limit
	}
	// make sure, its non all zero bytes
	if is_zero(b) {
		return err_zeros_bytes
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
	return err_nonnull_notfound
}

// padding policy for handling of the record's padding
enum PaddingMode {
	nopad  // no padding
	random // random padding
	full   // full padding
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
