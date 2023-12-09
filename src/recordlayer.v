module tls13

import io
import math
// import arrays
import encoding.binary
import blackshirt.aead

// The record layer fragments information blocks into TLSPlaintext records carrying data
// in chunks of 2^14 bytes or less.  Message boundaries are handled differently
// depending on the underlying ContentType.
struct RecordLayer {
	// underlying AEAD cipher encryption engine to be used
	cipher &aead.Cipher = unsafe { nil }
mut:
	// padding mode to be used as padding policy, default to .nopad
	// see `PaddingMode` for more detail
	padm PaddingMode = .nopad
	// read and write sequence number
	rseq u64
	wseq u64
}

// new_record_layer creates new RecordLayer based on CipherSuite c
fn new_record_layer(c CipherSuite) !&RecordLayer {
	ae := new_aead_cipher(c)!
	rc := &RecordLayer{
		cipher: ae
	}
	return rc
}

// set_padding_mode set of record's padding policy of the RecordLayer to m mode.
fn (mut rc RecordLayer) set_padding_mode(m PaddingMode) {
	if rc.padm == m {
		return
	}
	rc.padm = m
}

// inc_read_seq increases read sequence number by one
fn (mut rc RecordLayer) inc_read_seq() {
	rc.rseq += u64(1)
}

// inc_write_seq increases write sequence nunber by one
fn (mut rc RecordLayer) inc_write_seq() {
	rc.wseq += u64(1)
}

// reset_read_seq resets RecordLayer's read sequence number to 0
fn (mut rc RecordLayer) reset_read_seq() {
	rc.rseq = u64(0)
}

// reset_write_seq resets RecordLayer's write sequence number to 0
fn (mut rc RecordLayer) reset_write_seq() {
	rc.wseq = u64(0)
}

// reset_sequence reset of internal RecordLayer's sequence number
fn (mut rc RecordLayer) reset_sequence() {
	rc.reset_read_seq()
	rc.reset_write_seq()
}

// encrypt transforms TLSPlaintext to TLSCiphertext structure with provided `aead.Cipher`.
// Its accepts write_key, where the write_key is either the client_write_key or the server_write_key,
// and the nonce where it is derived from the sequence number and the client_write_iv or server_write_iv.
fn (mut rc RecordLayer) encrypt(pxt TLSPlaintext, write_key []u8, write_iv []u8) !TLSCiphertext {
	// build plaintext input to the AEAD algorithm where it is the encoded TLSInnerPlaintext structure
	inner := pxt.to_innerplaintext_with_padmode(rc.padm)!
	plaintext := inner.pack()!

	// calculates encrypted length, The length MUST NOT exceed 2^14 + 256 bytes
	// An endpoint that receives a record that exceeds this length MUST terminate
	// the connection with a "record_overflow" alert.
	length := plaintext.len + rc.cipher.tag_size()
	if length > 1 << 14 + 256 {
		return error('record_overflow alert.')
	}
	// build additional_data, ie TLSCiphertext header
	add := rc.build_add_data(ContentType.application_data, tls_v12, length)!

	// do cipher encryption, encrypted_record field of TLSCiphertext is set to result of encryption.
	// encrypted_record is concatenation of ciphertext plus tag result
	wr_nonce := rc.build_write_nonce(write_iv)
	ciphertext, tag := rc.cipher.encrypt(write_key, wr_nonce, add, plaintext)!

	mut encrypted_record := []u8{}
	encrypted_record << ciphertext
	encrypted_record << tag

	// make sure encrypted_record.len matching with calculated length above
	assert encrypted_record.len == length

	// finally, build TLSCiphertext structure and return it
	cxt := TLSCiphertext{
		opaque_type: ContentType.application_data
		legacy_version: tls_v12
		length: length
		encrypted_record: encrypted_record
	}

	// increase RecordLayer write seq number
	rc.inc_write_seq()
	return cxt
}

// decrypt transforms (decrypts) TLSCiphertext to TLSPlaintext, its reverse of encrypt operation
fn (mut rc RecordLayer) decrypt(cxt TLSCiphertext, peer_wrkey []u8, iv []u8) !(TLSPlaintext, []u8) {
	// build additional data, read nonce and other stuffs needed for decryption process
	aad := rc.build_add_data(cxt.opaque_type, cxt.legacy_version, cxt.length)!
	rnonce := rc.build_read_nonce(iv)

	// As a note, TLSCiphertext.encrypted field is containing ciphertext output of `.encrypt()`
	// operation plus appended with mac parts, so we split it to feed to decryption part.
	idx := cxt.encrypted_record.len - rc.cipher.tag_size()
	ciphertext := cxt.encrypted_record[0..idx]
	mac := cxt.encrypted_record[idx..]
	assert mac.len == rc.cipher.tag_size()

	// TODO: what is mac should we supplied to decrypt_and_verify?
	inner, valid := rc.cipher.decrypt_and_verify(peer_wrkey, rnonce, aad, ciphertext,
		mac)!
	if !valid {
		return error('verify of decrypt_and_verify failed')
	}
	innertext := TLSInnerPlaintext.unpack(inner)!
	pxt := innertext.to_plaintext()!

	rc.inc_read_seq()
	return pxt, mac
}

fn (rc RecordLayer) uncoalesced_hsk(rec TLSPlaintext) ![]Handshake {
	return error('Unimplemented')
}

// Handshake messages MAY be coalesced into a single TLSPlaintext record
// or fragmented across several records, provided that:
// Handshake messages MUST NOT be interleaved with other record
// types.  That is, if a handshake message is split over two or more
// records, there MUST NOT be any other records between them.
fn (rc RecordLayer) coalesce_hsk(hs []Handshake) !TLSPlaintext {
	if hs.packed_length() > 1 << 14 {
		return error('hs encoded length exceed limit to coalesce')
	}
	hsp := hs.pack()!
	pl := TLSPlaintext{
		ctn_type: .handshake
		legacy_version: tls_v12
		length: hsp.len
		fragment: hsp
	}
	return pl
}

fn (rc RecordLayer) hsk_msgs_not_interleaved(rcs []TLSPlaintext) bool {
	return rcs.all(it.ctn_type == .handshake)
}

// The per-record nonce for the AEAD construction is formed as follows:
//  1.  The 64-bit record sequence number is encoded in network byte
//      order and padded to the left with zeros to iv_length.
//  2.  The padded sequence number is XORed with either the static
//      client_write_iv or server_write_iv (depending on the role).
fn (rc RecordLayer) build_write_nonce(write_iv []u8) []u8 {
	mut wr_nonce := []u8{len: rc.cipher.nonce_size()}
	binary.big_endian_put_u64_end(mut wr_nonce, rc.wseq)
	for i, _ in wr_nonce {
		wr_nonce[i] ^= write_iv[i]
	}
	return wr_nonce
}

fn (rc RecordLayer) build_read_nonce(iv []u8) []u8 {
	mut rnonce := []u8{len: rc.cipher.nonce_size()}
	binary.big_endian_put_u64_end(mut rnonce, rc.rseq)

	for i := 0; i < rnonce.len; i++ {
		rnonce[i] = rnonce[i] ^ iv[i]
	}

	return rnonce
}

// build_add_data builds additional data needed for record encryption/decrption
// additional_data = TLSCiphertext.opaque_type || TLSCiphertext.legacy_record_version
//							|| TLSCiphertext.length
fn (rc RecordLayer) build_add_data(ctn_type ContentType, ver ProtoVersion, length int) ![]u8 {
	mut out := []u8{}

	out << ctn_type.pack()!
	out << ver.pack()!
	mut length_bytes := []u8{len: 2}
	assert length < math.max_u16
	binary.big_endian_put_u16(mut length_bytes, u16(length))
	out << length_bytes

	return out
}

// The TLS record protocol takes messages to be transmitted, fragments the data into manageable blocks, protects the records,
// and transmits the result.  Received data is verified, decrypted, reassembled, and then delivered to higher-level clients.
// see for proposed mbedtls handshake fragmentation handling at
// https://github.com/oesh/mbedtls/blob/hs_fragmentation__design_doc/docs/proposed/hs_reassembly.md
// do_fragment does fragmentation of payload if its length bigger than 2^14 bytes, by chunk-ing it
fn (rc RecordLayer) do_fragment(payload []u8, ctn_type ContentType) ![]TLSPlaintext {
	mut pxt_list := []TLSPlaintext{}
	if payload.len > 1 << 14 {
		// we're currently not supports for fragmentation, so return error instead
		// TODO: handles messages fragmentation, maybe we can split payload using `arrays.chunk()`
		// chunks := arrays.chunk(payload, 1 << 14)
		// for chunk in chunks {
		// pxt := TLSPlaintext{
		//	ctn_type: ctn_type
		//	length: chunk.len
		//	fragment: chunk
		//}
		// pxt_list << pxt
		//}
		// return pxt_list
		return error("we're not support for fragmentation")
	}
	// below 1<<14, directly build plaintext
	pxt := TLSPlaintext{
		ctn_type: ctn_type
		length: payload.len
		fragment: payload
	}
	pxt_list << pxt

	return pxt_list
}

// do_defragment handles record reassembly from tls record
fn (rc RecordLayer) do_defragment(pls []TLSPlaintext) ![][]u8 {
	mut out := [][]u8{}
	if pls.len <= 0 {
		return out
	}
	pt := pls[0].ctn_type
	pv := pls[0].legacy_version
	// check
	s := pls.all(it.ctn_type == pt && it.legacy_version == pv)
	if s {
		for p in pls {
			o := p.fragment
			out << o
		}
		return out
	}
	return error('contains different type and version')
}

// Handshake messages are supplied to the TLS record layer, where they are encapsulated within one
// or more TLSPlaintext or TLSCiphertext structures which are processed and transmitted as
// specified by the current active connection state.
fn (rc RecordLayer) take_handshake_msg(m Handshake) ![]TLSPlaintext {
	// maximum of handshake message length is 3 bytes length,
	// so maybe its bigger than the record length, ie, 2 bytes length
	// does this handshake message need to be encapsulated?
	msg := m.pack()!

	pxt_list := rc.do_fragment(msg, .handshake)!
	return pxt_list
}

// transmit_bytes writes bytes to underlying writer
fn (mut rc RecordLayer) transmit_bytes(mut wr io.Writer, bytes []u8) !int {
	n := wr.write(bytes)!
	return n
}

fn (mut rc RecordLayer) transmit_plaintext(mut wr io.Writer, pxt TLSPlaintext) !int {
	bytes := pxt.pack()!
	return rc.transmit_bytes(mut wr, bytes)
}

fn (mut rc RecordLayer) transmit_ciphertext(mut wr io.Writer, cxt TLSCiphertext) !int {
	bytes := cxt.pack()!
	return rc.transmit_bytes(mut wr, bytes)
}
