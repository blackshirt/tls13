module tls13

import crypto.hmac
import encoding.binary

const helloretry_magic = [u8(0xCF), 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
	0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09,
	0xE2, 0xC8, 0xA8, 0x33, 0x9C]

const tls12_random_magic = [u8(0x44), 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]
const tls11_random_magic = [u8(0x44), 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]

const min_hskmsg_size = 4

// Handshake represents Tls 1.3 handshake message.
//
@[noinit]
struct Handshake {
	msg_type HandshakeType // u8 value
	length   int           // max_u24
	payload  []u8
}

@[inline]
fn (h Handshake) packed_length() int {
	return min_hskmsg_size + h.payload.len
}

fn (h Handshake) expect_hsk_type(hsktype HandshakeType) bool {
	return h.msg_type == hsktype
}

// is_hrr checks whether this handshake message is HelloRetryRequest message.
// two cases here, first of it, the msg_type is hello_retry_request type and the second
// if the msg_type is .server_hello with random value contains helloretry_magic constant.
// otherwise, its not HelloRetryRequest message.
fn (h Handshake) is_hrr() !bool {
	if h.msg_type == .hello_retry_request {
		return true
	}
	if h.msg_type == .server_hello {
		sh := ServerHello.unpack(h.payload)!
		if sh.is_hrr() {
			return true
		}
	}
	return false
}

@[inline]
fn (h Handshake) pack() ![]u8 {
	if h.length != h.payload.len {
		return error('Unmatched Handshake length')
	}
	if h.length > max_u24 || h.payload.len > max_u24 {
		return error('Handshake length exceed limit')
	}
	mut out := []u8{}
	msg_type := h.msg_type.pack()!
	length := Uint24.from_int(h.length)!
	bytes_of_length := length.bytes()!

	// writes bytes into out
	out << msg_type
	out << bytes_of_length
	out << h.payload

	return out
}

@[direct_array_access; inline]
fn Handshake.unpack(b []u8) !Handshake {
	if b.len < min_hskmsg_size {
		return error('Underflow of Handshake bytes')
	}
	mut r := Buffer.new(b)!
	tipe := r.read_u8()!
	msg_type := HandshakeType.from_u8(tipe)!

	// bytes of length
	bytes_of_length := r.read_at_least(3)!
	val := Uint24.from_bytes(bytes_of_length)!
	length := int(val)

	// read Handshake payload
	payload := r.read_at_least(length)!
	assert payload.len == length
	out := Handshake{
		msg_type: msg_type
		length:   length
		payload:  payload
	}

	return out
}

// Arrays of handshakes messages handling
fn (hs []Handshake) packed_length() int {
	mut n := 0
	for m in hs {
		ln := m.packed_length()
		n += ln
	}
	return n
}

// filtered_msg_type filters []Handshake based on provided msg_type, its maybe null or contains filtered type.
fn (hs []Handshake) filtered_hsk_with_type(msgtype HandshakeType) []Handshake {
	return hs.filter(it.msg_type == msgtype)
}

// HandshakeList is arrays of handshake messages
type HandshakeList = []Handshake

// There are some situations, multiple handshake payload packed contained in single record.
// unpack_to_multi_handshake add supports to this situation, its unpack bytes array as
// array of Handshake
fn unpack_to_multi_handshake(b []u8) ![]Handshake {
	if b.len < min_hskmsg_size {
		return error('unpack_to_multi_handshakes: Underflow of Handshakes bytes')
	}
	mut hs := []Handshake{}
	mut i := 0
	mut r := Buffer.new(b)!
	for i < b.len {
		mut buf := []u8{}
		tp := r.read_u8()!
		bytes_length := r.read_bytes(3)!

		val := Uint24.from_bytes(bytes_length)!
		length := int(val)
		bytes := r.read_at_least(length)!

		buf << tp
		buf << bytes_length
		buf << bytes

		h := Handshake.unpack(buf)!
		i += buf.len
		hs << h
	}
	return hs
}

fn (hs []Handshake) pack() ![]u8 {
	mut out := []u8{}
	for h in hs {
		o := h.pack()!
		out << o
	}
	return out
}

type HandshakePayload = Certificate
	| CertificateRequest
	| CertificateVerify
	| ClientHello
	| EncryptedExtensions
	| EndOfEarlyData
	| Finished
	| KeyUpdate
	| NewSessionTicket
	| ServerHello

fn (h HandshakePayload) msg_type() !HandshakeType {
	match h {
		Certificate { return .certificate }
		CertificateRequest { return .certificate_request }
		CertificateVerify { return .certificate_verify }
		ClientHello { return .client_hello }
		EncryptedExtensions { return .encrypted_extensions }
		EndOfEarlyData { return .end_of_early_data }
		Finished { return .finished }
		KeyUpdate { return .key_update }
		ServerHello { return .server_hello }
		NewSessionTicket { return .new_session_ticket }
	}
}

// pack_to_handshake_bytes build Handshake message from HandshakePayload and then serializes it to bytes.
fn (h HandshakePayload) pack_to_handshake_bytes() ![]u8 {
	hsk := h.pack_to_handshake()!
	out := hsk.pack()!
	return out
}

// pack_to_handshake build Handshake message from HandshakePayload
fn (h HandshakePayload) pack_to_handshake() !Handshake {
	msg_type := h.msg_type()!
	payload := h.pack()!
	length := payload.len

	hsk := Handshake{
		msg_type: msg_type
		length:   length
		payload:  payload
	}
	return hsk
}

fn (h HandshakePayload) pack() ![]u8 {
	match h {
		Certificate {
			cert := h as Certificate
			out := cert.pack()!
			return out
		}
		CertificateRequest {
			crq := h as CertificateRequest
			out := crq.pack()!
			return out
		}
		CertificateVerify {
			cvr := h as CertificateVerify
			out := cvr.pack()!
			return out
		}
		ClientHello {
			ch := h as ClientHello
			out := ch.pack()!
			return out
		}
		EncryptedExtensions {
			ee := h as EncryptedExtensions
			out := ee.pack()!
			return out
		}
		EndOfEarlyData {
			eod := h as EndOfEarlyData
			out := eod.pack()!
			return out
		}
		Finished {
			fin := h as Finished
			out := fin.pack()!
			return out
		}
		KeyUpdate {
			ku := h as KeyUpdate
			out := ku.pack()!
			return out
		}
		ServerHello {
			sh := h as ServerHello
			out := sh.pack()!
			return out
		}
		NewSessionTicket {
			st := h as NewSessionTicket
			out := st.pack()!
			return out
		}
	}
}

// Minimal length checked here inculdes minimal of cipher_suites and extensions length
// Minimal bytes lengtb = 2 + 32 + 1 + 0 + 2 + 2 + 1 + 1 + 2 + 8
const min_clienthello_size = 51

struct ClientHello {
mut:
	lgc_version   ProtocolVersion = tls_v12 // TLS v1.2
	random        []u8          // 32 bytes
	lgc_sessid    []u8          // <0..32>;
	cipher_suites []CipherSuite // <2..2^16-2>;
	lgc_comp_meth u8            //<1..2^8-1>;
	extensions    []Extension   // <8..2^16-1>;
}

fn (ch ClientHello) packed_length() int {
	mut n := 0
	n += 2 // ProtocolVersion
	n += 32 // 32 bytes of random
	n += 1 // one byte of lgc_sessid.len
	n += ch.lgc_sessid.len
	n += ch.cipher_suites.packed_length()
	n += 1 // one byte of length compression_method
	n += 1 // one byte compression_method
	n += ch.extensions.packed_length()

	return n
}

@[inline]
fn (ch ClientHello) pack() ![]u8 {
	if ch.lgc_sessid.len > 32 {
		return error('Session id length exceed')
	}
	if ch.random.len != 32 {
		return error('Bad random length')
	}
	mut out := []u8{}

	out << ch.lgc_version.pack()!
	out << ch.random
	out << u8(ch.lgc_sessid.len)
	out << ch.lgc_sessid
	out << ch.cipher_suites.pack()!
	out << u8(0x01)
	out << ch.lgc_comp_meth
	out << ch.extensions.pack()!

	return out
}

@[direct_array_access; inline]
fn ClientHello.unpack(b []u8) !ClientHello {
	if b.len < min_clienthello_size {
		return error('Bad ClientHello bytes: underflow ')
	}
	mut r := Buffer.new(b)!
	// version,
	ver := r.read_u16()!
	version := ProtocolVersion.from_u16(ver)!
	if version != tls_v12 {
		return error('Bad protocol version: violated')
	}
	// random
	random := r.read_at_least(32)!
	// lgc_sessid
	legn := r.read_u8()!
	if legn > 32 {
		return error('lgc_sessid exceed')
	}
	legacy := r.read_at_least(int(legn))!

	// read ciphersuites length + underlying arrays
	ciphers_len := r.peek_u16()!
	ciphers_data := r.read_at_least(int(ciphers_len) + 2)!
	ciphers := CipherSuiteList.unpack(ciphers_data)!

	// read commpression method, should one byte length
	cm := r.read_u8()!
	if cm != u8(0x01) {
		return error('Bad compression_method length')
	}
	cmethd := r.read_u8()!

	// read remianing bytes extension list
	exts_len := r.peek_u16()!
	exts_bytes := r.read_at_least(int(exts_len) + 2)!
	extensions := ExtensionList.unpack(exts_bytes)!

	ch := ClientHello{
		lgc_version:   version
		random:        random
		lgc_sessid:    legacy
		cipher_suites: ciphers
		lgc_comp_meth: cmethd
		extensions:    extensions
	}
	return ch
}

// parse_server_hello parse ServerHello with associated ClientHello
fn (ch ClientHello) parse_server_hello(sh ServerHello) !bool {
	// A client which receives a cipher suite that was not offered MUST abort the handshake
	if !ch.cipher_suites.is_exist(sh.cipher_suite) {
		return error("ClientHello.cipher_suites doesn't contains server cipher_suite")
	}
	// TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below
	// MUST check that the last 8 bytes are not equal to either of these values.
	if sh.random.len != 32 {
		return error('Bad ServerHello.random length')
	}
	last8 := sh.random[24..31]
	if hmac.equal(last8, tls12_random_magic) || hmac.equal(last8, tls12_random_magic) {
		return error('Bad downgrade ServerHello.random detected')
	}
	// A client which receives a lgc_sessid_echo field that does not match what it sent
	// in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
	if !hmac.equal(ch.lgc_sessid, sh.lgc_sessid_echo) {
		return error("Server and Client sessid doesn't match")
	}
	// If the "supported_versions" extension in the ServerHello contains a version not offered
	// by the client or contains a version prior to TLS 1.3, the client MUST abort
	// the handshake with an "illegal_parameter" alert.
	contains_spv := sh.extensions.any(it.tipe == .supported_versions)
	if contains_spv {
		server_spv := sh.extensions.map(it.tipe == .supported_versions)
		client_spv := ch.extensions.map(it.tipe == .supported_versions)
		if server_spv != client_spv {
			return error("Server and Client SupportedVersion doesn't match")
		}
	}
	return true
}

const min_serverhello_size = 46

// ServerHello
//
struct ServerHello {
mut:
	lgc_version     ProtocolVersion = tls_v12
	random          []u8
	lgc_sessid_echo []u8 // <0..32>;
	cipher_suite    CipherSuite
	lgc_comp_meth   u8 = 0x00
	extensions      []Extension // <6..2^16-1>;
}

@[direct_array_access; inline]
fn (sh ServerHello) packed_length() int {
	mut n := 0

	n += 2
	n += 32
	n += 1
	n += sh.lgc_sessid_echo.len
	n += sh.cipher_suite.packed_length()
	n += 1 // compression_method
	n += sh.extensions.packed_length()

	return n
}

@[direct_array_access; inline]
fn (sh ServerHello) pack() ![]u8 {
	// we do early simple check of validity.
	if sh.random.len != 32 {
		return error('Bad random length')
	}
	if sh.lgc_sessid_echo.len > 32 {
		return error('Bad lgc_sessid_echo length')
	}
	mut out := []u8{}

	out << sh.lgc_version.pack()!
	out << sh.random
	out << u8(sh.lgc_sessid_echo.len)
	out << sh.lgc_sessid_echo
	out << sh.cipher_suite.pack()!
	out << sh.lgc_comp_meth
	out << sh.extensions.pack()!

	return out
}

@[direct_array_access; inline]
fn ServerHello.unpack(b []u8) !ServerHello {
	// min = 2 + 32 + 1 + 0 + 2 + 1 + 2 + 6
	if b.len < min_serverhello_size {
		return error('Bad ServerHello bytes: underflow')
	}
	mut r := Buffer.new(b)!
	// version
	ver := r.read_u16()!
	version := ProtocolVersion.from_u16(ver)!
	if version != tls_v12 {
		return error('Bad ProtocolVersion lgc_version')
	}
	random := r.read_at_least(32)!
	// lgc_sessid_echo
	s := r.read_u8()!
	if s > 32 {
		return error('Bad lgc_sessid_echo length')
	}
	sessid := r.read_at_least(int(s))!
	cp := r.read_at_least(2)!
	cipher := CipherSuite.unpack(cp)!
	comp_meth := r.read_u8()!

	// read remianing bytes extension list
	exts_ln := r.peek_u16()!
	exts_bytes := r.read_at_least(int(exts_ln) + 2)!
	extensions := ExtensionList.unpack(exts_bytes)!

	sh := ServerHello{
		lgc_version:     version
		random:          random
		lgc_sessid_echo: sessid
		cipher_suite:    cipher
		lgc_comp_meth:   comp_meth
		extensions:      extensions
	}
	return sh
}

fn (sh ServerHello) is_hrr() bool {
	return hmac.equal(sh.random, helloretry_magic)
}

struct EndOfEarlyData {}

fn (eo EndOfEarlyData) pack() ![]u8 {
	out := []u8{}
	return out
}

fn (mut eo EndOfEarlyData) unpack(b []u8) !EndOfEarlyData {
	return eo
}

struct EncryptedExtensions {
	extensions []Extension // <0..2^16-1>
}

fn (ee EncryptedExtensions) pack() ![]u8 {
	out := ee.extensions.pack()!
	return out
}

fn EncryptedExtensions.unpack(b []u8) !EncryptedExtensions {
	exts := ExtensionList.unpack(b)!
	ee := EncryptedExtensions{
		extensions: exts
	}
	return ee
}

// B.3.2.  Server Parameters Messages
// CertificateRequest handling
struct CertificateRequest {
	crq_ctx    []u8        // <0..2^8-1>;
	extensions []Extension // <2..2^16-1>;
}

fn (cr CertificateRequest) packed_length() int {
	mut n := 0
	n += 1
	n += cr.crq_ctx.len
	n += cr.extensions.packed_length()

	return n
}

fn (cr CertificateRequest) pack() ![]u8 {
	if cr.crq_ctx.len > max_u8 {
		return error('certreq context len exceed')
	}
	mut out := []u8{}
	exts_data := cr.extensions.pack()!

	// writes out CertificateRequest data into output buffer
	out << u8(cr.crq_ctx.len)
	out << cr.crq_ctx
	out << exts_data

	return out
}

fn CertificateRequest.unpack(b []u8) !CertificateRequest {
	if b.len < 3 {
		return error('bad CertificateRequest bytes')
	}
	mut r := Buffer.new(b)!
	crctx_len := r.read_u8()!
	crctx := r.read_at_least(int(crctx_len))!
	exts_len := r.peek_u16()!
	exts_bytes := r.read_at_least(int(exts_len) + 2)!
	exts := ExtensionList.unpack(exts_bytes)!

	cr := CertificateRequest{
		crq_ctx:    crctx
		extensions: exts
	}
	return cr
}

// CertificateType = u8
enum CertificateType as u8 {
	x509           = 0
	openpgp        = 1 // reserved
	raw_public_key = 2
	unknown        = 255 // unofficial
}

@[inline]
fn CertificateType.from_u8(val u8) !CertificateType {
	match val {
		0 { return .x509 }
		1 { return .openpgp }
		2 { return .raw_public_key }
		255 { return .unknown }
		else { return error('unsupported CertificateType value') }
	}
}

@[inline]
fn (ct CertificateType) pack() ![]u8 {
	if u8(ct) > max_u8 {
		return error('CertificateType exceed')
	}
	return [u8(ct)]
}

@[direct_array_access; inline]
fn CertificateType.unpack(b []u8) !CertificateType {
	if b.len != 1 {
		return error('Bad CertificateType bytes')
	}
	return CertificateType.from_u8(b[0])!
}

const max_certentry_data_size = max_u24 // 1 << 24 - 1

struct CertificateEntry {
	cert_type  CertificateType // u8
	cert_data  []u8            //<1..2^24-1>;
	extensions []Extension     //<0..2^16-1>;
}

fn (ce CertificateEntry) packed_length() int {
	mut n := 0
	n += 1 // cert_type
	n += 3 // ce.cert_data.len
	n += ce.cert_data.len
	n += ce.extensions.packed_length()

	return n
}

@[direct_array_access; inline]
fn (ce CertificateEntry) pack() ![]u8 {
	match ce.cert_type {
		.x509, .raw_public_key {
			// FIXME: is it should handle differently?
			if ce.cert_data.len > max_certentry_data_size {
				return error('Certificate data exceed')
			}
			cert_length := Uint24.from_int(ce.cert_data.len)!
			cert_bytes_length := cert_length.bytes()!

			exts := ce.extensions.pack()!
			mut out := []u8{}
			out << cert_bytes_length
			out << ce.cert_data
			out << exts

			return out
		}
		else {
			return error('to be implemented')
		}
	}
}

@[direct_array_access; inline]
fn CertificateEntry.unpack(b []u8) !CertificateEntry {
	if b.len < 5 {
		return error('Bad CertificateEntry bytes: underflow')
	}
	mut r := Buffer.new(b)!
	// read 3 bytes length of cert_data
	bytes_length := r.read_at_least(3)!
	val := Uint24.from_bytes(bytes_length)!
	length := int(val)
	if length > max_certentry_data_size {
		return error('CertificateEntry.cert_data exceed')
	}
	cert_data := r.read_at_least(length)!

	// read extensions
	exts_length := r.peek_u16()!
	exts_data := r.read_at_least(int(exts_length) + 2)!
	exts := ExtensionList.unpack(exts_data)!

	ce := CertificateEntry{
		cert_data:  cert_data
		extensions: exts
	}
	return ce
}

fn (cel []CertificateEntry) packed_length() int {
	mut n := 0
	n += 3
	for ce in cel {
		n += ce.packed_length()
	}
	return n
}

fn (cel []CertificateEntry) pack() ![]u8 {
	mut cel_length := 0
	for c in cel {
		cel_length += c.packed_length()
	}
	if cel_length > max_u24 {
		return error('CertificateEntry list exceed')
	}
	mut out := []u8{}
	celist_length := Uint24.from_int(cel_length)!
	celist_bytes := celist_length.bytes()!

	out << celist_bytes
	for ce in cel {
		o := ce.pack()!
		out << o
	}
	return out
}

type CertificateEntryList = []CertificateEntry

fn CertificateEntryList.unpack(b []u8) !CertificateEntryList {
	if b.len < 3 {
		return error('CertificateEntryList bytes underflow')
	}
	mut r := Buffer.new(b)!

	// read 3 bytes of length
	bytes_of_length := r.read_at_least(3)!
	val := Uint24.from_bytes(bytes_of_length)!
	length := int(val)

	// remaining bytes was smaller then length
	// if r.remainder() < length {
	//	return error('Underflow of remaining of CertificateEntryList bytes')
	// }
	// read payload
	payload := r.read_at_least(length)!
	mut i := 0
	mut cel := []CertificateEntry{}
	for i < payload.len {
		ce := CertificateEntry.unpack(payload[i..])!
		cel << ce
		i += ce.packed_length()
	}
	return CertificateEntryList(cel)
}

const min_certificate_msg_size = 4

// 4.4.2.  Certificate
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
//
struct Certificate {
	cert_req_ctx []u8               // <0..2^8-1>;
	cert_list    []CertificateEntry // <0..2^24-1>;
}

fn (c Certificate) packed_length() int {
	mut n := 0
	n += 1
	n += c.cert_req_ctx.len
	n += c.cert_list.packed_length()

	return n
}

@[direct_array_access; inline]
fn (c Certificate) pack() ![]u8 {
	mut out := []u8{}

	if c.cert_req_ctx.len > max_u8 {
		return error('Bad cert_req_ctx length: overflow')
	}
	// writes certificate request context
	out << u8(c.cert_req_ctx.len)
	out << c.cert_req_ctx

	// writes certificates list
	cert_list := c.cert_list.pack()!
	out << cert_list

	return out
}

@[direct_array_access; inline]
fn Certificate.unpack(b []u8) !Certificate {
	if b.len < min_certificate_msg_size {
		return error('Bad Certificate bytes: underflow')
	}
	mut r := Buffer.new(b)!
	// read cert_req_ctx
	cr := r.read_u8()!
	creq := r.read_at_least(int(cr))!

	// peek 3 bytes of length
	bytes_of_length := r.peek_bytes(3)!
	val := Uint24.from_bytes(bytes_of_length)!
	length := int(val)

	certlist_payload := r.read_at_least(length + 3)!
	cert_list := CertificateEntryList.unpack(certlist_payload)!

	cert := Certificate{
		cert_req_ctx: creq
		cert_list:    cert_list
	}
	return cert
}

const min_certverify_msg_size = 4

// 4.4.3.  Certificate Verify
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
//
struct CertificateVerify {
	algorithm SignatureScheme // u16
	signature []u8            // <0..2^16-1>;
}

@[inline]
fn (cv CertificateVerify) packed_length() int {
	return 4 + cv.signature.len
}

@[direct_array_access; inline]
fn (cv CertificateVerify) pack() ![]u8 {
	if cv.signature.len > max_u16 {
		return error('CertificateVerify.signature exceed')
	}
	mut out := []u8{}
	mut siglen := []u8{len: 2}
	binary.big_endian_put_u16(mut siglen, u16(cv.signature.len))

	out << cv.algorithm.pack()!
	out << siglen
	out << cv.signature

	return out
}

@[direct_array_access; inline]
fn CertificateVerify.unpack(b []u8) !CertificateVerify {
	if b.len < min_certverify_msg_size {
		return error('Bad CertificateVerify bytes: underflow')
	}
	mut r := Buffer.new(b)!
	alg := r.read_u16()!
	algorithm := SignatureScheme.from_u16(alg)!

	// signature
	slen := r.read_u16()!
	signature := r.read_at_least(int(slen))!

	cv := CertificateVerify{
		algorithm: algorithm
		signature: signature
	}
	return cv
}

struct Finished {
	verify_data []u8 // [Hash.length]
}

fn (fin Finished) packed_length() int {
	return fin.verify_data.len
}

fn (fin Finished) pack() ![]u8 {
	mut out := []u8{}
	out << fin.verify_data
	return out
}

fn Finished.unpack(b []u8) !Finished {
	fin := Finished{
		verify_data: b
	}
	return fin
}

const min_newsessionticket_size = 13

// NewSessionTicket
//
//  struct {
//          uint32 ticket_lifetime;
//          uint32 ticket_age_add;
//          opaque ticket_nonce<0..255>;
//          opaque ticket<1..2^16-1>;
//          Extension extensions<0..2^16-2>;
//      } NewSessionTicket;
struct NewSessionTicket {
	tkt_lifetime u32
	tkt_ageadd   u32
	tkt_nonce    []u8 // u8
	ticket       []u8 // u16
	extensions   []Extension
}

fn (st NewSessionTicket) packed_length() int {
	mut n := 0
	n += 8 // ticket lifetime + ageadd
	n += 1
	n += st.tkt_nonce.len
	n += 2
	n += st.ticket.len
	n += st.extensions.packed_length()

	return n
}

@[direct_array_access; inline]
fn (st NewSessionTicket) pack() ![]u8 {
	mut out := []u8{}
	mut tkt := []u8{len: 8}
	binary.big_endian_put_u32(mut tkt[0..4], st.tkt_lifetime)
	binary.big_endian_put_u32(mut tkt[4..8], st.tkt_ageadd)
	out << tkt
	if st.tkt_nonce.len > 255 {
		return error('bad tkt_nonce.len')
	}
	if st.ticket.len > 1 << 16 - 1 {
		return error('bad ticket.len')
	}
	out << u8(st.tkt_nonce.len)
	out << st.tkt_nonce
	mut t := []u8{len: 2}
	binary.big_endian_put_u16(mut t, u16(st.ticket.len))
	out << t
	out << st.ticket
	out << st.extensions.pack()!

	return out
}

@[direct_array_access; inline]
fn NewSessionTicket.unpack(b []u8) !NewSessionTicket {
	if b.len < min_newsessionticket_size {
		return error('NewSessionTicket bytes underflow')
	}
	mut r := Buffer.new(b)!
	lifetime := r.read_u32()!
	ageadd := r.read_u32()!
	nonce_len := r.read_u8()!
	tkt_nonce := r.read_at_least(int(nonce_len))!
	tkt_len := r.read_u16()!
	ticket := r.read_at_least(int(tkt_len))!

	// read extensions
	exts_length := r.peek_u16()!
	exts_data := r.read_at_least(int(exts_length) + 2)!
	exts := ExtensionList.unpack(exts_data)!

	st := NewSessionTicket{
		tkt_lifetime: lifetime
		tkt_ageadd:   ageadd
		tkt_nonce:    tkt_nonce
		ticket:       ticket
		extensions:   exts
	}
	return st
}

// KeyUpdate
// KeyUpdateRequest = u8
enum KeyUpdateRequest as u8 {
	update_not_requested = 0
	update_requested     = 1
	// 255
}

@[inline]
fn KeyUpdateRequest.from_u8(val u8) !KeyUpdateRequest {
	match val {
		0 { return .update_not_requested }
		1 { return .update_requested }
		else { return error('unsupported KeyUpdateRequest value') }
	}
}

@[inline]
fn (ku KeyUpdateRequest) pack() ![]u8 {
	if u8(ku) > max_u8 {
		return error('KeyUpdateRequest value exceed ')
	}
	return [u8(ku)]
}

@[direct_array_access; inline]
fn KeyUpdateRequest.unpack(b []u8) !KeyUpdateRequest {
	if b.len != 1 {
		return error('bad KeyUpdateRequest')
	}
	return KeyUpdateRequest.from_u8(b[0])!
}

struct KeyUpdate {
	kupd_req KeyUpdateRequest
}

fn (ku KeyUpdate) pack() ![]u8 {
	return ku.kupd_req.pack()!
}

@[direct_array_access; inline]
fn KeyUpdate.unpack(b []u8) !KeyUpdate {
	o := KeyUpdateRequest.unpack(b)!
	ku := KeyUpdate{
		kupd_req: o
	}
	return ku
}
