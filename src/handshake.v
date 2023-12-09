module tls13

import math
import crypto.hmac
import encoding.binary
import blackshirt.buffer
import blackshirt.u24

const helloretry_magic = [u8(0xCF), 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
	0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09,
	0xE2, 0xC8, 0xA8, 0x33, 0x9C]

const tls12_random_magic = [u8(0x44), 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]

const tls11_random_magic = [u8(0x44), 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]

// HandshakeType = u8
enum HandshakeType {
	hello_request        = 0 // _RESERVED
	client_hello         = 1
	server_hello         = 2
	hello_verify_request = 3 // _RESERVED
	new_session_ticket   = 4
	end_of_early_data    = 5
	hello_retry_request  = 6 // _RESERVED =
	encrypted_extensions = 8
	certificate          = 11
	server_key_exchange  = 12 // _RESERVED
	certificate_request  = 13
	server_hello_done    = 14 // _RESERVED
	certificate_verify   = 15
	client_key_exchange  = 16 // _RESERVED
	finished             = 20
	certificate_url      = 21 // _RESERVED
	certificate_status   = 22 // _RESERVED
	supplemental_data    = 23 // _RESERVED
	key_update           = 24
	message_hash         = 254
}

fn (h HandshakeType) pack() ![]u8 {
	if int(h) > math.max_u8 {
		return error('HandshakeType exceed limit')
	}
	return [u8(h)]
}

fn HandshakeType.unpack(b []u8) !HandshakeType {
	if b.len != 1 {
		return error('bad length of HandshakeType bytes')
	}
	return unsafe { HandshakeType(b[0]) }
}

fn HandshakeType.from(b u8) !HandshakeType {
	match b {
		0x00 {
			return HandshakeType.hello_request
		}
		0x01 {
			return HandshakeType.client_hello
		}
		0x02 {
			return HandshakeType.server_hello
		}
		0x03 {
			return HandshakeType.hello_verify_request
		}
		0x04 {
			return HandshakeType.new_session_ticket
		}
		0x05 {
			return HandshakeType.end_of_early_data
		}
		0x06 {
			return HandshakeType.hello_retry_request
		}
		0x08 {
			return HandshakeType.encrypted_extensions
		}
		0x0b {
			return HandshakeType.certificate
		}
		0x0c {
			return HandshakeType.server_key_exchange
		}
		0x0d {
			return HandshakeType.certificate_request
		}
		0x0e {
			return HandshakeType.server_hello_done
		}
		0x0f {
			return HandshakeType.certificate_verify
		}
		0x10 {
			return HandshakeType.client_key_exchange
		}
		0x14 {
			return HandshakeType.finished
		}
		0x15 {
			return HandshakeType.certificate_url
		}
		0x16 {
			return HandshakeType.certificate_status
		}
		0x17 {
			return HandshakeType.supplemental_data
		}
		0x18 {
			return HandshakeType.key_update
		}
		0xfe {
			return HandshakeType.message_hash
		}
		else {
			return error('Unsupported value for HandshakeType')
		}
	}
}

const handshake_header_size = 4

// Handshake represents Tls 1.3 handshake message.
struct Handshake {
	msg_type HandshakeType
	length   int // max_u24
	payload  []u8
}

fn (h Handshake) packed_length() int {
	mut n := 0
	n += 1
	n += 3
	n += h.payload.len

	return n
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

fn (h Handshake) pack() ![]u8 {
	if h.length != h.payload.len {
		return error('Unmatched Handshake length')
	}
	if h.length > u24.max_u24 || h.payload.len > u24.max_u24 {
		return error('Handshake length exceed limit')
	}
	mut out := []u8{}
	msg_type := h.msg_type.pack()!
	length := u24.from_int(h.length)!
	bytes_of_length := length.bytes()

	// writes bytes to out
	out << msg_type
	out << bytes_of_length
	out << h.payload

	return out
}

fn Handshake.unpack(b []u8) !Handshake {
	if b.len < tls13.handshake_header_size {
		return error('Underflow of Handshake bytes')
	}
	mut r := buffer.new_reader(b)
	tipe := r.read_byte()!
	msg_type := unsafe { HandshakeType(tipe) }

	// bytes of length
	bytes_of_length := r.read_at_least(3)!
	val := u24.from_bytes(bytes_of_length)!
	length := val.to_int()!

	// read Handshake payload
	payload := r.read_at_least(length)!
	assert payload.len == length
	out := Handshake{
		msg_type: msg_type
		length: length
		payload: payload
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
	if b.len < tls13.handshake_header_size {
		return error('unpack_to_multi_handshakes: Underflow of Handshakes bytes')
	}
	mut hs := []Handshake{}
	mut i := 0
	mut r := buffer.new_reader(b)
	for i < b.len {
		mut buf := []u8{}
		tp := r.read_byte()!
		bytes_length, ln := r.read_sized(3)!
		assert ln == 3
		val := u24.from_bytes(bytes_length)!
		length := val.to_int()!
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
		length: length
		payload: payload
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

struct ClientHello {
mut:
	legacy_version             ProtoVersion = ProtoVersion(0x0303) // TLS v1.2
	random                     []u8 // 32 bytes
	legacy_session_id          []u8 // <0..32>;
	cipher_suites              []CipherSuite // <2..2^16-2>;
	legacy_compression_methods u8 //<1..2^8-1>;
	extensions                 []Extension // <8..2^16-1>;
}

fn (ch ClientHello) packed_length() int {
	mut n := 0
	n += 2 // ProtoVersion
	n += 32 // 32 bytes of random
	n += 1 // one byte of legacy_session_id.len
	n += ch.legacy_session_id.len
	n += ch.cipher_suites.packed_length()
	n += 1 // one byte of length compression_method
	n += 1 // one byte compression_method
	n += ch.extensions.packed_length()

	return n
}

fn (ch ClientHello) pack() ![]u8 {
	if ch.legacy_session_id.len > 32 {
		return error('Session id length exceed')
	}
	if ch.random.len != 32 {
		return error('Bad random length')
	}
	mut out := []u8{}

	out << ch.legacy_version.pack()!
	out << ch.random
	out << u8(ch.legacy_session_id.len)
	out << ch.legacy_session_id
	out << ch.cipher_suites.pack()!
	out << u8(0x01)
	out << ch.legacy_compression_methods
	out << ch.extensions.pack()!

	return out
}

fn ClientHello.unpack(b []u8) !ClientHello {
	// minimal length checked here inculdes minimal of cipher_suites and extensionz length
	// minimal bytes lengtb = 2 + 32 + 1 + 0 + 2 + 2 + 1 + 1 + 2 + 8
	if b.len < 51 {
		return error('Bad ClientHello bytes: underflow ')
	}
	mut r := buffer.new_reader(b)
	// version,
	ver := r.read_u16()!
	version := unsafe { ProtoVersion(ver) }
	if version != tls_v12 {
		return error('Bad protocol version: violated')
	}
	// random
	random := r.read_at_least(32)!
	// legacy_session_id
	legn := r.read_byte()!
	if legn > 32 {
		return error('legacy_session_id exceed')
	}
	legacy := r.read_at_least(int(legn))!

	// read ciphersuites length + underlying arrays
	ciphers_len := r.peek_u16()!
	ciphers_data := r.read_at_least(int(ciphers_len) + 2)!
	ciphers := CipherSuiteList.unpack(ciphers_data)!

	// read commpression method, should one byte length
	cm := r.read_byte()!
	if cm != u8(0x01) {
		return error('Bad compression_method length')
	}
	cmethd := r.read_byte()!

	// read remianing bytes extension list
	exts_len := r.peek_u16()!
	exts_bytes := r.read_at_least(int(exts_len) + 2)!
	extensions := ExtensionList.unpack(exts_bytes)!

	ch := ClientHello{
		legacy_version: version
		random: random
		legacy_session_id: legacy
		cipher_suites: ciphers
		legacy_compression_methods: cmethd
		extensions: extensions
	}
	return ch
}

// parse_server_hello parse ServerHello with associated ClientHello
fn (ch ClientHello) parse_server_hello(sh ServerHello) !bool {
	// A client which receives a cipher suite that was not offered MUST abort the handshake
	if !ch.cipher_suites.is_exist(sh.cipher_suite) {
		ae := Alert{
			level: .fatal
			desc: .illegal_parameter
		}
		return tls_error(ae, "ClientHello.cipher_suites doesn't contains server cipher_suite")
	}
	// TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below
	// MUST check that the last 8 bytes are not equal to either of these values.
	if sh.random.len != 32 {
		ae := Alert{
			level: .fatal
			desc: .illegal_parameter
		}
		return tls_error(ae, 'Bad ServerHello.random length')
	}
	last8 := sh.random[24..31]
	if hmac.equal(last8, tls13.tls12_random_magic) || hmac.equal(last8, tls13.tls12_random_magic) {
		ae := Alert{
			level: .fatal
			desc: .unexpected_message
		}
		return tls_error(ae, 'Bad downgrade ServerHello.random detected')
	}
	// A client which receives a legacy_session_id_echo field that does not match what it sent
	// in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
	if !hmac.equal(ch.legacy_session_id, sh.legacy_session_id_echo) {
		ae := Alert{
			level: .fatal
			desc: .illegal_parameter
		}
		return tls_error(ae, "Server and Client sessid doesn't match")
	}
	// If the "supported_versions" extension in the ServerHello contains a version not offered
	// by the client or contains a version prior to TLS 1.3, the client MUST abort
	// the handshake with an "illegal_parameter" alert.
	contains_spv := sh.extensions.any(it.tipe == .supported_versions)
	if contains_spv {
		server_spv := sh.extensions.map(it.tipe == .supported_versions)
		client_spv := ch.extensions.map(it.tipe == .supported_versions)
		if server_spv != client_spv {
			ae := Alert{
				level: .fatal
				desc: .illegal_parameter
			}
			return tls_error(ae, "Server and Client SupportedVersion doesn't match")
		}
	}
	return true
}

// ServerHello
//
struct ServerHello {
mut:
	legacy_version            ProtoVersion = tls_v12
	random                    []u8
	legacy_session_id_echo    []u8 // <0..32>;
	cipher_suite              CipherSuite
	legacy_compression_method u8 = 0x00
	extensions                []Extension // <6..2^16-1>;
}

fn (sh ServerHello) packed_length() int {
	mut n := 0

	n += 2
	n += 32
	n += 1
	n += sh.legacy_session_id_echo.len
	n += sh.cipher_suite.packed_length()
	n += 1 // compression_method
	n += sh.extensions.packed_length()

	return n
}

fn (sh ServerHello) pack() ![]u8 {
	// we do early simple check of validity.
	if sh.random.len != 32 {
		return error('Bad random length')
	}
	if sh.legacy_session_id_echo.len > 32 {
		return error('Bad legacy_session_id_echo length')
	}
	mut out := []u8{}

	out << sh.legacy_version.pack()!
	out << sh.random
	out << u8(sh.legacy_session_id_echo.len)
	out << sh.legacy_session_id_echo
	out << sh.cipher_suite.pack()!
	out << sh.legacy_compression_method
	out << sh.extensions.pack()!

	return out
}

fn ServerHello.unpack(b []u8) !ServerHello {
	// min = 2 + 32 + 1 + 0 + 2 + 1 + 2 + 6
	if b.len < 46 {
		return error('Bad ServerHello bytes: underflow')
	}
	mut r := buffer.new_reader(b)
	// version
	ver := r.read_u16()!
	version := unsafe { ProtoVersion(ver) }
	if version != tls_v12 {
		return error('Bad ProtoVersion legacy_version')
	}
	random := r.read_at_least(32)!
	// legacy_session_id_echo
	s := r.read_byte()!
	if s > 32 {
		return error('Bad legacy_session_id_echo length')
	}
	sessid := r.read_at_least(int(s))!
	cp := r.read_at_least(2)!
	cipher := CipherSuite.unpack(cp)!
	comp_meth := r.read_byte()!

	// read remianing bytes extension list
	exts_ln := r.peek_u16()!
	exts_bytes := r.read_at_least(int(exts_ln) + 2)!
	extensions := ExtensionList.unpack(exts_bytes)!

	sh := ServerHello{
		legacy_version: version
		random: random
		legacy_session_id_echo: sessid
		cipher_suite: cipher
		legacy_compression_method: comp_meth
		extensions: extensions
	}
	return sh
}

fn (sh ServerHello) is_hrr() bool {
	return hmac.equal(sh.random, tls13.helloretry_magic)
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

// CertificateRequest handling
struct CertificateRequest {
	crq_ctx    []u8        // <0..2^8-1>;
	extensions []Extension // <2..2^16-1>;
}

fn (cr CertificateRequest) pack() ![]u8 {
	if cr.crq_ctx.len > int(math.max_u8) {
		return error('certreq context len exceed')
	}
	mut out := []u8{}
	exts := cr.extensions.pack()!

	out << u8(cr.crq_ctx.len)
	out << cr.crq_ctx
	out << exts

	return out
}

fn CertificateRequest.unpack(b []u8) !CertificateRequest {
	if b.len < 3 {
		return error('bad CertificateRequest bytes')
	}
	mut r := buffer.new_reader(b)
	crctx_len := r.read_byte()!
	crctx := r.read_at_least(int(crctx_len))!
	exts_len := r.peek_u16()!
	exts_bytes := r.read_at_least(int(exts_len) + 2)!
	exts := ExtensionList.unpack(exts_bytes)!

	cr := CertificateRequest{
		crq_ctx: crctx
		extensions: exts
	}
	return cr
}

// CertificateType = u8
enum CertificateType {
	x509           = 0
	openpgp        = 1 // reserved
	raw_public_key = 2
	unknown        = 255 // unofficial
}

fn (ct CertificateType) pack() ![]u8 {
	if int(ct) > math.max_u8 {
		return error('CertificateType exceed')
	}
	return [u8(ct)]
}

fn CertificateType.unpack(b []u8) !CertificateType {
	if b.len != 1 {
		return error('Bad CertificateType bytes')
	}
	return unsafe { CertificateType(b[0]) }
}

struct CertificateEntry {
	certificate_type CertificateType
	cert_data        []u8        //<1..2^24-1>;
	extensions       []Extension //<0..2^16-1>;
}

fn (ce CertificateEntry) packed_length() int {
	mut n := 0
	n += 3
	n += ce.cert_data.len
	n += ce.extensions.packed_length()

	return n
}

fn (ce CertificateEntry) pack() ![]u8 {
	match ce.certificate_type {
		.x509, .raw_public_key {
			// FIXME: is it should handle differently?
			if ce.cert_data.len > 1 << 24 - 1 {
				return error('Certificate data exceed')
			}
			cert_length := u24.from_int(ce.cert_data.len)!
			cert_bytes_length := cert_length.bytes()

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

fn CertificateEntry.unpack(b []u8) !CertificateEntry {
	if b.len < 5 {
		return error('Bad CertificateEntry bytes: underflow')
	}
	mut r := buffer.new_reader(b)
	// read 3 bytes length of cert_data
	bytes_length := r.read_at_least(3)!
	val := u24.from_bytes(bytes_length)!
	length := val.to_int()!
	if length > 1 << 24 - 1 {
		return error('CertificateEntry.cert_data exceed')
	}
	cert_data := r.read_at_least(length)!

	// read extensions
	exts_length := r.peek_u16()!
	exts_data := r.read_at_least(int(exts_length) + 2)!
	exts := ExtensionList.unpack(exts_data)!

	ce := CertificateEntry{
		cert_data: cert_data
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
	if cel_length > 1 << 24 - 1 {
		return error('CertificateEntry list exceed')
	}
	mut out := []u8{}
	celist_length := u24.from_int(cel_length)!
	celist_bytes := celist_length.bytes()

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
	mut r := buffer.new_reader(b)

	// read 3 bytes of length
	bytes_of_length := r.read_at_least(3)!
	val := u24.from_bytes(bytes_of_length)!
	length := val.to_int()!

	// remaining bytes was smaller then length
	if r.remainder() < length {
		return error('Underflow of remaining of CertificateEntryList bytes')
	}
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

struct Certificate {
	cert_req_ctx []u8 // <0..2^8-1>;
	cert_list    []CertificateEntry // <0..2^24-1>;
}

fn (c Certificate) packed_length() int {
	mut n := 0
	n += 1
	n += c.cert_req_ctx.len
	n += c.cert_list.packed_length()

	return n
}

fn (c Certificate) pack() ![]u8 {
	mut out := []u8{}

	if c.cert_req_ctx.len > math.max_u8 {
		return error('Bad cert_req_ctx length: overflow')
	}
	out << u8(c.cert_req_ctx.len)
	out << c.cert_req_ctx

	cert_list := c.cert_list.pack()!
	out << cert_list

	return out
}

fn Certificate.unpack(b []u8) !Certificate {
	if b.len < 4 {
		return error('Bad Certificate bytes: underflow')
	}
	mut r := buffer.new_reader(b)
	// read cert_req_ctx
	cr := r.read_byte()!
	creq := r.read_at_least(int(cr))!

	// peek 3 bytes of length
	bytes_of_length, _ := r.peek_sized(3)!
	val := u24.from_bytes(bytes_of_length)!
	length := val.to_int()!

	certlist_payload := r.read_at_least(length + 3)!
	cert_list := CertificateEntryList.unpack(certlist_payload)!

	c := Certificate{
		cert_req_ctx: creq
		cert_list: cert_list
	}
	return c
}

struct CertificateVerify {
	algorithm SignatureScheme
	signature []u8 // <0..2^16-1>;
}

fn (cv CertificateVerify) packed_length() int {
	mut n := 0
	n += cv.algorithm.packed_length()
	n += 2
	n += cv.signature.len

	return n
}

fn (cv CertificateVerify) pack() ![]u8 {
	if cv.signature.len > 1 << 16 - 1 {
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

fn CertificateVerify.unpack(b []u8) !CertificateVerify {
	if b.len < 4 {
		return error('Bad CertificateVerify bytes: underflow')
	}
	mut r := buffer.new_reader(b)
	alg := r.read_u16()!
	algorithm := unsafe { SignatureScheme(alg) }

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
	tkt_nonce    []u8
	ticket       []u8
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

fn NewSessionTicket.unpack(b []u8) !NewSessionTicket {
	if b.len < 13 {
		return error('NewSessionTicket bytes underflow')
	}
	mut r := buffer.new_reader(b)
	lifetime := r.read_u32()!
	ageadd := r.read_u32()!
	nonce_len := r.read_byte()!
	tkt_nonce := r.read_at_least(int(nonce_len))!
	tkt_len := r.read_u16()!
	ticket := r.read_at_least(int(tkt_len))!

	// read extensions
	exts_length := r.peek_u16()!
	exts_data := r.read_at_least(int(exts_length) + 2)!
	exts := ExtensionList.unpack(exts_data)!

	st := NewSessionTicket{
		tkt_lifetime: lifetime
		tkt_ageadd: ageadd
		tkt_nonce: tkt_nonce
		ticket: ticket
		extensions: exts
	}
	return st
}

// KeyUpdate
// KeyUpdateRequest = u8
enum KeyUpdateRequest {
	update_not_requested = 0
	update_requested     = 1
	// 255
}

fn (ku KeyUpdateRequest) pack() ![]u8 {
	if int(ku) > int(math.max_u8) {
		return error('KeyUpdateRequest value exceed ')
	}
	return [u8(ku)]
}

fn KeyUpdateRequest.unpack(b []u8) !KeyUpdateRequest {
	if b.len != 1 {
		return error('bad KeyUpdateRequest')
	}
	return unsafe { KeyUpdateRequest(b[0]) }
}

struct KeyUpdate {
	req_update KeyUpdateRequest
}

fn (ku KeyUpdate) pack() ![]u8 {
	return ku.req_update.pack()!
}

fn KeyUpdate.unpack(b []u8) !KeyUpdate {
	o := KeyUpdateRequest.unpack(b)!
	ku := KeyUpdate{
		req_update: o
	}
	return ku
}
