module tls13

import crypto.hmac
import encoding.binary
import crypto.internal.subtle

// helloretry_magic was special constant used in HelloRetryRequest message but
// with Random set to the special value of the SHA-256 of "HelloRetryRequest"
// ie, 	CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
// 		C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
const helloretry_magic = [u8(0xCF), 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
	0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09,
	0xE2, 0xC8, 0xA8, 0x33, 0x9C]

const tls12_random_magic = [u8(0x44), 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]
const tls11_random_magic = [u8(0x44), 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]

// minimal handshake message size
const min_hskmsg_size = 4
// Used in ClientHello and ServerHello
const min_random_size = 32
const max_sessid_size = 32

// Handshake represents Tls 1.3 handshake message.
//
@[noinit]
struct Handshake {
mut:
	// tipe was u8 value
	tipe HandshakeType
	// max_u24 lengtb
	payload []u8
}

@[inline]
fn (h Handshake) packed_length() int {
	return min_hskmsg_size + h.payload.len
}

fn (h Handshake) expect_hsk_type(hsktype HandshakeType) bool {
	return h.tipe == hsktype
}

// is_hrr checks whether this handshake message is HelloRetryRequest message.
// two cases here, first of it, the tipe is hello_retry_request type and the second
// if the tipe is .server_hello with random value contains helloretry_magic constant.
// otherwise, its not HelloRetryRequest message.
fn (h Handshake) is_hrr() !bool {
	if h.tipe == .hello_retry_request {
		return true
	}
	if h.tipe == .server_hello {
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
	tipe := h.tipe.pack()!
	length := Uint24.from_int(h.length)!
	bytes_of_length := length.bytes()!

	// writes bytes into out
	out << tipe
	out << bytes_of_length
	out << h.payload

	return out
}

@[direct_array_access; inline]
fn Handshake.unpack(b []u8) !Handshake {
	if b.len < min_hskmsg_size {
		return error('Underflow of Handshake bytes')
	}
	mut r := new_buffer(b)!
	tp := r.read_u8()!
	tipe := HandshakeType.from_u8(tp)!

	// bytes of length
	bytes_of_length := r.read_at_least(3)!
	val := Uint24.from_bytes(bytes_of_length)!
	length := int(val)

	// read Handshake payload
	payload := r.read_at_least(length)!
	assert payload.len == length
	out := Handshake{
		tipe:    tipe
		length:  length
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

// filtered_msg_type filters []Handshake based on provided tipe, its maybe null or contains filtered type.
fn (hs []Handshake) filtered_hsk_with_type(msgtype HandshakeType) []Handshake {
	return hs.filter(it.tipe == msgtype)
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
	mut r := new_buffer(b)!
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

fn (h HandshakePayload) tipe() !HandshakeType {
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
	tipe := h.tipe()!
	payload := h.pack()!
	length := payload.len

	hsk := Handshake{
		tipe:    tipe
		length:  length
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

// TLS 1.3 ClientHello handshake message
//
// See the spec at 4.1.2.  Client Hello
//
// Minimal length checked here inculdes minimal of csuites and xslist length
// Minimal bytes lengtb = 2 + 32 + 1 + 0 + 2 + 2 + 1 + 1 + 2 + 8
//
const min_chello_size = 51
const min_chello_cmeths_size = 1
const max_chello_cmeths_size = max_u8

// TLS 1.3 ClientHello handshake message
//
@[noinit]
struct ClientHello {
mut:
	version TlsVersion = tls_v12 // TLS v1.2
	// 32-bytes of random bytes
	random []u8
	// legacy session id, <0..32> length
	sessid []u8
	// list of client supported ciphersuite <2..2^16-2>
	csuites []CipherSuite
	// legacy list of compression_method, <1..2^8-1>;
	cmeths []u8
	// client extension list <8..2^16-1>;
	xslist []Extension
}

// check_chello validates ClientHello c
@[inline]
fn check_chello(c ClientHello) ! {
	// TODO: should ClientHello version == TLS 1.2 ?
	if c.sessid.len > 32 {
		return error('Session id length exceed')
	}
	if c.random.len != 32 {
		return error('Bad random length')
	}
	// non-null ciphersuites
	if c.csuites.len < 1 {
		return error('null-length of ciphersuites was not allowed')
	}
	if c.cmeths.len < min_chello_cmeths_size || c.cmeths.len > max_chello_cmeths_size {
		return error('invalid compression_method size')
	}
	// TODO: check another constrains
	// xslist<8..2^16-1>;
}

// packlen_chello returns the length of serialized ClientHello c.
@[inline]
fn packlen_chello(c ClientHello) int {
	mut n := 0
	// u16-sized TlsVersion
	n += 2
	// 32 bytes of random
	n += 32
	// one byte of sessid.len and sessid
	n += 1
	n += ch.sessid.len

	// Arrays of ciphersuite was prepended by u16-sized length
	n += cap_u16list_withlen[CipherSuite](c.csuites, 2)

	n += 1 // one byte of length compression_method
	n += c.cmeths.len // compression_method values

	// extension list with prepended u16-sized length
	n += packlen_xslist_withlen(c.xslist)

	return n
}

// pack_chello encodes ClientHello c into bytes array
@[inline]
fn pack_chello(c ClientHello) ![]u8 {
	// validates ClientHello and setup output buffer
	check_chello(c)!
	mut out := []u8{cap: packlen_chello(c)}

	// encodes ClientHello version, its an u16 value
	out << pack_u16item[TlsVersion](c.version)

	// encodes ClientHello random bytes
	out << c.random

	// encodes ClientHello sessid, prepended with 1-byte length
	out << u8(c.sessid.len)
	out << c.sessid

	// encodes CipherSuite arrays, prepended with 2-bytes length.
	out << pack_u16list_withlen[CipherSuite](c.csuites, 2)!

	// encodes ClientHello compression_method arrays with one-byte length
	out << u8(c.cmeths.len)
	out << c.cmeths

	// encodes extension list prepended with u16-sized length
	out << pack_extlist_withlen(c.xslist)!

	return out
}

// parse_chello decodes bytes into ClientHello and validates the result.
@[direct_array_access; inline]
fn parse_chello(bytes []u8) !ClientHello {
	if bytes.len < min_chello_size {
		return error('underflow client hello bytes')
	}
	mut r := new_buffer(bytes)!
	// read two-bytes version
	val := r.read_u16()
	ver := new_tlsversion(val)!

	// read 32-bytes of random bytes
	random := r.read_at_least(32)!

	// read one-byte sessid length and sessid bytes
	sid := r.read_u8()!
	sid_bytes := r.read_at_least(int(sid))!

	// read cipher suites list with prepended 2-bytes length
	ciphers_len := r.read_u16()!
	ciphers_data := r.read_at_least(int(ciphers_len))!
	csuites := parse_u16list[CipherSuite](ciphers_data, new_csuite)!

	// read compression_method length and the contents of compression_method bytes
	cm := r.read_u8()
	cmeths := r.read_at_least(int(cm))!

	// read extension list with prepended length
	xlen := r.read_u16()
	xs_bytes := r.read_at_least(int(xlen))!
	xs := parse_extlist(xs_bytes)!

	// build the result
	ch := ClientHello{
		version: ver
		random:  random
		sessid:  sid_bytes
		csuites: csuites
		cmeths:  cmeths
		xslist:  xs
	}
	// validates the result
	check_chello(ch)!

	return ch
}

// parse_server_hello parse ServerHello with associated ClientHello
fn (ch ClientHello) parse_server_hello(sh ServerHello) !bool {
	// A client which receives a cipher suite that was not offered MUST abort the handshake
	if !ch.csuites.is_exist(sh.csuite) {
		return error("ClientHello.csuites doesn't contains server csuite")
	}
	// TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below
	// MUST check that the last 8 bytes are not equal to either of these values.
	if sh.random.len != 32 {
		return error('Bad ServerHello.random length')
	}
	last8 := sh.random[24..31]
	if subtle.constant_time_compare(last8, tls12_random_magic) == 1
		|| subtle.constant_time_compare(last8, tls12_random_magic) == 1 {
		return error('Bad downgrade ServerHello.random detected')
	}
	// A client which receives a sessid field that does not match what it sent
	// in the ClientHello MUST abort the handshake with an "illegal_parameter" alert.
	if !(subtle.constant_time_compare(ch.sessid, sh.sessid) == 1) {
		return error("Server and Client sessid doesn't match")
	}
	// If the "supported_versions" extension in the ServerHello contains a version not offered
	// by the client or contains a version prior to TLS 1.3, the client MUST abort
	// the handshake with an "illegal_parameter" alert.
	contains_spv := sh.xslist.any(it.tipe == .supported_versions)
	if contains_spv {
		server_spv := sh.xslist.map(it.tipe == .supported_versions)
		client_spv := ch.xslist.map(it.tipe == .supported_versions)
		if server_spv != client_spv {
			return error("Server and Client SupportedVersion doesn't match")
		}
	}
	return true
}

// TLS 1.3 ServerHello handshake message
//
const min_shello_size = 46

// 4.1.3.  Server Hello
//
@[noinit]
struct ServerHello {
mut:
	version TlsVersion = tls_v12
	random  []u8
	sessid  []u8 // <0..32>;
	// choosen cipher suite
	csuite CipherSuite
	// choosen compression method
	cmeth  u8 = 0x00
	xslist []Extension // <6..2^16-1>;
}

@[inline]
fn (s ServerHello) validate_srvhello() ! {
	return error('TODO')
}

// size_srvhello return the length of serialized single item of ServerHello s
@[inline]
fn size_srvhello(s ServerHello) int {
	mut n := 0
	// 2-bytes of TlsVersion
	n += 2
	// 32-bytes of random
	n += 32
	// 1-byte of sessid.len plus sessid.len
	n += sessid.len + 1
	// 2-bytes ciphersuite
	n += 2
	// 1-byte compression_method
	n += 1
	// extension list with prepended 2-bytes length
	n += packlen_xslist_withlen(s.xslist)

	return n
}

// pack_srvhello encodes a single item of ServerHello s into bytes array.
@[inline]
fn pack_srvhello(s ServerHello) ![]u8 {
	s.validate_srvhello()!
	mut out := []u8{cap: size_srvhello(s)}

	// encodes version, its an u16 value
	out << pack_u16item[TlsVersion](s.version)

	// encodes 32-bytes of ServerHello random
	out << s.random

	// encodes ServerHello sessid, prepended with 1-byte length
	out << pack_raw_withlen(s.sessid, .size1)!

	// encodes choosen CipherSuite, its an u16-based value
	out << pack_u16item[CipherSuite](s.csuite)

	// encodes 1-byte ServerHello compression_method
	out << s.cmeth

	// encodes extension list prepended with 2-bytes length
	out << pack_objlist_withlen[TlsExtension](s.xslist, pack_srvhello, size_srvhello,
		.size2)!

	return out
}

// parse_srvhello decodes bytes array into ServerHello and validates them.
@[direct_array_access]
fn parse_srvhello(bytes []u8) !ServerHello {
	if bytes.len < min_shello_size {
		return error('underflow ServerHello bytes')
	}
	mut r := new_buffer(bytes)!
	// read 2-bytes version
	val := r.read_u16()
	ver := new_tlsversion(val)!

	// read 32-bytes of random bytes
	random := r.read_at_least(32)!

	// read 1-byte sessid length and sessid bytes
	sid := r.read_u8()!
	sid_bytes := r.read_at_least(int(sid))!

	// read 2-bytes ciphersuite
	cs := r.read_u16()!
	csuite := new_csuite(cs)!

	// read 1-byte compression_method
	cmeth := r.read_u8()!

	// read extension list with prepended length
	xlen := r.read_u16()
	xs_bytes := r.read_at_least(int(xlen))!
	xs := parse_extlist(xs_bytes)!

	// build ServerHello message
	sh := ServerHello{
		version: ver
		random:  random
		sessid:  sid_bytes
		csuite:  csuite
		cmeth:   cmeth
		xslist:  xs
	}
	// validates
	sh.validate_srvhello()!

	return sh
}

// HelloRetryRequest
//
@[noinit]
struct HelloRetryRequest {
	ServerHello
}

// is_hrr check whether this ServerHello is a HelloRetryRequest message
@[inline]
fn (sh ServerHello) is_hrr() bool {
	return subtle.constant_time_compare(sh.random, helloretry_magic) == 1
}

// 4.5.  End of Early Data
// See https://datatracker.ietf.org/doc/html/rfc8446#section-4.5
//
struct EndOfEarlyData {}

@[inline]
fn pack_eod(e EndOfEarlyData) []u8 {
	return []u8{}
}

@[inline]
fn parse_eod(bytes []u8) EndOfEarlyData {
	return EndOfEarlyData{}
}

@[noinit]
struct EncryptedExtensions {
mut:
	xslist []Extension // <0..2^16-1>
}

// B.3.2.  Server Parameters Messages
// 4.3.2.  Certificate Request
//
// struct {
//        opaque certificate_request_context<0..2^8-1>;
//        Extension extensions<2..2^16-1>;
//    } CertificateRequest;
//
const min_creq_size = 3

@[noinit]
struct CertificateRequest {
mut:
	opaque []u8        // <0..2^8-1>;
	xslist []Extension // <2..2^16-1>;
}

// check_ce does basic check validation on CertificateRequest cr.
@[inline]
fn (cr CertificateRequest) check_creq() ! {
	if cr.opaque.len > max_u8 {
		return error('certificate request opaque exceed max_u8')
	}
}

// packlen_creq returns the length of serialized CertificateRequest cr
@[inline]
fn packlen_creq(cr CertificateRequest) int {
	mut n := 0
	n += 1 // cr.opaque.len
	n += cr.opaque.len
	n += packlen_xslist_withlen(cr.xslist)
	return n
}

// pack_creq encodes CertificateRequest cr into bytes array.
@[direct_array_access; inline]
fn pack_creq(cr CertificateRequest) ![]u8 {
	cr.check_creq()!
	mut out := []u8{cap: packlen_creq(cr)}

	// encodes certificate request context opaque and their 1-byte length
	out << u8(cr.opaque.len)
	out << cr.opaque

	// encodes certificate request extension list with ltheir ength
	out << pack_extlist_withlen(cr.xslist)!

	return out
}

// parse_creq decodes bytes b into CertificateEntry
@[direct_array_access; inline]
fn parse_creq(b []u8) !CertificateRequest {
	if b.len < min_creq_size {
		return error('Bad CertificateRequest bytes: underflow')
	}
	mut r := new_buffer(b)!

	// read 1-bytes length of opaque
	opaque_len := r.read_u8()!
	opaque_data := r.read_at_least(int(opaque_len))!

	// read extension list with prepended length
	xlen := r.read_u16()
	xs_bytes := r.read_at_least(int(xlen))!
	xs := parse_extlist(xs_bytes)!

	cr := CertificateRequest{
		opaque: opaque_data
		xslist: xs
	}
	cr.check_creq()!

	return cr
}

// 4.4.2.  Certificate
//
// CertificateType = u8
enum CertificateType as u8 {
	x509           = 0
	openpgp        = 1 // reserved
	raw_public_key = 2
	unknown        = 255 // unofficial
}

// new_certtype creates a CertificateType from byte value
@[inline]
fn new_certtype(val u8) !CertificateType {
	match val {
		0 { return .x509 }
		1 { return .openpgp }
		2 { return .raw_public_key }
		255 { return .unknown }
		else { return error('unsupported CertificateType value') }
	}
}

// CertificateEntry
//
// struct {
//       select (certificate_type) {
//            case RawPublicKey:
//              /* From RFC 7250 ASN.1_subjectPublicKeyInfo */
//              opaque ASN1_subjectPublicKeyInfo<1..2^24-1>;
//
//            case X509:
//              opaque cert_data<1..2^24-1>;
//        };
//        Extension extensions<0..2^16-1>;
//    } CertificateEntry;
//
const min_centry_size = 5
const max_opaque_size = max_u24 // 1 << 24 - 1

// CertificateEntry is a part of Certificate structure
//
@[noinit]
struct CertificateEntry {
mut:
	opaque []u8        //<1..2^24-1>;
	xslist []Extension //<0..2^16-1>;
}

// check_ce does basic check validation on ce
@[inline]
fn (ce CertificateEntry) check_ce() ! {
	if ce.opaque.len > max_u24 {
		return error('certificate entry data exceed max_u24')
	}
}

// packlen_centry returns the length of serialized CertificateEntry ce
@[inline]
fn packlen_centry(ce CertificateEntry) int {
	mut n := 0
	n += 3 // ce.opaque.len
	n += ce.opaque.len
	n += packlen_xslist_withlen(ce.xslist)
	return n
}

// pack_centry encodes ce into bytes array.
@[direct_array_access; inline]
fn pack_centry(ce CertificateEntry) ![]u8 {
	mut out := []u8{cap: packlen_centry(ce)}

	// FIXME: different type should be handled differently?
	if ce.opaque.len > max_opaque_size {
		return error('Certificate data exceed')
	}
	// encodes certificate data and their length
	bol3 := u24_from_int(ce.opaque.len)!
	out << bol3.bytes()!
	out << ce.opaque

	// encodes certificate extension list with length
	out << pack_extlist_withlen(c.xslist)!

	return out
}

// parse_centry decodes bytes b into CertificateEntry
@[direct_array_access; inline]
fn parse_centry(b []u8) !CertificateEntry {
	if b.len < min_centry_size {
		return error('Bad CertificateEntry bytes: underflow')
	}
	mut r := new_buffer(b)!

	// read 3 bytes length of opaque
	bol3 := r.read_at_least(3)!
	opaque_len := u24_from_bytes(bol3)!
	opaque := r.read_at_least(int(opaque_len))!

	// read extension list with prepended length
	xlen := r.read_u16()
	xs_bytes := r.read_at_least(int(xlen))!
	xs := parse_extlist(xs_bytes)!

	ce := CertificateEntry{
		opaque: opaque
		xslist: xs
	}
	ce.check_ce()!

	return ce
}

// CertificateEntry list certificate_list<0..2^24-1>;
//
// packlen_celist returns the length of encoded cs without the length part.
@[inline]
fn packlen_celist(cs []CertificateEntry) int {
	mut n := 0
	for c in cs {
		n += packlen_centry(c)
	}
	return n
}

// packlen_celist_withlen returns encoded cs with prepended n-bytes length, n should be 3
@[inline]
fn packlen_celist_withlen(cs []CertificateEntry, n int) int {
	match n {
		1 { return 1 + packlen_celist(cs) }
		2 { return 2 + packlen_celist(cs) }
		3 { return 3 + packlen_celist(cs) }
		4 { return 4 + packlen_celist(cs) }
		else { panic('unsupported length') }
	}
}

// pack_celist encodes cs into bytes array without the length part
@[direct_array_access; inline]
fn pack_celist(cs []CertificateEntry) ![]u8 {
	mut out := []u8{cap: packlen_celist(cs)}
	for c in cs {
		out << pack_centry(c)!
	}
	return out
}

// pack_celist_withlen encodes array of CertificateEntry cs into bytes array prepended with n-bytes length
@[direct_array_access; inline]
fn pack_celist_withlen(cs []CertificateEntry, n int) ![]u8 {
	mut out := []u8{cap: packlen_celist_withlen(cs, n)}
	match n {
		3 {
			bol3 := u24_from_int(packlen_celist(cs))!
			out << bol3.bytes()!
		}
		else {
			return error('unsupported length for celist ')
		}
	}
	// serializes cs
	out << pack_celist(cs)!

	return out
}

// parse_celist decodes bytes array into array of CertificateEntry without the length part.
@[direct_array_access; inline]
fn parse_celist(bytes []u8) ![]CertificateEntry {
	mut i := 0
	mut cs := []CertificateEntry{cap: bytes.len / min_centry_size}
	for i < bytes.len {
		c := parse_centry(bytes[i..])!
		cs << c
		i += packlen_centry(c)
	}
	return cs
}

// parse_celist_withlen decodes bytes array into arrays of CertificateEntry includes the 3-bytes length.
@[direct_array_access; inline]
fn parse_celist_withlen(bytes []u8) ![]CertificateEntry {
	if bytes.len < 3 {
		return error('underflow bytes for celist')
	}
	mut r := new_buffer(bytes)!
	// read 3-bytes length of the arrays
	bol3 := r.read_at_least(3)!
	arrays_len := u24_from_bytes(bol3)!
	arrays_data := r.read_at_least(int(arrays_len))!

	// parse this array data into array of CertificateEntry
	cs := parse_celist(arrays_data)!

	return cs
}

// TLS 1.3 Certificate
//
const min_certificate_size = 4

// 4.4.2.  Certificate
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.2
//
// struct {
//       opaque certificate_request_context<0..2^8-1>;
//       CertificateEntry certificate_list<0..2^24-1>;
//    } Certificate;
//
@[noinit]
struct Certificate {
mut:
	context []u8               // <0..2^8-1>;
	celist  []CertificateEntry // <0..2^24-1>;
}

// check_cert does basic validation check on certifcate c.
@[inline]
fn (c Certificate) check_cert() ! {
	if c.context.len > max_u8 {
		return error('certificate context length exceed max_u8')
	}
	if packlen_celist(c.celist) > max_u24 {
		return error('celist size exceed max_u24')
	}
}

// packlen_cert returns the length of encoded certifcate c, in bytes.
@[inline]
fn packlen_cert(c Certificate) int {
	mut n := 0
	n += 1 + c.context.len
	n += packlen_celist_withlen(c.celist, 3)
	return n
}

// pack_cert encodes certifcate c into bytes array and check the result.	
@[inline]
fn pack_cert(c Certificate) ![]u8 {
	mut out := []u8{cap: packlen_cert(c)}
	// encodes 1-byte context.len and the certificate context
	out << u8(c.context)
	out << c.context

	// encodes certificate list
	out << pack_celist_withlen(c.celist, 3)!

	return out
}

// parse_cert decodes bytes array into Certificate opaque and validates them.
@[direct_array_access; inline]
fn parse_cert(bytes []u8) !Certificate {
	if b.len < min_certificate_size {
		return error('Bad Certificate bytes: underflow')
	}
	mut r := new_buffer(b)!
	// read certificate context
	cr := r.read_u8()!
	context := r.read_at_least(int(cr))!

	// read 3-bytes length of certificate list
	bol3 := r.read_bytes(3)!
	length := u24_from_bytes(bol3)!

	// parse certificate entries payload
	celist_data := r.read_at_least(int(length))!
	celist := parse_celist(celist_data)!

	c := Certificate{
		context: context
		celist:  celist
	}
	// check
	c.check_cert()!

	return cert
}

// 4.4.3.  Certificate Verify
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.3
//
const min_certverify_size = 4

// struct {
//       SignatureScheme algorithm;
//       opaque signature<0..2^16-1>;
//   } CertificateVerify;
//
@[noinit]
struct CertificateVerify {
mut:
	algorithm SignatureScheme // u16
	signature []u8            // <0..2^16-1>;
}

// packlen_certverify returns the length of encoded CertificateVerify cv.
@[inline]
fn packlen_certverify(cv CertificateVerify) int {
	return min_certverify_size + cv.signature.len
}

// check_cv does basic check on CertificateVerify c.
@[inline]
fn (c CertificateVerify) check_cv() ! {
	if c.signature.len > max_u16 {
		return error('certifcate verify signature length exceed max_u16')
	}
}

// pack_certverify encodes CertificateVerify cv into bytes array.
@[direct_array_access; inline]
fn pack_certverify(cv CertificateVerify) ![]u8 {
	cv.check()!
	mut out := []u8{cap: packlen_certverify(cv)}
	// encodes signature algorithm
	out << pack_u16item[SignatureScheme](cv.algorithm)
	// encodes signature bytes with their length
	out << pack_raw_withlen(cv.signature, 2)!

	return out
}

// parse_certverify decodes bytes b into CertificateVerify
@[direct_array_access; inline]
fn parse_certverify(b []u8) !CertificateVerify {
	if b.len < min_certverify_size {
		return error('Bad CertificateVerify bytes: underflow')
	}
	mut r := new_buffer(b)!
	// read signature algorithm
	alg := r.read_u16()!
	algorithm := new_sigscheme(alg)!

	// read 2-bytes length of signature and their bytes
	slen := r.read_u16()!
	signature := r.read_at_least(int(slen))!

	cv := CertificateVerify{
		algorithm: algorithm
		signature: signature
	}
	// check the result
	cv.check_cv()!

	return cv
}

// 4.4.4.  Finished
//
@[noinit]
struct Finished {
mut:
	verify_data []u8 // [Hash.length]
}

@[inline]
fn packlen_fin(f Finished) int {
	return f.verify_data.len
}

@[inline]
fn packlen_fin_withlen(f Finished, n int) int {
	match n {
		0 { return 0 + f.verify_data.len }
		1 { return 1 + f.verify_data.len }
		2 { return 2 + f.verify_data.len }
		else { panic('unsupported length finished') }
	}
}

// 4.6.1.  New Session Ticket Message
//
const min_nst_size = 13

// NewSessionTicket
//
//  struct {
//          uint32 ticket_lifetime;
//          uint32 ticket_age_add;
//          opaque ticket_nonce<0..255>;
//          opaque ticket<1..2^16-1>;
//          Extension xslist<0..2^16-2>;
//      } NewSessionTicket;
//
@[noinit]
struct NewSessionTicket {
mut:
	lifetime u32
	ageadd   u32
	nonce    []u8 // u8
	ticket   []u8 // u16
	xslist   []Extension
}

// packlen_nst returns the length of encoded NewSessionTicket message st into bytes array.
@[inline]
fn packlen_nst(st NewSessionTicket) int {
	mut n := 0
	n += 8 // ticket lifetime + ageadd
	// 1-byte nonce.len and the nonce
	n += 1
	n += st.nonce.len
	// 2-bytes ticket.len and the ticket
	n += 2
	n += st.ticket.len
	// extension list with prepended 2-bytes length
	n += packlen_xslist_withlen(st.xslist)

	return n
}

// check_nst does basic validation on NewSessionTicket message st
@[inline]
fn (st NewSessionTicket) check_nst() ! {
	return error('TODO')
}

// pack_nst encodes NewSessionTicket message st into bytes array.
@[direct_array_access; inline]
fn pack_nst(st NewSessionTicket) ![]u8 {
	st.check_nst()!
	mut out := []u8{cap: packlen_nst(st)}

	// encodes lifetime + ageadd
	mut plus2 := []u8{len: 8}
	binary.big_endian_put_u32(mut plus2[0..4], st.lifetime)
	binary.big_endian_put_u32(mut plus2[4..8], st.ageadd)
	out << plus2

	// encodes nst nonce with 1-byte length
	out << pack_raw_withlen(st.nonce, 1)!
	// encodes nst ticket with 2-bytes length
	out << pack_raw_withlen(st.ticket, 2)!
	// encodes extension list with their length
	out << pack_extlist_withlen(st.xslist)!

	return out
}

// parse_nst decodes bytes array into NewSessionTicket message and validates them.
@[direct_array_access; inline]
fn parse_nst(b []u8) !NewSessionTicket {
	if b.len < min_nst_size {
		return error('NewSessionTicket bytes underflow')
	}
	mut r := new_buffer(b)!
	lifetime := r.read_u32()!
	ageadd := r.read_u32()!
	nonce_len := r.read_u8()!
	nonce := r.read_at_least(int(nonce_len))!
	tkt_len := r.read_u16()!
	ticket := r.read_at_least(int(tkt_len))!

	// read extension list with prepended length
	xlen := r.read_u16()
	xs_bytes := r.read_at_least(int(xlen))!
	xs := parse_extlist(xs_bytes)!

	st := NewSessionTicket{
		lifetime: lifetime
		ageadd:   ageadd
		nonce:    nonce
		ticket:   ticket
		xslist:   xs
	}
	// check the result
	st.check_nst()!

	return st
}

// KeyUpdate message
//
enum KeyUpdate as u8 {
	not_requested = 0
	was_requested = 1
	// 255
}

// new_keyupdate creates new KeyUpdate
@[inline]
fn new_keyupdate(val u8) !KeyUpdate {
	match val {
		0 { return .not_requested }
		1 { return .was_requested }
		else { return error('unsupported KeyUpdateRequest value') }
	}
}
