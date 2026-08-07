// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// TLS 1.3 handshake module
//
// This module provides TLS 1.3 handshake message definitions, wire format
// helpers, and encoding/decoding functions for handshake payloads.
module tls13

import encoding.binary
import crypto.internal.subtle

// helloretry_magic is the fixed ServerHello random value that signals a
// HelloRetryRequest as defined by RFC 8446.
const helloretry_magic = [u8(0xCF), 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
	0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09,
	0xE2, 0xC8, 0xA8, 0x33, 0x9C]

// TLS downgrade-detection values used when validating ServerHello random.
const tls12_random_magic = [u8(0x44), 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01]
const tls11_random_magic = [u8(0x44), 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x00]

// minimal handshake message header size (1-byte type + 3-byte length)
const min_hskmsg_size = 4
// Handshake random and session ID sizes used in ClientHello and ServerHello
const min_random_size = 32
const max_sessid_size = 32

// Handshake represents a TLS 1.3 handshake message header and payload.
//
// The payload is the serialized message body that follows the handshake type
// and 3-byte length fields.
@[noinit]
struct Handshake {
mut:
	tipe    HandshakeType
	payload []u8
}

// check_hsk validates Handshake payload length against the maximum allowed size.
@[inline]
fn (h Handshake) check_hsk() ! {
	if h.payload.len > max_u24 {
		return error('hsk payload size exceed max_u24')
	}
}

// size_hsk returns the serialized length of a Handshake message.
@[inline]
fn size_hsk(h Handshake) int {
	return min_hskmsg_size + h.payload.len
}

// expect_hsk_type returns true when the handshake message is the requested type.
fn (h Handshake) expect_hsk_type(hsktype HandshakeType) bool {
	return h.tipe == hsktype
}

// is_hrr returns true when the handshake is a HelloRetryRequest.
//
// It detects HRR messages either by explicit handshake type or by a ServerHello
// payload whose random field matches the HRR magic value.
fn (h Handshake) is_hrr() !bool {
	if h.tipe == .hello_retry_request {
		return true
	}
	if h.tipe == .server_hello {
		sh := parse_shello(h.payload)!
		return sh.is_hrr()
	}
	return false
}

// pack_hsk serializes a Handshake message into its wire format.
@[inline]
fn pack_hsk(h Handshake) ![]u8 {
	h.check_hsk()!
	mut out := []u8{cap: size_hsk(h)}

	out << u8(h.tipe)
	out << pack_raw(h.payload, .size3)!

	return out
}

// parse_hsk deserializes raw handshake bytes into a Handshake value.
@[direct_array_access; inline]
fn parse_hsk(b []u8) !Handshake {
	if b.len < min_hskmsg_size {
		return error('Underflow of Handshake bytes')
	}
	mut r := new_buffer(b)!
	tp := r.read_u8()!
	tipe := new_hsktype(tp)!

	bol3 := r.read_at_least(3)!
	length := u24_from_bytes(bol3)!

	payload := r.read_at_least(int(length.value))!

	hsk := Handshake{
		tipe:    tipe
		payload: payload
	}
	hsk.check_hsk()!

	return hsk
}

// filtered_hsk_with_type returns only the handshake messages that match msgtype.
fn (hs []Handshake) filtered_hsk_with_type(msgtype HandshakeType) []Handshake {
	return hs.filter(it.tipe == msgtype)
}

// HandshakeList is an array of handshake messages.
type HandshakeList = []Handshake

// size_hsklist returns the encoded length of a handshake list when prefixed
// with an n-byte length field.
@[direct_array_access; inline]
fn size_hsklist(hs []Handshake, n SizeT) int {
	return size_objlist[Handshake](hs, size_hsk, n)
}

// size_hsklist_nolen returns the encoded length of a handshake list without
// any length prefix.
@[direct_array_access; inline]
fn size_hsklist_nolen(hs []Handshake) int {
	return size_objlist_nolen[Handshake](hs, size_hsk)
}

// pack_hsklist encodes a handshake list with an explicit length prefix.
@[direct_array_access; inline]
fn pack_hsklist(hs []Handshake, n SizeT) ![]u8 {
	return pack_objlist[Handshake](hs, pack_hsk, size_hsk, n)!
}

// pack_hsklist_nolen encodes a handshake list without a length prefix.
@[direct_array_access]
fn pack_hsklist_nolen(hs []Handshake) ![]u8 {
	return pack_objlist_nolen[Handshake](hs, pack_hsk, size_hsk)!
}

// Supported TLS 1.3 handshake payload
type HskPayload = Certificate
	| CertificateRequest
	| CertificateVerify
	| ClientHello
	| EncryptedExtensions
	| EndOfEarlyData
	| Finished
	| HelloRetryRequest
	| KeyUpdate
	| NewSessionTicket
	| ServerHello

// the handshake type of this HskPayload
fn (h HskPayload) tipe() !HandshakeType {
	match h {
		Certificate { return .certificate }
		CertificateRequest { return .certificate_request }
		CertificateVerify { return .certificate_verify }
		ClientHello { return .client_hello }
		EncryptedExtensions { return .encrypted_extensions }
		EndOfEarlyData { return .end_of_early_data }
		Finished { return .finished }
		HelloRetryRequest { return .hello_retry_request }
		KeyUpdate { return .key_update }
		ServerHello { return .server_hello }
		NewSessionTicket { return .new_session_ticket }
	}
}

// pack_hskpayload encodes handshake payload h into bytes array
@[inline]
fn pack_hskpayload(h HskPayload) ![]u8 {
	match h {
		Certificate {
			cert := h as Certificate
			return pack_cert(cert)!
		}
		CertificateRequest {
			crq := h as CertificateRequest
			return pack_creq(crq)!
		}
		CertificateVerify {
			cvr := h as CertificateVerify
			return pack_certverify(cvr)!
		}
		ClientHello {
			ch := h as ClientHello
			return pack_chello(ch)!
		}
		EncryptedExtensions {
			ee := h as EncryptedExtensions
			return pack_ee(ee)!
		}
		EndOfEarlyData {
			// eod was an empty opaque
			return []u8{}
		}
		Finished {
			fin := h as Finished
			// return verify_data directly
			return fin.verify_data
		}
		HelloRetryRequest {
			hrr := h as HelloRetryRequest
			return pack_hrr(hrr)!
		}
		KeyUpdate {
			ku := h as KeyUpdate
			// keyupdate was single byte
			return [u8(ku)]
		}
		ServerHello {
			sh := h as ServerHello
			return pack_shello(sh)!
		}
		NewSessionTicket {
			st := h as NewSessionTicket
			return pack_nst(st)!
		}
	}
}

// TLS 1.3 ClientHello handshake message definitions and wire helpers.
//
// See RFC 8446 section 4.1.2 for the record layout and field requirements.
// The minimum size accounts for version, random, session ID, cipher suites,
// compression methods, and extension list overhead.
const min_chello_size = 51
const min_chello_cmeths_size = 1
const max_chello_cmeths_size = max_u8

// ClientHello carries client protocol preferences, legacy fields, and extensions.
@[noinit]
struct ClientHello {
mut:
	version Version = .tls12
	random  []u8
	sessid  []u8
	csuites []CipherSuite
	cmeths  []u8
	xslist  []Extension
}

// check_chello validates a ClientHello before serialization.
@[inline]
fn (c ClientHello) check_chello() ! {
	if c.sessid.len > max_sessid_size {
		return error('Session id length exceed')
	}
	if c.random.len != min_random_size {
		return error('Bad random length')
	}
	if c.csuites.len < 1 {
		return error('null-length of ciphersuites was not allowed')
	}
	if c.cmeths.len < min_chello_cmeths_size || c.cmeths.len > max_chello_cmeths_size {
		return error('invalid compression_method size')
	}
}

// size_chello returns the encoded length of a ClientHello message.
@[inline]
fn size_chello(c ClientHello) int {
	mut n := 0
	n += 2
	n += 32
	n += 1 + c.sessid.len
	n += size_u16list[CipherSuite](c.csuites, .size2)
	n += 1 + c.cmeths.len
	n += size_extlist(c.xslist, .size2)
	return n
}

// pack_chello serializes the ClientHello to TLS wire format.
@[inline]
fn pack_chello(c ClientHello) ![]u8 {
	c.check_chello()!
	mut out := []u8{cap: size_chello(c)}

	out << pack_u16item[Version](c.version)
	out << c.random
	out << pack_raw(c.sessid, .size1)!
	out << pack_u16list[CipherSuite](c.csuites, .size2)!
	out << pack_raw(c.cmeths, .size1)!
	out << pack_extlist(c.xslist, .size2)!

	return out
}

// parse_chello decodes a ClientHello from raw bytes and validates its fields.
@[direct_array_access; inline]
fn parse_chello(bytes []u8) !ClientHello {
	if bytes.len < min_chello_size {
		return error('underflow client hello bytes')
	}
	mut r := new_buffer(bytes)!
	val := r.read_u16()!
	ver := new_version(val)!

	random := r.read_at_least(32)!

	sid := r.read_u8()!
	sid_bytes := r.read_at_least(int(sid))!

	ciphers_len := r.read_u16()!
	ciphers_data := r.read_at_least(int(ciphers_len))!
	csuites := parse_u16list_nolen[CipherSuite](ciphers_data, new_csuite)!

	cm := r.read_u8()!
	cmeths := r.read_at_least(int(cm))!

	xlen := r.read_u16()!
	xs_bytes := r.read_at_least(int(xlen))!
	xs := parse_extlist_nolen(xs_bytes)!

	ch := ClientHello{
		version: ver
		random:  random
		sessid:  sid_bytes
		csuites: csuites
		cmeths:  cmeths
		xslist:  xs
	}
	ch.check_chello()!

	return ch
}

/*
// check_compliance parse ServerHello with associated ClientHello
fn (ch ClientHello) check_compliance(sh ServerHello) !bool {
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
*/

// TLS 1.3 ServerHello handshake message definitions and wire helpers.
//
// See RFC 8446 section 4.1.3 for the ServerHello structure and field semantics.
const min_shello_size = 40

@[noinit]
struct ServerHello {
mut:
	version Version = .tls12
	random  []u8
	sessid  []u8
	csuite  CipherSuite
	cmeth   u8 = 0x00
	xslist  []Extension
}

// check_shello validates the ServerHello session-id length.
@[inline]
fn (s ServerHello) check_shello() ! {
	if s.sessid.len > max_sessid_size {
		return error('wrong sessid size')
	}
}

// size_shello returns the encoded length of a ServerHello message.
@[inline]
fn size_shello(s ServerHello) int {
	mut n := 0
	n += 2
	n += 32
	n += 1 + s.sessid.len
	n += 2
	n += 1
	n += size_extlist(s.xslist, .size2)
	return n
}

// pack_shello serializes the ServerHello to TLS wire format.
@[inline]
fn pack_shello(s ServerHello) ![]u8 {
	s.check_shello()!
	mut out := []u8{cap: size_shello(s)}

	out << pack_u16item[Version](s.version)
	out << s.random
	out << pack_raw(s.sessid, .size1)!
	out << pack_u16item[CipherSuite](s.csuite)
	out << s.cmeth
	out << pack_extlist(s.xslist, .size2)!

	return out
}

// parse_shello deserializes a ServerHello from raw bytes and validates it.
@[direct_array_access]
fn parse_shello(bytes []u8) !ServerHello {
	if bytes.len < min_shello_size {
		return error('underflow ServerHello bytes')
	}
	mut r := new_buffer(bytes)!
	val := r.read_u16()!
	ver := new_version(val)!

	random := r.read_at_least(32)!

	sid := r.read_u8()!
	sid_bytes := r.read_at_least(int(sid))!

	cs := r.read_u16()!
	csuite := new_csuite(cs)!

	cmeth := r.read_u8()!

	xlen := r.read_u16()!
	xs_bytes := r.read_at_least(int(xlen))!
	xs := parse_extlist_nolen(xs_bytes)!

	sh := ServerHello{
		version: ver
		random:  random
		sessid:  sid_bytes
		csuite:  csuite
		cmeth:   cmeth
		xslist:  xs
	}
	sh.check_shello()!

	return sh
}

// HelloRetryRequest is represented on the wire using the ServerHello layout
// with a special fixed random value.
@[noinit]
struct HelloRetryRequest {
	ServerHello
}

// pack_hrr serializes a HelloRetryRequest as a ServerHello wire value.
@[inline]
fn pack_hrr(h HelloRetryRequest) ![]u8 {
	return pack_shello(h.ServerHello)!
}

// parse_hrr decodes a HelloRetryRequest and validates the HRR magic bytes.
@[direct_array_access; inline]
fn parse_hrr(bytes []u8) !HelloRetryRequest {
	sh := parse_shello(bytes)!
	if subtle.constant_time_compare(sh.random, helloretry_magic) != 1 {
		return error('not a hrr random')
	}
	return HelloRetryRequest{sh}
}

// is_hrr returns true when a ServerHello contains the HRR magic random.
@[inline]
fn (sh ServerHello) is_hrr() bool {
	return subtle.constant_time_compare(sh.random, helloretry_magic) == 1
}

// EndOfEarlyData is an empty TLS handshake message used to signal the end
// of early data when the server accepts it.
struct EndOfEarlyData {}

// EncryptedExtensions carries the server extension list after ServerHello.

@[noinit]
type EncryptedExtensions = []Extension

// pack_ee serializes EncryptedExtensions with a length-prefixed extension list.
@[inline]
fn pack_ee(ee EncryptedExtensions) ![]u8 {
	return pack_extlist(ee, .size2)!
}

// parse_ee deserializes an EncryptedExtensions payload.
@[direct_array_access; inline]
fn parse_ee(bytes []u8) !EncryptedExtensions {
	return EncryptedExtensions(parse_extlist(bytes)!)
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

// size_creq returns the length of serialized CertificateRequest cr
@[inline]
fn size_creq(cr CertificateRequest) int {
	mut n := 0
	n += 1 + cr.opaque.len
	n += size_extlist(cr.xslist, .size2)
	return n
}

// pack_creq encodes CertificateRequest cr into bytes array.
@[direct_array_access; inline]
fn pack_creq(cr CertificateRequest) ![]u8 {
	cr.check_creq()!
	mut out := []u8{cap: size_creq(cr)}

	// encodes certificate request context opaque and their 1-byte length
	out << pack_raw(cr.opaque, .size1)!

	// encodes certificate request extension list with 2-bytes length
	out << pack_extlist(cr.xslist, .size2)!

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

	// read extension list with prepended 2-bytes length
	xlen := r.read_u16()!
	xs_bytes := r.read_at_least(int(xlen))!
	xs := parse_extlist_nolen(xs_bytes)!

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

// size_centry returns the length of serialized CertificateEntry ce
@[inline]
fn size_centry(ce CertificateEntry) int {
	mut n := 0
	n += 3 + ce.opaque.len
	n += size_extlist(ce.xslist, .size2)
	return n
}

// pack_centry encodes ce into bytes array.
@[direct_array_access; inline]
fn pack_centry(ce CertificateEntry) ![]u8 {
	mut out := []u8{cap: size_centry(ce)}

	// FIXME: different type should be handled differently?
	if ce.opaque.len > max_opaque_size {
		return error('Certificate data exceed')
	}
	// encodes certificate data with 3-bytes length
	out << pack_raw(ce.opaque, .size3)!

	// encodes certificate extension list with 2-bytes length
	out << pack_extlist(ce.xslist, .size2)!

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
	opaque := r.read_at_least(int(opaque_len.value))!

	// read extension list with prepended length
	xlen := r.read_u16()!
	xs_bytes := r.read_at_least(int(xlen))!
	xs := parse_extlist_nolen(xs_bytes)!

	ce := CertificateEntry{
		opaque: opaque
		xslist: xs
	}
	ce.check_ce()!

	return ce
}

// CertificateEntry list certificate_list<0..2^24-1>;
//

// parse_celist_nolen decodes bytes array into array of CertificateEntry without the length part.
@[direct_array_access; inline]
fn parse_celist_nolen(bytes []u8) ![]CertificateEntry {
	mut i := 0
	mut cs := []CertificateEntry{cap: bytes.len / min_centry_size}
	for i < bytes.len {
		c := parse_centry(bytes[i..])!
		cs << c
		i += size_centry(c)
	}
	return cs
}

// parse_celist decodes bytes array into arrays of CertificateEntry includes the 3-bytes length.
@[direct_array_access; inline]
fn parse_celist(bytes []u8) ![]CertificateEntry {
	if bytes.len < 3 {
		return error('underflow bytes for celist')
	}
	mut r := new_buffer(bytes)!
	// read 3-bytes length of the arrays
	bol3 := r.read_at_least(3)!
	// arrays_len was Uint24 opaque
	arrays_len := u24_from_bytes(bol3)!
	arrays_data := r.read_at_least(int(arrays_len.value))!

	// parse this array data into array of CertificateEntry
	cs := parse_celist_nolen(arrays_data)!

	return cs
}

// TLS 1.3 Certificate
//
const min_certificate_size = 4

// TLS 1.3 Certificate message definitions and wire helpers.
//
// The Certificate message contains a request context and a list of certificate
// entries, each with certificate data and extensions.
@[noinit]
struct Certificate {
mut:
	context []u8
	celist  []CertificateEntry
}

// check_cert validates the Certificate structure before serialization.
@[inline]
fn (c Certificate) check_cert() ! {
	if c.context.len > max_u8 {
		return error('certificate context length exceed max_u8')
	}
	if size_objlist_nolen[CertificateEntry](c.celist, size_centry) > max_u24 {
		return error('celist size exceed max_u24')
	}
}

// size_cert returns the encoded length of a Certificate message.
@[inline]
fn size_cert(c Certificate) int {
	mut n := 0
	n += 1 + c.context.len
	n += size_objlist[CertificateEntry](c.celist, size_centry, .size3)
	return n
}

// pack_cert serializes a Certificate message into TLS wire format.
@[inline]
fn pack_cert(c Certificate) ![]u8 {
	c.check_cert()!
	mut out := []u8{cap: size_cert(c)}

	out << pack_raw(c.context, .size1)!
	out << pack_objlist[CertificateEntry](c.celist, pack_centry, size_centry, .size3)!

	return out
}

// parse_cert deserializes a Certificate message and validates the parsed result.
@[direct_array_access; inline]
fn parse_cert(bytes []u8) !Certificate {
	if bytes.len < min_certificate_size {
		return error('Bad Certificate bytes: underflow')
	}
	mut r := new_buffer(bytes)!
	cr := r.read_u8()!
	context := r.read_at_least(int(cr))!

	bol3 := r.read_bytes(3)!
	length := u24_from_bytes(bol3)!

	celist_data := r.read_at_least(int(length.value))!
	celist := parse_celist_nolen(celist_data)!

	cert := Certificate{
		context: context
		celist:  celist
	}
	cert.check_cert()!

	return cert
}

// TLS 1.3 CertificateVerify message definitions and wire helpers.
//
// See RFC 8446 section 4.4.3 for the signature algorithm and signature fields.
const min_certverify_size = 4

@[noinit]
struct CertificateVerify {
mut:
	algorithm SignatureScheme
	signature []u8
}

// size_certverify returns the encoded length of CertificateVerify.
@[inline]
fn size_certverify(cv CertificateVerify) int {
	return min_certverify_size + cv.signature.len
}

// check_cv validates a CertificateVerify structure before serialization.
@[inline]
fn (c CertificateVerify) check_cv() ! {
	if c.signature.len > max_u16 {
		return error('certifcate verify signature length exceed max_u16')
	}
}

// pack_certverify serializes CertificateVerify into TLS wire format.
@[direct_array_access; inline]
fn pack_certverify(cv CertificateVerify) ![]u8 {
	cv.check_cv()!
	mut out := []u8{cap: size_certverify(cv)}

	out << pack_u16item[SignatureScheme](cv.algorithm)
	out << pack_raw(cv.signature, .size2)!

	return out
}

// parse_certverify deserializes CertificateVerify from raw bytes.
@[direct_array_access; inline]
fn parse_certverify(b []u8) !CertificateVerify {
	if b.len < min_certverify_size {
		return error('Bad CertificateVerify bytes: underflow')
	}
	mut r := new_buffer(b)!
	alg := r.read_u16()!
	algorithm := new_sigscheme(alg)!

	slen := r.read_u16()!
	signature := r.read_at_least(int(slen))!

	cv := CertificateVerify{
		algorithm: algorithm
		signature: signature
	}
	cv.check_cv()!

	return cv
}

// TLS 1.3 Finished message definition.
//
// The verify_data length depends on the negotiated hash algorithm.
@[noinit]
struct Finished {
mut:
	verify_data []u8
}

// size_fin returns the length of Finished verify_data.
@[inline]
fn size_fin(f Finished) int {
	return f.verify_data.len
}

// finished_from_hsk converts a finished Handshake payload to Finished.
@[inline]
fn finished_from_hsk(h Handshake) !Finished {
	if h.tipe != .finished {
		return error('not finished message')
	}
	return Finished{
		verify_data: h.payload
	}
}

// TLS 1.3 NewSessionTicket message definitions and wire helpers.
//
// See RFC 8446 section 4.6.1 for the ticket lifetime, age add, nonce,
// ticket value, and extensions.
const min_nst_size = 13

@[noinit]
struct NewSessionTicket {
mut:
	lifetime u32
	ageadd   u32
	nonce    []u8
	ticket   []u8
	xslist   []Extension
}

// size_nst returns the encoded length of a NewSessionTicket message.
@[inline]
fn size_nst(st NewSessionTicket) int {
	mut n := 0
	n += 8
	n += 1 + st.nonce.len
	n += 2 + st.ticket.len
	n += size_extlist(st.xslist, .size2)
	return n
}

// check_nst validates the fixed-size constraints of NewSessionTicket.
@[inline]
fn (st NewSessionTicket) check_nst() ! {
	if st.nonce.len > max_u8 {
		return error('ticket_nonce length exceed max_u8')
	}
	if st.ticket.len < 1 || st.ticket.len > max_u16 {
		return error('ticket length out of range')
	}
}

// pack_nst serializes a NewSessionTicket to TLS wire format.
@[direct_array_access; inline]
fn pack_nst(st NewSessionTicket) ![]u8 {
	st.check_nst()!
	mut out := []u8{cap: size_nst(st)}

	mut plus2 := []u8{len: 8}
	binary.big_endian_put_u32(mut plus2[0..4], st.lifetime)
	binary.big_endian_put_u32(mut plus2[4..8], st.ageadd)
	out << plus2

	out << pack_raw(st.nonce, .size1)!
	out << pack_raw(st.ticket, .size2)!
	out << pack_extlist(st.xslist, .size2)!

	return out
}

// parse_nst deserializes NewSessionTicket from raw bytes.
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

	xlen := r.read_u16()!
	xs_bytes := r.read_at_least(int(xlen))!
	xs := parse_extlist_nolen(xs_bytes)!

	st := NewSessionTicket{
		lifetime: lifetime
		ageadd:   ageadd
		nonce:    nonce
		ticket:   ticket
		xslist:   xs
	}
	st.check_nst()!

	return st
}

// KeyUpdate message indicates whether the peer should update its traffic keys.
enum KeyUpdate as u8 {
	not_requested = 0
	was_requested = 1
}

// new_keyupdate converts a raw byte to a KeyUpdate enum.
@[inline]
fn new_keyupdate(val u8) !KeyUpdate {
	match val {
		0 { return .not_requested }
		1 { return .was_requested }
		else { return error('unsupported KeyUpdateRequest value') }
	}
}
