module tls13

import arrays
import crypto
import crypto.sha256
import crypto.sha512

const min_hello_ctx = 2
const ful_hello_ctx = 4
const min_middle_ctx = 6
const min_full_ctx = 7

// Transcripter mimics unpublished structure from standard vlib in a `cyrpto.hash.Digest`
interface Transcripter {
	size() int
	block_size() int
mut:
	free()
	reset()
	write(p []u8) !int
	checksum() []u8
	sum(b []u8) []u8
}

// new_transcripter creates new Transcripter with
fn new_transcripter(h crypto.Hash) !&Transcripter {
	match h {
		.sha256 { return sha256.new() }
		.sha384 { return sha512.new384() }
		.sha512 { return sha512.new() }
		else { return error('unsupported hash digest') }
	}
}

// Protocol messages MUST be sent in the order defined below.
// A peer which receives a handshake message in an unexpected order MUST abort the handshake
// with an "unexpected_message" alert.
// Full of sequence of handshake messages, starting at the first ClientHello, ie:
// ClientHello(1), HelloRetryRequest(6), ClientHello(1), ServerHello(2),
// EncryptedExtensions(8), server CertificateRequest(13), server Certificate(11),
// server CertificateVerify(15), server Finished(20), EndOfEarlyData(5), client
// Certificate(11), client CertificateVerify(15), client Finished(20).
const fullhsk_msgtype_sum = 120
const fullhsk_messages_len = 13

// HelloContext is arrays of Handshake messages start from first ClientHello to last ServerHello,
// ie [ClientHello(1), optional server HelloRetryRequest(6), ClientHello(1), server ServerHello(2)]
// - if HelloRetryRequest is not sent by server, its should be only first ClientHello and ServerHello.
// - otherwise, its should include HelloRetryRequest to the second ServerHello.
type HelloContext = []Handshake

fn (hc HelloContext) valid_length() bool {
	return hc.len >= 2 && hc.len <= 4
}

fn (hc HelloContext) valid_hello_context() !bool {
	if hc.valid_length() {
		contains_hrr := hc.contains_hrr()!
		if contains_hrr {
			// when contains hrr, its should length 4
			if hc.len != 4 {
				return false
			}
			hc1_ishrr := hc[1].is_hrr()!
			hc3_ishrr := hc[3].is_hrr()!
			// hc[0] == .client_hello (first)
			// hc[1] == .hello_retry_request (or server_hello with hrr magic)
			// hc[2] == .client_hello (second)
			// hc[3] == .server_hello
			return hc[0].msg_type == .client_hello && hc1_ishrr && hc[2].msg_type == .client_hello
				&& hc[3].msg_type == .server_hello && !hc3_ishrr
		}
		// otherwise, its not contains hrr
		if hc.len != 2 {
			return false
		}
		return hc[0].msg_type == .client_hello && hc[1].msg_type == .server_hello
	}
	return false
}

// with_hrr return true if this HelloContext contains HelloRetryRequest message
fn (hc HelloContext) with_hrr() !bool {
	with_hrr := hc.contains_hrr()!
	if with_hrr && hc.len == 4 && hc[0].msg_type == .client_hello {
		if hc[1].is_hrr()! && hc[2].msg_type == .client_hello {
			hc3_hrr := hc[3].is_hrr()!
			if !hc3_hrr {
				return true
			}
		}
	}
	return false
}

// without_hrr is HelloContext without HelloRetryRequest message
fn (hc HelloContext) without_hrr() !bool {
	if hc.contains_hrr()! {
		return false
	}
	if hc.len == 2 && hc[0].msg_type == .client_hello {
		if hc[1].is_hrr()! {
			return false
		}
		if hc[1].msg_type != .server_hello {
			return false
		}
		return true
	}
	return false
}

// transpiles_client_hello transforms first ClientHello to dictated synthetic handshake message.
fn transpiles_client_hello(ch Handshake, mut tc Transcripter) ![]u8 {
	// When client receives HelloRetryRequest message, transpiles of first ClientHello to other form.
	// see https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1 for more detail.
	// when the server responds to with a HelloRetryRequest, the value of ClientHello1 is
	// replaced with a special synthetic handshake message of handshake type "message_hash" containing Hash(ClientHello1)
	// (message_hash ||        /* Handshake type */
	//		00 00 Hash.length  ||  /* Handshake message length (bytes) */
	//		Hash(ClientHello1) ||  /* Hash of ClientHello1 */
	//		HelloRetryRequest  || ... || Mn)

	// mut tc := new_transcripter(c)!
	mut out := []u8{}
	if ch.msg_type != .client_hello {
		return error('provided handshake not client_hello')
	}
	out << HandshakeType.message_hash.pack()!
	out << [u8(0x00), 0x00, u8(tc.size())]

	ch_packed := ch.pack()!
	n := tc.write(ch_packed)!
	assert n == ch_packed.len

	ch_hash := tc.sum([]u8{})
	out << ch_hash

	return out
}

// bytes serializes this HelloContext to bytes array.
fn (hc HelloContext) pack_hello_context(c crypto.Hash) ![]u8 {
	if hc.valid_hello_context()! {
		mut out := []u8{}
		if hc.with_hrr()! {
			// when we receive .hello_retry_request message, do transpiles of first
			// client hello msg with `.transpiles_client_hello`
			mut tc := new_transcripter(c)!
			ch := hc[0]

			obj := transpiles_client_hello(ch, mut tc)!
			out << obj

			// updates output bytes with remaining handshake messages.
			// Its start with second handshake element to the last message.
			for i := 1; i < hc.len; i++ {
				out << hc[i].pack()!
			}
			return out
		}
		// otherwise, just pack all of handshake messages to bytes
		for h in hc {
			out << h.pack()!
		}
		return out
	}
	return error('not valid HelloContext')
}

// MiddleContext is arrays of Handshake message start from EncryptedExtensions
// to the server Finished message, ie, [EncryptedExtensions(8), optional server CertificateRequest(13),
// server Certificate(11), server CertificateVerify(15), server Finished(20)]
type MiddleContext = []Handshake

fn (mc MiddleContext) valid_length() bool {
	return mc.len >= 4 && mc.len <= 5
}

fn (mc MiddleContext) valid_middle_context() bool {
	if mc.valid_length() {
		if mc.contains_certrequest() {
			// its should have length of 5 msgs
			return mc[0].msg_type == .encrypted_extensions && mc[1].msg_type == .certificate_request
				&& mc[2].msg_type == .certificate && mc[3].msg_type == .certificate_verify
				&& mc[4].msg_type == .finished
		}
		// otherwise, its not contains CertificateRequest,
		return mc[0].msg_type == .encrypted_extensions && mc[1].msg_type == .certificate
			&& mc[2].msg_type == .certificate_verify && mc[3].msg_type == .finished
	}
	return false
}

// pack_middle_context serializes MiddleContext to bytes array
fn (mc MiddleContext) pack_middle_context() ![]u8 {
	if mc.valid_middle_context() {
		mut out := []u8{}
		for h in mc {
			out << h.pack()!
		}
		return out
	}
	return error('not valid MiddleContext')
}

// EndContext is arrays of Handshake message after MiddleContext, includes EndofEarlyData
// (if supported) to the last client Finished message.
// ie, [optional client EndOfEarlyData(5), optional client Certificate(11),
// optional client CertificateVerify(15), client Finished(20)]
type EndContext = []Handshake

fn (ec EndContext) valid_length() bool {
	return ec.len >= 1 && ec.len <= 4
}

fn (ec EndContext) contains_endofearlydata() bool {
	return ec.contains_exactlyone_msgtype(.end_of_early_data)
}

fn (ec EndContext) valid_end_context() bool {
	if ec.valid_length() {
		// last messages should .finished msg
		if ec[ec.len - 1].msg_type != .finished {
			return false
		}
		// if contains .end_of_early_data, first msg should .end_of_early_data
		if ec.contains_endofearlydata() {
			if ec[0].msg_type != .end_of_early_data {
				return false
			}
		}
		// if .certificate msg is sent, .certificate_verify msg should be sent too
		if ec.contains_exactlyone_msgtype(.certificate) {
			if !ec.contains_exactlyone_msgtype(.certificate_verify) {
				return false
			}
			// otherwise, its contains both of them, so we make sure, .certificate_verify is after .certificate
			// we use of arrays.index_of_first[T](array []T, predicate fn (idx int, elem T) bool) int to find out index
			cert_idx := arrays.index_of_first[Handshake](ec, fn (idx int, elem Handshake) bool {
				return elem.msg_type == .certificate
			})

			cert_verifs_idx := arrays.index_of_first[Handshake](ec, fn (idx int, elem Handshake) bool {
				return elem.msg_type == .certificate_verify
			})
			// todo : maybe need check if cert_verifs_idx := cert_idx + 1
			if cert_idx > cert_verifs_idx {
				return false
			}
		}
		// otherwise, its should valid context
		return true
	}
	return false
}

fn (ec EndContext) pack_end_context() ![]u8 {
	if ec.valid_end_context() {
		mut out := []u8{}
		for m in ec {
			o := m.pack()!
			out << o
		}
		return out
	}
	return error('not valid EndContext')
}

// ServerFinishedContext = HelloContext + MiddleContext
struct ServerFinishedContext {
	hctx HelloContext
	mctx MiddleContext
}

fn (sfc ServerFinishedContext) valid_length() bool {
	return sfc.hctx.valid_length() && sfc.mctx.valid_length()
}

fn (sfc ServerFinishedContext) valid_server_finished_context() bool {
	valid_hc := sfc.hctx.valid_hello_context() or { return false }
	return valid_hc && sfc.mctx.valid_middle_context()
}

fn (sfc ServerFinishedContext) pack_srv_finished_context(c crypto.Hash) ![]u8 {
	if sfc.valid_server_finished_context() {
		mut out := []u8{}
		out << sfc.hctx.pack_hello_context(c)!
		out << sfc.mctx.pack_middle_context()!
		return out
	}
	return error('bad ServerFinishedContext')
}

// FullContext = ServerFinishedContext + EndContext
struct FullContext {
	srv_fctx ServerFinishedContext
	cln_fctx EndContext
}

fn (fux FullContext) valid_length() bool {
	if fux.srv_fctx.hctx.len + fux.srv_fctx.mctx.len + fux.cln_fctx.len > 13 {
		return false
	}
	return fux.srv_fctx.valid_length() && fux.cln_fctx.valid_length()
}

fn (fux FullContext) valid_full_context() bool {
	return fux.srv_fctx.valid_server_finished_context() && fux.cln_fctx.valid_end_context()
}

fn (fux FullContext) pack_full_context(c crypto.Hash) ![]u8 {
	if fux.valid_full_context() {
		mut out := []u8{}
		out << fux.srv_fctx.pack_srv_finished_context(c)!
		out << fux.cln_fctx.pack_end_context()!
		return out
	}
	return error('bad FullContext')
}

// Utility function
// take_context splits arrays of handshake messages, from first to end, and the rest.
fn (hs []Handshake) take_context(end int) !([]Handshake, []Handshake) {
	if end > hs.len {
		return error('bad end')
	}
	ctx := hs[0..end]
	rest := hs[end..]
	return ctx, rest
}

// take_hello_context takes clienthello and serverhello parts of handshakes messages,
// included hrr message if any, it returns hello context
fn (hs []Handshake) take_hello_context() !(HelloContext, []Handshake) {
	mut end := 0
	with_hrr := hs.contains_hrr()!
	if !with_hrr {
		end = 2
	} else {
		end = 4
	}
	ctx, rest := hs.take_context(end)!
	hello_ctx := HelloContext(ctx)
	valid_hctx := hello_ctx.valid_hello_context()!
	if !valid_hctx {
		return error('Handshakes does not contains valid HelloContext messages')
	}
	return hello_ctx, rest
}

// take_premiddle_context takes Handshake messages before the last server Finished message
fn (hs []Handshake) take_upto_premiddle_context() ![]Handshake {
	middle, _ := hs.take_upto_middle_context()!

	assert middle[middle.len - 1].msg_type == .finished
	premiddle := middle[0..middle.len - 1].clone()
	return premiddle
}

fn (hs []Handshake) take_upto_middle_context() !([]Handshake, []Handshake) {
	mut awal_length := 0
	mut end := 0
	with_hrr := hs.contains_hrr()!
	if !with_hrr {
		awal_length = 2
	} else {
		awal_length = 4
	}
	end += awal_length
	with_certreq := hs.contains_certrequest()
	if with_certreq {
		end += 5
	} else {
		end += 4
	}

	tomid_ctx, rest_ctx := hs.take_context(end)!
	hello_ctx, srv_ctx := tomid_ctx.take_context(awal_length)!
	hlo_ctx := HelloContext(hello_ctx).valid_hello_context()!
	mid_ctx := MiddleContext(srv_ctx).valid_middle_context()
	valid := hlo_ctx && mid_ctx
	if !valid {
		return error('wrong Handshake Context')
	}

	return tomid_ctx, rest_ctx
}

fn (hs []Handshake) contains_encrypted_ext() bool {
	return hs.contains_exactlyone_msgtype(.encrypted_extensions)
}

fn (hs []Handshake) contains_certrequest() bool {
	return hs.contains_exactlyone_msgtype(.certificate_request)
}

fn (hs []Handshake) contains_exactlyone_msgtype(msg_type HandshakeType) bool {
	filtered := hs.filter(it.msg_type == msg_type)
	return filtered.len == 1
}

fn (hs []Handshake) contains_empty_msgtype(msg_type HandshakeType) bool {
	filtered := hs.filter(it.msg_type == msg_type)
	return filtered.len == 0
}

// Helper for Handshake Context
// contains_hrr	checks whether one of the handshake messages in array is hrr message
fn (hs []Handshake) contains_hrr() !bool {
	for h in hs {
		hrr := h.is_hrr()!
		if hrr {
			return true
		}
	}
	return false
}

fn (hs []Handshake) valid_length_and_sum() bool {
	mut sum := 0
	for h in hs {
		sum += int(h.msg_type)
	}
	if sum > tls13.fullhsk_msgtype_sum || hs.len > tls13.fullhsk_messages_len {
		return false
	}
	return true
}

// bytes serialize []Handshake to bytes, FIXME: this redundant with .pack_to_multihandshake_bytes()
fn (hs []Handshake) pack_handshakes_msg(c crypto.Hash) ![]u8 {
	mut tc := new_transcripter(c)!
	mut out := []u8{}
	if hs.len == 0 {
		return out
	}
	if hs.contains_hrr()! {
		ch := hs[0]
		assert ch.msg_type == .client_hello
		obj := transpiles_client_hello(ch, mut tc)!
		out << obj
		for i := 1; i < hs.len; i++ {
			out << hs[i].pack()!
		}
		return out
	}
	for i := 0; i < hs.len; i++ {
		out << hs[i].pack()!
	}
	return out
}

fn (mut hs []Handshake) clear() {
	hs.clear()
}

// append_msg append handshake message m to existing handshake arrays.
// its does validation on appending message, by enforces order correctness.
fn (mut hs []Handshake) append_msg(m Handshake) ! {
	// check
	if !hs.valid_length_and_sum() {
		return error('Bad append handshake: full')
	}
	match m.msg_type {
		.client_hello {
			if hs.len == 0 {
				// first message, append it then return
				hs << m
				return
			}
			// [ch1, hrr], its valid append
			if hs.len == 2 && hs[0].msg_type == .client_hello {
				// check for hrr
				if hs[1].is_hrr()! {
					hs << m
					return
				}
			}
			return error('Bad appending ClientHello on current state')
		}
		.hello_retry_request {
			// its only valid after first client_hello
			if hs.contains_empty_msgtype(.hello_retry_request) && hs.len == 1
				&& hs[0].msg_type == .client_hello {
				hs << m
				return
			}
			return error('Bad appending hello_retry_request on current state')
		}
		.server_hello {
			// serverhello only valid after first ClientHello, or second ClientHello
			// it is possible to add .server_hello msg after first .client_hello, even
			// this is HelloRetryRequest msg, but not allowed after second .client_hello
			msg_ishrr := m.is_hrr()!
			// first ServerHello (or ServerHello with hrr random)
			if hs.len == 1 && hs[0].msg_type == .client_hello {
				hs << m
				return
			}
			if hs.len == 3 && hs[hs.len - 1].msg_type == .client_hello {
				if msg_ishrr {
					return error('this msg is hrr, not allowed here')
				}
				// otherwise, we can add it to the array.
				hs << m
				return
			}
			return error('Bad appending server_hello on current state')
		}
		.encrypted_extensions {
			// only valid after 2 or 4 msg
			if hs.contains_empty_msgtype(.encrypted_extensions) && hs.len <= 4
				&& hs[hs.len - 1].msg_type == .server_hello {
				hs << m
				return
			}
			return error('Bad appending encrypted_extensions on current state')
		}
		.certificate_request {
			// only valid after encrypted_extensions
			if hs.contains_empty_msgtype(.certificate_request) && hs.len >= 4
				&& hs[hs.len - 1].msg_type == .encrypted_extensions {
				hs << m
				return
			}
			return error('Bad appending certificate_request on current state')
		}
		.certificate {
			// There are two possibilities its maybe appear, first certificate coming from server, and the second
			// certificate from client (if supplied).
			// first, check its no .certificate msg in the hs array, so its first .certificate
			// coming from server, its appear after .encrypted_extension
			if hs.contains_empty_msgtype(.certificate) {
				if hs.len >= 3 && hs[hs.len - 1].msg_type == .encrypted_extensions {
					hs << m
					return
				}
			}
			// check if it already one .certificate msg in the array, so
			// this is second .certificate msg coming from client, its should appear
			// after server Finished msg
			if hs.contains_exactlyone_msgtype(.certificate) {
				if hs.len >= 6 && hs.contains_exactlyone_msgtype(.finished) {
					hs << m
					return
				}
			}
			// otherwise, its not valid state
			return error('Bad appending .certificate on current state')
		}
		.certificate_verify {
			// only valid after .certificate
			if hs.contains_empty_msgtype(.certificate_verify) {
				if hs.len >= 4 && hs[hs.len - 1].msg_type == .certificate {
					hs << m
					return
				}
			}
			// check if it already one .certificate_verify msg in the array, so
			// this is second .certificate_verify msg, that should happen after .certificate msg
			if hs.contains_exactlyone_msgtype(.certificate_verify) {
				if hs.len >= 7 && hs[hs.len - 1].msg_type == .certificate {
					hs << m
					return
				}
			}
			return error('Bad appending .certificate_verify on current state')
		}
		.finished {
			// only valid after .certificate_verify
			// allow two .finished msg, server Finished and client Finished
			if hs.contains_empty_msgtype(.finished) {
				if hs.len >= 5 && hs[hs.len - 1].msg_type == .certificate_verify {
					hs << m
					return
				}
			}
			// second .finished msg
			if hs.contains_exactlyone_msgtype(.finished) {
				if hs.len >= 6 {
					hs << m
					return
				}
			}
			return error('Bad appending finished on current state')
		}
		.end_of_early_data {
			// only valid after first server .finished msg
			if hs.contains_empty_msgtype(.end_of_early_data) && hs.len >= 6
				&& hs[hs.len - 1].msg_type == .finished {
				hs << m
				return
			}
			return error('Bad appending end_of_early_data on current state')
		}
		else {
			return error('Not supported for current handshake context')
		}
	}
}
