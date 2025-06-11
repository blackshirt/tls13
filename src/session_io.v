module tls13

import io
import log
import net
import math
import encoding.binary

// This file contains routine for IO handling of reading/writing bytes to the wire.
// Its splitted from main session files for readable and clarity reason.

// read_tls_bytes_header read 5 bytes of TLS record header
fn (mut ses Session) read_tls_bytes_header(mut buf []u8) !int {
	if buf.len != 5 {
		return error('header record need 5 bytes')
	}
	return ses.reader.read(mut buf)!
}

// read_tls_record reads single TLS 1.3 record from session reader.
// Its return bytes length that have been read and the TLSRecord structure.
// It's does not decrypts or interpretes the record.
pub fn (mut ses Session) read_tls_record() !TLSRecord {
	// we use `Session.read_at_least` routine to ensure we get required bytes
	// read a TLS header record, ie, 5 bytes length
	mut hdr := []u8{len: 5}
	hdr_len := ses.read_at_least(mut hdr)!
	assert hdr_len == 5

	// we don't interpretes content type, just do read as is
	ctn_type := ContentType.from(hdr[0])! // unsafe { ContentType(hdr[0]) }
	ver := binary.big_endian_u16(hdr[1..2])
	version := ProtocolVersion.from_u16(ver)! // unsafe { ProtocolVersion(ver) }
	length := binary.big_endian_u16(hdr[3..4])

	// read payload content
	mut payload := []u8{len: int(length)}
	payload_len := ses.read_at_least(mut payload)!

	assert payload_len == int(length)

	rec := TLSRecord{
		ctn_type: ctn_type
		version:  version
		length:   int(length)
		payload:  payload
	}
	return rec
}

// read_and_decrypt_record tries to read bytes from reader, decrypts the record
// and return the decrypted record in the form TLSPlaintext structure
pub fn (mut ses Session) read_and_decrypt_record() !TLSPlaintext {
	// let's read a raw record
	// rec := ses.read_tls_record()!
	rec := ses.read_with_skipped_ccs_record()!

	// if hsk_secured active, the record should be decrypted under associated key
	if ses.hsk_secured {
		if ses.hsk_connected {
			// when ses.hsk_connected, the record should be decrypted
			// under key derived from application traffic secret
			assert int(ses.tls_state()) >= int(TlsState.ts_connected)
			assert ses.ks.srv_app_wrkey.len != 0
			assert ses.ks.srv_app_wriv.len != 0
			pxt := ses.decrypt_record(rec, ses.ks.srv_app_wrkey, ses.ks.srv_app_wriv)!
			// An implementation which receives any other change_cipher_spec value or
			// which receives a protected change_cipher_spec record MUST abort the
			// handshake with an unexpected_message alert
			if pxt.ctn_type == .change_cipher_spec {
				return error('unexpected_message: get ccs')
			}
			return pxt
		}

		// decrypted under key derived from handshake traffic secret
		assert ses.ks.srv_hsk_wrkey.len != 0
		assert ses.ks.srv_hsk_wriv.len != 0
		pxt := ses.decrypt_record(rec, ses.ks.srv_hsk_wrkey, ses.ks.srv_hsk_wriv)!
		if pxt.ctn_type == .change_cipher_spec {
			return error('unexpected_message: get ccs')
		}
		return pxt

		// todo: decrypt under key derived from early traffic secret, if supported
	}

	// plaintext
	pxt := rec.to_plaintext()
	return pxt
}

// read reads data from socket into the provided buffer. Its not guarantees the bytes
// has been read was fulffil `buf.len` bytes. For this use case, use `Session.read_at_least`.
fn (mut ses Session) read(mut buf []u8) !int {
	lock {
		if ses.on_closed_state() || ses.conn.sock.handle <= 1 {
			return error('sock_read: trying to read a closed socket')
		}
		n := ses.reader.read(mut buf)!
		return n
	}
	return error('none')
}

// read_at_least reads at least `buf.len` of bytes data from socket into the provided buffer.
// If we can not read `buf.len` bytes we return error instead.
fn (mut ses Session) read_at_least(mut buf []u8) !int {
	lock {
		if ses.on_closed_state() || ses.conn.sock.handle <= 1 {
			return error('sock_read: trying to read a closed socket')
		}

		// n := ses.reader.read(mut buf)!
		n := read_at_least(mut ses.reader, mut buf)!
		assert n == buf.len

		return n
	}
	return error('none')
}

// read_with_skipped_ccs_record tries to read from reader for single TLS record, and perform checks for
// .change_cipher_spec msg, and if its happen, we ignore this type of msg and read the next record instead.
fn (mut ses Session) read_with_skipped_ccs_record() !TLSRecord {
	rec := ses.read_tls_record()!
	// In TLS 1.3, change_cipher_spec msg is ignored, so we check
	// for this type of msg, if yes, we read next record.
	if rec.ctn_type == .change_cipher_spec {
		next_rec := ses.read_with_skipped_ccs_record()!
		// if we received .change_cipher_spec msg again, we return error instead.
		// in proper implementation, its should never happen, when multiples
		// .change_cipher_spec msg sequentially sent by peer.
		if next_rec.ctn_type == .change_cipher_spec {
			return error('Recv sequentially .change_cipher_spec msg')
		}
		return next_rec
	}
	return rec
}

// Utility read function, ported from Golang io package
//
// read_at_least reads from reader r into result buffer until it has read at least result.len
// Its adapted from golang of `bytes.ReadAtLeast` from bytes module. Its return number of bytes
// has been read from reader, exactly its return result.len, otherwise its return error.
fn read_at_least(mut r io.Reader, mut result []u8) !int {
	needed := result.len
	mut temp := []u8{len: needed}
	mut taken := 0
	for taken <= needed {
		// amount of `reader.read` is limited by temp.len, ie, bytes needed length.
		// mut amount := 0
		amount := r.read(mut temp)!
		if amount >= needed {
			// if bytes has been read was reaching with needed amount,
			// we copy it to the result buffer and return this.
			s := copy(mut result, temp)
			assert s == needed
			return s
		}

		// otherwise, its need more bytes to read on, so we copy current result
		// to right place of the result buffer and updates taken bytes
		// by amount of bytes has been read and loop from the start until
		// we reached needed bytes length.
		cur_result := unsafe { temp[0..amount] }
		s := copy(mut result[taken..taken + cur_result.len], cur_result)
		assert s == cur_result.len
		taken += amount
	}
	if taken > 0 && taken < needed {
		return error('error: unexpected eof')
	}

	return taken
}

// write writes the provided bytes array to the underlying Session writer.
fn (mut ses Session) write(bytes []u8) !int {
	lock {
		if ses.on_closed_state() || ses.conn.sock.handle <= 1 {
			return error('socket_write: trying to write on a closed socket')
		}
		for {
			// write bytes to underlying net.TcpConn. Under the hood, TcpConn.write
			// was using TcpConn.write_ptr thats blocks and attempts to write all data
			n := ses.conn.write(bytes) or {
				if err.code() == net.err_timed_out_code {
					continue
				}
				return err
			}
			return n
		}
		panic('reached unreachable code')
	}
	return error('reached unreachable code')
}

// record with an Alert type MUST contain exactly one message. it doesn't span on multiple record.
// alert messages are encrypted as specified by the current connection state.
// TOOD: provide with context write_key and write_iv
pub fn (mut ses Session) write_alert(a Alert) !int {
	if ses.on_closed_state() {
		return error('write on .closed state')
	}
	ap := TLSPlaintext.from_alert(a)!
	assert ap.length < max_u16

	if ses.hsk_secured {
		// do encryption of alert record
		// TODO: its depends where is this happen on the Session state,
		// when in .connected state, we use client_app_write_key
		// when in handshake phase, we use client_hsk_write_key
		if ses.hsk_connected {
			// encrypt with cln_app_wrkey, cln_app_wriv
			acx := ses.reclayer.encrypt(ap, ses.ks.cln_app_wrkey, ses.ks.cln_app_wriv)!
			n := ses.write_ciphertext(acx)!
			return n
		}

		acx := ses.reclayer.encrypt(ap, ses.ks.cln_hsk_wrkey, ses.ks.cln_hsk_wriv)!
		n := ses.write_ciphertext(acx)!
		return n
	}
	n := ses.write_plaintext(ap)!
	return n
}

fn (mut ses Session) write_handshake(h Handshake) !int {
	if ses.on_closing_state() || ses.on_closed_state() {
		return error('Write handshake msg on ${ses.tls_state()} state is not allowed')
	}
	if h.packed_length() > 1 << 14 {
		return error('Handshake packed length exceed record limit, please do fragment on this msg')
	}
	pxt := TLSPlaintext.from_handshake(h)!
	// Handshake messages are supplied to the TLS record layer where they
	// are encapsulated within one or more TLSPlaintext or TLSCiphertext structures#
	// TODO: more better for writing handshake message
	// pxt_list := ses.reclayer.take_handshake_msg(h)!
	if ses.hsk_secured {
		if ses.hsk_connected {
			cxt := ses.reclayer.encrypt(pxt, ses.ks.cln_app_wrkey, ses.ks.cln_app_wriv)!
			n := ses.write_ciphertext(cxt)!
			return n
		}
		cxt := ses.reclayer.encrypt(pxt, ses.ks.cln_hsk_wrkey, ses.ks.cln_hsk_wriv)!
		n := ses.write_ciphertext(cxt)!

		return n
	}
	// otherwise, write plaintext msg
	return ses.write_plaintext(pxt)!
}

// write_application_data writes raw application data, its happens after handshake is completed.
pub fn (mut ses Session) write_application_data(data []u8) !int {
	// write .application_data type should happen after we reached .ts_connected state onwards
	if int(ses.tls_state()) < int(TlsState.ts_connected) || ses.on_closing_state()
		|| ses.on_closed_state() {
		return error('Cant write .application_data on current state:${ses.tls_state()}')
	}

	pxt := TLSPlaintext{
		ctn_type:    .application_data
		lgc_version: tls_v12
		length:      data.len
		fragment:    data
	}
	cxt := ses.reclayer.encrypt(pxt, ses.ks.cln_app_wrkey, ses.ks.cln_app_wriv)!
	return ses.write_ciphertext(cxt)!
}

// write_plaintext writes TLSPlaintext to underlying Session writer
fn (mut ses Session) write_plaintext(pxt TLSPlaintext) !int {
	if ses.on_closed_state() {
		return error('write handshake msg on ${ses.tls_state()} state is not allowed')
	}
	// what if ses.on_closing_state() ? we can still sent alert msg
	if ses.hsk_secured {
		return error('You can not write plaintext on secure state')
	}
	pb := pxt.pack()!
	n := ses.write(pb)!
	return n
}

// write_ciphertext writes TLSCiphertext to underlying Session writer
fn (mut ses Session) write_ciphertext(cx TLSCiphertext) !int {
	if ses.on_closing_state() || ses.on_closed_state() {
		return error('write TLSCiphertext on ${ses.tls_state()} state is not allowed')
	}
	if ses.hsk_secured {
		cb := cx.pack()!
		n := ses.write(cb)!
		return n
	}
	return error('Not in secure state, use write_plaintext instead')
}

fn (mut ses Session) send_client_finished_msg(cfin Finished) ! {
	// TODO : validate handshake context
	log.info('Perform ${@METHOD} ...')

	clientfin_hsk := HandshakePayload(cfin).pack_to_handshake()!
	_ := ses.send_handshake_msg(clientfin_hsk)!

	// append this client Finished msg to Handshake context arrays
	// state transition happens on main handshake routine
	ses.ks.append_hskmsg_and_update_hash(clientfin_hsk)!
}

fn (mut ses Session) send_eoed_msg(ed EndOfEarlyData) ! {
	log.info('Perform ${@METHOD} ...')
}

fn (mut ses Session) send_client_certificate_msg(cert Certificate) ! {
	log.info('Perform ${@METHOD} ...')
	assert ses.rcv_srv_certreq == true
	hsk := HandshakePayload(cert).pack_to_handshake()!
	_ := ses.send_handshake_msg(hsk)!

	// appends this msg to handshake context,
	ses.ks.append_hskmsg_and_update_hash(hsk)!
}

fn (mut ses Session) send_client_certificate_verify_msg(crv CertificateVerify) ! {
	log.info('Perform ${@METHOD} ...')
	assert ses.rcv_srv_certreq == true
	hsk := HandshakePayload(crv).pack_to_handshake()!
	_ := ses.send_handshake_msg(hsk)!
	ses.ks.append_hskmsg_and_update_hash(hsk)!
}

fn (mut ses Session) send_handshake_msg(hsk Handshake) !int {
	return ses.write_handshake(hsk)!
}
