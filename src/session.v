module tls13

import io
import log
import net
import math
import encoding.binary
import blackshirt.ecdhe

@[params]
pub struct Options {
	group  NamedGroup  = .x25519
	csuite CipherSuite = .tls_chacha20_poly1305_sha256
	rto    i64 = net.tcp_default_read_timeout
	wto    i64 = net.tcp_default_write_timeout
}

// Session represents TLs 1.3 capable client
@[heap]
struct Session {
mut:
	conn       &net.TcpConn = unsafe { nil }
	rto        i64                = net.tcp_default_read_timeout
	wto        i64                = net.tcp_default_write_timeout
	group      NamedGroup         = .x25519
	csuite     CipherSuite        = .tls_chacha20_poly1305_sha256
	exchanger  &ecdhe.Exchanger   = unsafe { nil }
	ks         &KeyScheduler      = unsafe { nil }
	reclayer   &RecordLayer       = unsafe { nil }
	reader     &io.BufferedReader = unsafe { nil }
	privkey    ecdhe.PrivateKey //= unsafe { nil } // []u8
	pubkey     ecdhe.PublicKey
	shared_sec []u8 // shared secret of ecdhe Exchanger
	psk_bytes  []u8 // psk bytes
	state      State = .closed
	recv_hrr   bool
	firstch    ClientHello
	// secure_state flag tells if this session should perform
	// encryption or decryption, depends on the context. its should be set up
	// after .wait_sh
	secure_state  bool
	hsk_completed bool
}

pub fn (mut ses Session) reset_write_ctr() {
	ses.reclayer.reset_write_seq()
}

fn (ses Session) peer_address() !(string, u16) {
	addr := ses.conn.peer_ip()!
	host, port := net.split_address(addr)!
	return host, port
}

// new_session creates new session from already connected tcp connection
pub fn new_session(conn &net.TcpConn, opt Options) !&Session {
	cv := opt.group.curve()!
	exchanger := ecdhe.new_exchanger(cv)!
	ks := new_key_scheduler(opt.csuite.hasher())!
	reclayer := new_record_layer(opt.csuite)!

	mut ses := &Session{
		privkey: ecdhe.PrivateKey{
			curve: exchanger
		}
		pubkey: ecdhe.PublicKey{
			curve: exchanger
		}
	}

	ses.group = opt.group
	ses.csuite = opt.csuite
	ses.wto = opt.wto
	ses.rto = opt.rto

	ses.exchanger = exchanger
	ses.ks = ks
	ses.reclayer = reclayer

	ses.conn = conn
	reader := io.new_buffered_reader(io.BufferedReaderConfig{ reader: conn })
	ses.reader = reader

	return ses
}

// read_record reads single tls record from session reader, its return bytes length that have been read
// and the TLSRecord structure. It's does not decrypts the record.
pub fn (mut ses Session) read_raw_record() !(int, TLSRecord) {
	mut n := 0
	// read a header record
	mut hdr := []u8{len: 5}
	hdr_len := ses.read_at_least(mut hdr)!
	assert hdr_len == 5
	n += hdr_len

	// we dont interpretes content type, just do read as is
	ctn_type := unsafe { ContentType(hdr[0]) }
	ver := binary.big_endian_u16(hdr[1..2])
	version := unsafe { ProtoVersion(ver) }
	length := binary.big_endian_u16(hdr[3..4])

	// read payload content
	mut payload := []u8{len: int(length)}
	payload_len := ses.read_at_least(mut payload)!
	n += payload_len

	assert payload_len == int(length)

	rec := TLSRecord{
		ctn_type: ctn_type
		version: version
		length: int(length)
		payload: payload
	}
	return n, rec
}

fn (mut ses Session) read_with_skipped_ccs_record() !(int, TLSRecord) {
	mut n, rec := ses.read_raw_record()!
	if rec.ctn_type == .change_cipher_spec {
		m, next_rec := ses.read_raw_record()!
		n += m
		return n, next_rec
	}
	return n, rec
}

// read_to_plaintext read from Session reader, constructs record, decrypts it, and return TLSPlaintext.
// when we receive change_cipher_spec msg, instead process it, we discard it, and take the next record and return it.
fn (mut ses Session) read_to_plaintext(with_key []u8, with_iv []u8) !(TLSPlaintext, []u8) {
	log.info('${@METHOD}: ....')
	_, rec := ses.read_with_skipped_ccs_record()!
	// if session protection is active, do decryption, and check for .change_cipher_message
	// otherwise, just return it
	if ses.secure_state {
		pxt, tag := ses.decrypt_record(rec, with_key, with_iv)!
		if pxt.ctn_type == .change_cipher_spec {
			_, next_rec := ses.read_with_skipped_ccs_record()!
			next_pxt, next_tag := ses.decrypt_record(next_rec, with_key, with_iv)!
			return next_pxt, next_tag
		}

		return pxt, tag
	}
	pxt := rec.to_plaintext()
	return pxt, nullbytes
}

// TODO: handshake messages maybe split up multiple records.
fn (mut ses Session) read_handshake_msg(exp_type HandshakeType, with_key []u8, with_iv []u8) !Handshake {
	log.info('${@METHOD}: ....')
	pxt, _ := ses.read_to_plaintext(with_key, with_iv)!

	// we expect .handshake type here
	if !pxt.expect_type(ContentType.handshake) {
		alert := new_alert(.fatal, .unexpected_message)
		ses.change_to_state(.closed)
		return tls_error(alert, 'recv ${pxt.ctn_type}, expected .handshake')
	}
	hsk := Handshake.unpack(pxt.fragment)!
	if !hsk.expect_hsk_type(exp_type) {
		alert := new_alert(.fatal, .unexpected_message)
		ses.change_to_state(.closed)
		return tls_error(alert, 'recv ${hsk.msg_type}, expected ${exp_type}')
	}
	return hsk
}

fn (mut ses Session) write_record_with_payload(payload []u8, ctn_type ContentType) !int {
	record := TLSRecord{
		ctn_type: ctn_type
		version: tls_v12
		length: payload.len
		payload: payload
	}
	recbytes := record.pack()!
	n := ses.write(recbytes)!
	return n
}

pub fn (mut ses Session) decrypt(rec TLSRecord) !(TLSPlaintext, []u8) {
	if ses.secure_state {
		if ses.hsk_completed {
			assert ses.state() == .application_data
			assert ses.ks.srv_app_wrkey.len != 0
			assert ses.ks.srv_app_wriv.len != 0
			pxt, mac := ses.decrypt_record(rec, ses.ks.srv_app_wrkey, ses.ks.srv_app_wriv)!
			return pxt, mac
		}
		// in handshake phase
		assert int(ses.state()) <= int(State.connected)
		assert ses.ks.srv_hsk_wrkey.len != 0
		assert ses.ks.srv_hsk_wriv.len != 0
		pxt, mac := ses.decrypt_record(rec, ses.ks.srv_hsk_wrkey, ses.ks.srv_hsk_wriv)!
		return pxt, mac
		// TODO: if its a early packet, should protected under early_write_key (iv)
	}
	// otherwise is plaintext
	pxt := rec.to_plaintext()
	return pxt, nullbytes
}

// decrypt_record decrypts TLSRecord when it's should be decrypted, or interpretes its as a plaintext if not.
fn (mut ses Session) decrypt_record(rec TLSRecord, key []u8, iv []u8) !(TLSPlaintext, []u8) {
	// when encryption/deceyption engine is active, we treated
	// this record as an encrypted record, otherwise is a plaintext record
	if ses.secure_state {
		cxt := rec.to_ciphertext()
		pxl, tag := ses.reclayer.decrypt(cxt, key, iv)!
		return pxl, tag
	}
	return error('not in secure state')
}

// record with an Alert type MUST contain exactly one message. it doesn't span on multiple record.
// alert messages are encrypted as specified by the current connection state.
// TOOD: provide with context write_key and write_iv
pub fn (mut ses Session) write_alert(a Alert) !int {
	if ses.state_is_closed() {
		return error('write on .closed state')
	}
	ap := TLSPlaintext.from_alert(a)!
	assert ap.length < math.max_u16

	if ses.secure_state {
		// do encryption of alert record
		// TODO: its depends where is this happen on the Session state,
		// when in .connected state, we use client_app_write_key
		// when in handshake phase, we use client_hsk_write_key
		if ses.hsk_completed {
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

fn (mut ses Session) write_handshake(h Handshake, key []u8, iv []u8) !int {
	if ses.state_is_closed() {
		return error('write on .closed state')
	}
	// pl := TLSPlaintext.from_handshake(h)!
	// Handshake messages are supplied to the TLS record layer where they
	// are encapsulated within one or more TLSPlaintext or TLSCiphertext structures
	pxt_list := ses.reclayer.take_handshake_msg(h)!
	mut n := 0
	if ses.secure_state {
		for pl in pxt_list {
			cxt := ses.reclayer.encrypt(pl, key, iv)!
			nxt := ses.write_ciphertext(cxt)!
			n += nxt
		}

		return n
	}
	obj := pxt_list.pack()!
	n += ses.write(obj)!

	return n
}

pub fn (mut ses Session) write_application_data(data []u8) !int {
	assert ses.state() == .application_data
	if !ses.secure_state {
		return error('Handshake not completed or performed')
	}
	pxt := TLSPlaintext{
		ctn_type: .application_data
		legacy_version: tls_v12
		length: data.len
		fragment: data
	}
	cxt := ses.reclayer.encrypt(pxt, ses.ks.cln_app_wrkey, ses.ks.cln_app_wriv)!
	return ses.write_ciphertext(cxt)!
}

// write_plaintext writes TLSPlaintext to underlying Session writer
fn (mut ses Session) write_plaintext(px TLSPlaintext) !int {
	if ses.state_is_closed() {
		return error('write on .closed state')
	}
	pb := px.pack()!
	n := ses.write(pb)!
	return n
}

// write_ciphertext writes TLSCiphertext to underlying Session writer
fn (mut ses Session) write_ciphertext(cx TLSCiphertext) !int {
	if ses.state_is_closed() {
		return error('write on .closed state')
	}
	cb := cx.pack()!
	n := ses.write(cb)!
	return n
}

fn (mut ses Session) handle_alert(ae Alert, msg string) ! {
	match ae.desc {
		.close_notify {
			// do nothing, or should do transition to closing state ?
		}
		// Whenever an implementation encounters a fatal error condition, it
		// SHOULD send an appropriate fatal alert and MUST close the connection
		// without sending or receiving any additional data.
		else {
			// treated as fatal error
			// ses.write_alert(mut wr, ae)!
			ses.change_to_state(.closed)
			if msg == '' {
				return tls_error(ae, ae.desc.str())
			}
			return tls_error(ae, msg)
		}
	}
}

// set_buffer sets buffered reader of the Session.
fn (mut ses Session) set_reader(r io.Reader) {
	sr := io.new_buffered_reader(io.BufferedReaderConfig{ reader: r })
	ses.reader = sr
}

// reset resets and clear internal state of Session
fn (mut ses Session) reset() ! {
	ses.reclayer.reset_sequence()
	ses.reset_state()
	ses.recv_hrr = false
	ses.ks.hsx.clear()
	// ses.keys.reset()
	// TODO: buf.clear() ?
}

// write writes the provided byte array to the socket
fn (mut ses Session) write(bytes []u8) !int {
	lock {
		if ses.state_is_closed() || ses.conn.sock.handle <= 1 {
			return error('socket_write: trying to write on a closed socket')
		}
		for {
			n := ses.reclayer.transmit_bytes(mut ses.conn, bytes) or {
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

// close closes the connection
pub fn (mut ses Session) close() ! {
	if ses.state_is_closed() || ses.conn.sock.handle <= 1 {
		return error('Socket already closed')
	}
	log.info('Do ${@METHOD}')
	defer {
		ses.reset_state()
		ses.reclayer.reset_sequence()
		ses.conn.close() or {}
	}

	// send close notify alert then close
	a := Alert{
		level: .warning
		desc: .close_notify
	}
	n := ses.write_alert(a)!
	log.info('Successfully write alert ${a.desc} ${n} bytes')
}

// read reads data from socket into the provided buffer
fn (mut ses Session) read(mut buf []u8) !int {
	lock {
		if ses.state_is_closed() || ses.conn.sock.handle <= 1 {
			return error('sock_read: trying to read a closed socket')
		}
		n := read_at_least(mut ses.reader, mut buf)!
		assert n == buf.len

		return n
	}
	return error('none')
}

// read_at_least reads at least buf.len of bytes data from socket into the provided buffer
fn (mut ses Session) read_at_least(mut buf []u8) !int {
	lock {
		if ses.state_is_closed() || ses.conn.sock.handle <= 1 {
			return error('sock_read: trying to read a closed socket')
		}
		// n := ses.reader.read(mut buf)!
		n := read_at_least(mut ses.reader, mut buf)!
		assert n == buf.len

		return n
	}
	return error('none')
}

// Utility read function, ported from Golang io package
//
// read_at_least reads from r into result buffer until it has read at least result.len
// Its adapted from golang of ReadAtLeast from bytes module. Its return number of bytes
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
