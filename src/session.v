module tls13

import io
import log
import net
import time
import blackshirt.ecdhe

const max_warning_alerts = 5

const max_session_ticket = 1

@[params]
pub struct Options {
	group  NamedGroup  = .x25519
	csuite CipherSuite = .tls_chacha20_poly1305_sha256
	rto    i64         = 2 * time.second // net.tcp_default_read_timeout = 30 seconds
	wto    i64         = 2 * time.second // net.tcp_default_write_timeout = 30 seconds
}

// Session represents TLs 1.3 capable client
@[heap]
struct Session {
mut:
	conn       &net.TcpConn       = unsafe { nil }
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
	psk_bytes  []u8 //// set when using PSK
	sessid     []u8 // Session Id for connection
	app_buffer []TLSPlaintext
	// Session flag supporting authentication via PSK (not yet supported)
	psk_enabled   bool // psk support matching with psk_bytes
	early_enabled bool
	// stores NewSessionTicket in post handshake message
	tickets []NewSessionTicket // session ticket received from server
	// state   State    = .closed
	tstate  TlsState = .ts_closed // play with this expanded state
	firstch ClientHello
	// Flags that tells session handshake phase.
	hsk_secured   bool
	hsk_connected bool
	hsk_completed bool // in .ts_application_data
	// How many Alert messages has been received by this Session
	alert_count int
	// Session receives HelloRetryRequest, set to true if received
	rcv_hello_retry bool
	// Session receives .close_notify alert, set to true if received
	// marking for closing the session
	rcv_close_notify bool
	// Session receives .fatal level alert, set to true if received
	// Lead to terminate connection
	rcv_fatal_alert bool
	// Session receives CertificateRequest message from Server, set to true if received
	// Client should sent Certificate message to accomply this
	rcv_srv_certreq bool
	// Compatibility support, in plan
	compat_support bool
}

// new_session creates new session from already connected tcp connection
pub fn new_session(mut conn net.TcpConn, opt Options) !&Session {
	conn.set_read_timeout(opt.rto)
	conn.set_write_timeout(opt.wto)

	cv := opt.group.curve()!
	exchanger := ecdhe.new_exchanger(cv)!
	ks := new_key_scheduler(opt.csuite.hasher())!
	reclayer := new_record_layer(opt.csuite)!

	mut ses := &Session{
		privkey: ecdhe.PrivateKey{
			curve: exchanger
		}
		pubkey:  ecdhe.PublicKey{
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

fn (ses Session) peer_address() !(string, u16) {
	addr := ses.conn.peer_ip()!
	host, port := net.split_address(addr)!
	return host, port
}

pub fn (mut ses Session) decrypt(rec TLSRecord) !TLSPlaintext {
	if ses.hsk_secured {
		if ses.hsk_connected {
			// TODO: check for on_closing_state
			assert int(ses.tls_state()) > int(TlsState.ts_connected) && !ses.on_closing_state()
			assert ses.ks.srv_app_wrkey.len != 0
			assert ses.ks.srv_app_wriv.len != 0
			pxt := ses.decrypt_record(rec, ses.ks.srv_app_wrkey, ses.ks.srv_app_wriv)!
			return pxt
		}
		// in handshake phase
		assert int(ses.tls_state()) <= int(TlsState.ts_connected) && !ses.on_closed_state()
		assert ses.ks.srv_hsk_wrkey.len != 0
		assert ses.ks.srv_hsk_wriv.len != 0
		pxt := ses.decrypt_record(rec, ses.ks.srv_hsk_wrkey, ses.ks.srv_hsk_wriv)!
		return pxt
		// TODO: if its a early packet, should protected under early_write_key (iv)
	}
	// otherwise is plaintext
	pxt := rec.to_plaintext()
	return pxt
}

pub fn (ses Session) tickets() []NewSessionTicket {
	return ses.tickets
}

// decrypt_record decrypts TLSRecord when it's should be decrypted, or interpretes its as a plaintext if not.
fn (mut ses Session) decrypt_record(rec TLSRecord, key []u8, iv []u8) !TLSPlaintext {
	// when encryption/deceyption engine is active, we treated
	// this record as an encrypted record, otherwise is a plaintext record
	if ses.hsk_secured {
		cxt := rec.to_ciphertext()
		pxl := ses.reclayer.decrypt(cxt, key, iv)!
		return pxl
	}
	return error('not in secure state')
}

// set_buffer sets buffered reader of the Session.
fn (mut ses Session) set_reader(r io.Reader) {
	sr := io.new_buffered_reader(io.BufferedReaderConfig{ reader: r })
	ses.reader = sr
}

// reset resets and clear internal state of Session
fn (mut ses Session) reset() ! {
	ses.reclayer.reset_sequence()
	ses.reset_tls_state()
	ses.rcv_hello_retry = false
	ses.ks.hsx.clear()
	// ses.keys.reset()
	// TODO: buf.clear() ?
}

// close closes the connection
pub fn (mut ses Session) close() ! {
	if ses.on_closed_state() || ses.conn.sock.handle <= 1 {
		return error('Socket already closed')
	}
	log.info('Do ${@METHOD}')
	defer {
		ses.reset_tls_state()
		ses.reclayer.reset()
		ses.conn.close() or {}
	}

	// send close notify alert then close
	a := Alert{
		level: .warning
		desc:  .close_notify
	}
	n := ses.write_alert(a)!
	log.info('Successfully write alert ${a.desc} ${n} bytes')
}
