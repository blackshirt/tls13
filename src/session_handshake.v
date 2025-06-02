module tls13

import log
import crypto.hmac
import crypto.rand
import encoding.binary
import blackshirt.ecdhe

// This file mainly contains routines for doing TLS handshake process.

// do_full_handshake performs handshake process until we get state .ts_application_data
pub fn (mut ses Session) do_full_handshake() ! {
	if ses.on_closing_state() {
		return error('Handshake maybe in progress, .ts_closing on the way')
	}
	if ses.on_closed_state() {
		// please, do proper way to reset and initialize session
		assert !ses.hsk_secured
		assert !ses.hsk_connected
		assert !ses.hsk_completed
		ses.change_tls_state(.ts_init)
	}
	if ses.hsk_completed {
		// we have reached connected state, dont need to do handshake
		assert ses.hsk_secured && ses.hsk_connected
		return
	}
	for !ses.hsk_completed {
		log.info('State: ${ses.tls_state()}')
		match ses.tls_state() {
			.ts_init {
				// todo: add support for initializing
				// 0-rtt or resume handshake
				ch := ses.build_initial_client_hello()!
				ses.firstch = ch
				ses.change_tls_state(.ts_client_hello)
			}
			.ts_client_hello {
				// changes state was done in `.send_client_hello` step
				// because of, there are possibility we receive HelloRetryRequest msg
				if ses.first_client_hello() {
					hsk := HandshakePayload(ses.firstch).pack_to_handshake()!
					_ := ses.send_handshake_msg(hsk)!

					// hsk := HandshakePayload(ses.firstch).pack_to_handshake()!
					//_ := ses.send_handshake_msg(hsk)!
					_ := ses.ks.append_hskmsg_and_update_hash(hsk)!
					// TODO: early keys calcs
					//
					// for initial ClientHello, change state to .server_hello
					ses.change_tls_state(.ts_server_hello)
				} else {
					assert ses.second_client_hello()
					// Second ClientHello responding to a HelloRetryRequest, the client must
					// use the same random value as it did in the initial ClientHello
					// TODO: build new CLientHello respons to HelloRetryRequest
					newch := ClientHello{
						legacy_version:             tls_v12
						random:                     ses.firstch.random
						legacy_session_id:          ses.firstch.legacy_session_id
						cipher_suites:              ses.firstch.cipher_suites
						legacy_compression_methods: ses.firstch.legacy_compression_methods
						extensions:                 ses.firstch.extensions
					}
					hsk := HandshakePayload(newch).pack_to_handshake()!
					_ := ses.send_handshake_msg(hsk)!
					n := ses.ks.append_hskmsg_and_update_hash(hsk)!
					assert n == hsk.packed_length()

					// change state to wait second valid server_hello
					ses.change_tls_state(.ts_server_hello_2)
				}
			}
			.ts_client_certificate {
				// TODO: check if client has received CertificateRequest from server
				if !ses.rcv_srv_certreq {
					return error('Not receiving server CertificateRequest, no need to send Certificate msg')
				}
				cert := Certificate{}
				ses.send_client_certificate_msg(cert)!
				ses.change_tls_state(.ts_client_certificate_verify)
			}
			// Waiting for a message from the server?
			.ts_server_hello, .ts_server_hello_2, .ts_encrypted_extensions,
			.ts_server_certificate_request, .ts_server_certificate, .ts_server_certificate_verify,
			.ts_server_finished {
				// TODO: proper way for handling multiples handshake messages
				// sent in single TLS record
				pxt := ses.read_and_decrypt_record()!
				ses.parse_tls_message(pxt)!
			}
			.ts_client_certificate_verify {
				// TODO: check client has received CertificateRequest from server,
				// and also client Certificate has been sent to the peer.
				crv := CertificateVerify{}
				ses.send_client_certificate_verify_msg(crv)!
				ses.change_tls_state(.ts_client_finished)
			}
			.ts_client_finished {
				// client FInished calculation
				cln_finkey := ses.ks.client_finished_key(ses.ks.cln_hsk_tsecret)!
				cln_verify_data := ses.ks.verify_data(cln_finkey, ses.ks.hsx)!
				client_fin := Finished{
					verify_data: cln_verify_data
				}
				ses.send_client_finished_msg(client_fin)!

				// After successfully sent client Finished msg, we transite to connected state,
				ses.change_tls_state(.ts_connected)
			}
			.ts_key_update {
				ku := KeyUpdate{}
				ses.send_key_update(ku)!
				// After sending a KeyUpdate message, the sender shall send all its
				// traffic using the next generation of keys
				ses.change_tls_state(.ts_application_data)
			}
			.ts_connected {
				// Transitional state, actually you can directly goes to .ts_application_data
				// In connected handshake state, we marks session's hsk_connected as true
				ses.hsk_connected = true

				// after this onward, we should use app_write_key (iv) for encrypt or decrypt
				// so, we reset the counter
				ses.reclayer.reset_read_seq()
				ses.reclayer.reset_write_seq()

				// At this point, the handshake is complete, and the client and server
				// can exchange application-layer data
				ses.change_tls_state(.ts_application_data)
			}
			.ts_application_data {
				log.info('Reached ${ses.tls_state()}')
				ses.hsk_completed = true
			}
			.ts_endof_early_data {
				// EndOfEarlyData message indicates that all 0-RTT application
				// data messages, if any, have been transmitted and that the following
				// records are protected under handshake traffic keys
				ed := EndOfEarlyData{}
				ses.send_eoed_msg(ed)!

				// change to hsk_secured
				ses.hsk_secured = true
			}
			.ts_closing {
				// Mark the Session as closed
				ses.change_tls_state(.ts_closed)
			}
			.ts_closed {
				// do something when session.tsate is .ts_closed
				return error('Drops to .ts_closed state')
			}
			else {
				return error('Should not here')
			}
		}
	}
}

pub fn (mut ses Session) do_post_handshake() ! {
	// make sure its after handshake has been established
	if !ses.hsk_connected {
		return error('Handshake not completed for post handshake')
	}
	for {
		mut hdr := []u8{len: 5}
		n := ses.read(mut hdr) or { return }
		// if n == 0 {
		//	return
		//}
		if n < 5 {
			return error('truncated bytes header')
		}
		ctn_type := ContentType.from(hdr[0])! // unsafe { ContentType(hdr[0]) }
		ver := binary.big_endian_u16(hdr[1..2])
		version := ProtoVersion.from(int(ver))! // unsafe { ProtoVersion(ver) }
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

		// lets try to decrypt
		pxt := ses.decrypt(rec)!
		ses.parse_post_msg(pxt)!
	}
}

fn (mut ses Session) parse_post_msg(pxt TLSPlaintext) ! {
	match pxt.ctn_type {
		.handshake {
			hsk := Handshake.unpack(pxt.fragment)!
			match hsk.msg_type {
				// Two messages maybe sent by server after handshake was completed
				// ie, KeyUpdate and NewSessionTicket message
				.key_update {
					// TODO: checks and validates key_update msg
					ku := KeyUpdate.unpack(hsk.payload)!
					ses.parse_key_update(ku)!
					// other todo
				}
				.new_session_ticket {
					// TODO: validates ticket
					nst := NewSessionTicket.unpack(hsk.payload)!
					ses.tickets << nst
				}
				else {
					return error('Bad handshake msg ${hsk.msg_type} for post handshake')
				}
			}
		}
		.application_data {
			// just add to app_buffer
			ses.app_buffer << pxt
		}
		.alert {
			a := Alert.unpack(pxt.fragment)!
			ses.parse_tls_alert(a)!
		}
		else {
			return error('Bad ${pxt.ctn_type} for post handshake')
		}
	}
}

fn (mut ses Session) parse_tls_message(pxt TLSPlaintext) ! {
	log.info('${@FN} .. ${pxt.ctn_type}')
	match pxt.ctn_type {
		.handshake {
			// handshake msg maybe coalesced into single TLSPlaintext record,
			// so we do RecordLayer.uncoalesced_record to get []Handshake
			// hsk := Handshake.unpack(pxt.fragment)!
			// dump(pxt)
			// dump(hsk)
			// ses.parse_handshake_msg(hsk)!

			hks := ses.reclayer.uncoalesced_record(pxt)! //[]Handshake {
			for h in hks {
				ses.parse_handshake_msg(h)!
			}
		}
		.change_cipher_spec {
			// do nothing
		}
		.alert {
			ale := Alert.unpack(pxt.fragment)!
			ses.parse_tls_alert(ale)!
		}
		.application_data {
			// The server cannot transmit application data before the handshake
			// is completed
			if !ses.hsk_completed {
				return error('unexpected message')
			}
			log.info('Receive application_data')
			// when received application_data msg in post handshake,
			// its mean we already completely post handshake phase,
			// do required thing and then break
			ses.app_buffer << pxt
			ses.hsk_completed = true
		}
		else {
			return error('unsupported type')
		}
	}
}

fn (mut ses Session) parse_server_hsk_msg(hsk Handshake) ! {
	log.info('${@FN}..${hsk.msg_type}')
	match hsk.msg_type {
		.hello_retry_request {
			// if we have receive HelloRetryRequest before this, we should abort
			// the connection, we can not do more with security params negotiation.
			// Internally, parse_hello_retry_request does check for this.
			// but we check it here for early exit.
			if ses.rcv_hello_retry || ses.tls_state() == .ts_server_hello_2 {
				return error('Second HelloRetryRequest msg is not allowed')
			}
			sh := ServerHello.unpack(hsk.payload)!
			ses.parse_hello_retry_request(sh)!

			if ses.compat_support {
				// The middlebox compatibility mode improves the chance of successfully
				// connecting through middleboxes
				if ses.tls_state() == .ts_server_hello {
					// In middlebox compatibility mode, the client sends a dummy
					// ChangeCipherSpec record immediately before its second flight
					// ses.send_dummy_ccs(ccs)!
				}
			}
			n := ses.ks.append_hskmsg_and_update_hash(hsk)!
			assert n == hsk.packed_length()
			// The client can send its second flight
			ses.change_tls_state(.ts_client_hello)
		}
		.server_hello {
			sh := ServerHello.unpack(hsk.payload)!
			if hsk.is_hrr()! {
				// currently, parse_hello_retry_request return error
				// we have no support for this HelloRetryRequest msg.
				ses.parse_hello_retry_request(sh)!
				n := ses.ks.append_hskmsg_and_update_hash(hsk)!
				assert n == hsk.packed_length()
				// back state to .ts_client_hello for second ClientHello flight
				ses.change_tls_state(.ts_client_hello)
			} else {
				ses.parse_server_hello(sh)!
				n := ses.ks.append_hskmsg_and_update_hash(hsk)!
				assert n == hsk.packed_length()

				// we can derive traffic secret and keys needed
				ses.calc_shared_secret()!
				ses.derive_early_traffic_keys()!
				ses.derive_handshake_traffic_keys()!

				// sets to secure state
				ses.hsk_secured = true
				ses.change_tls_state(.ts_encrypted_extensions)
			}
		}
		// receive server .encrypted_extensions?
		.encrypted_extensions {
			// EncryptedExtensions message sent by server immediately after
			// ServerHello message. EncryptedExtensions message contains
			// extensions that can be protected
			ee := EncryptedExtensions.unpack(hsk.payload)!
			ses.parse_encrypted_extensions(ee)!
			n := ses.ks.append_hskmsg_and_update_hash(hsk)!
			assert n == hsk.packed_length()

			// where go to state
			if ses.psk_enabled {
				ses.change_tls_state(.ts_server_finished)
			} else {
				ses.change_tls_state(.ts_server_certificate_request)
			}
		}
		// receive server .certificate_request
		.certificate_request {
			cert_req := CertificateRequest.unpack(hsk.payload)!
			ses.parse_cert_request(cert_req)!
			n := ses.ks.append_hskmsg_and_update_hash(hsk)!
			assert n == hsk.packed_length()

			// We have received CertificateRequest msg, so set `ses.rcv_srv_certreq` to true
			ses.rcv_srv_certreq = true

			// we dont support to send Certificate currently, return error instead
			// return error('Receives certificate_request that doesnt we support')
			ses.change_tls_state(.ts_server_certificate)
		}
		// receive server certificate msg
		.certificate {
			cert := Certificate.unpack(hsk.payload)!
			ses.parse_certificate(cert)!
			n := ses.ks.append_hskmsg_and_update_hash(hsk)!
			assert n == hsk.packed_length()

			ses.change_tls_state(.ts_server_certificate_verify)
		}
		// receive server certificate_verify msg
		.certificate_verify {
			// When authenticating via a certificate. server should sent this message
			// immediately after the Certificate message
			cert_verif := CertificateVerify.unpack(hsk.payload)!
			ses.handle_cert_verify(cert_verif)!
			n := ses.ks.append_hskmsg_and_update_hash(hsk)!
			assert n == hsk.packed_length()

			ses.change_tls_state(.ts_server_finished)
		}
		// receive server Finished msg
		.finished {
			// A Finished message is sent after an optinal server ChangeCipherSpec,
			// Certificate, and CertificateVerify message to verify that the key
			// exchange and authentication processes were successful
			fin := Finished.unpack(hsk.payload)!
			// TODO: verify data of server Finished.verify_data
			ses.parse_server_finished(fin)!

			n := ses.ks.append_hskmsg_and_update_hash(hsk)!
			assert n == hsk.packed_length()

			// After receives server Finished msg, we can derive application traffic key
			// and sets `Session.hsk_connected` to true
			ses.derive_app_traffic_keys()!

			// if we receiving CertificateRequest msg from server, we should
			// send client Certificate
			if ses.rcv_srv_certreq {
				ses.change_tls_state(.ts_client_certificate)
			} else {
				// Continue to do post handshake
				ses.change_tls_state(.ts_client_finished)
			}
		}
		.new_session_ticket {
			// In TLS 1.3, .new_session_ticket maybe sent by server after
			// handshake was completed, in post handshake phase.
			nst := NewSessionTicket.unpack(hsk.payload)!
			ses.parse_new_session_ticket(nst)!

			ses.tickets << nst
			// hacky to break
			ses.change_tls_state(.ts_application_data)
		}
		.key_update {
			// KeyUpdate handshake message is used to indicate that the server
			// is updating its sending cryptographic keys. This message can be sent
			// by the server after it has sent a Finished message
			ku := KeyUpdate.unpack(hsk.payload)!
			ses.parse_key_update(ku)!
			ses.do_key_update()!
			ses.change_tls_state(.ts_key_update)
		}
		else {
			return error('Unsupported handshake type: ${hsk.msg_type}')
		}
	}
}

fn (mut ses Session) send_client_hello() ! {
	log.info('${@FN}')
	if ses.tls_state() == .ts_client_hello {
		// check if this initial ClientHello sent
		if ses.first_client_hello() {
			hsk := HandshakePayload(ses.firstch).pack_to_handshake()!
			_ := ses.send_handshake_msg(hsk)!

			// hsk := HandshakePayload(ses.firstch).pack_to_handshake()!
			//_ := ses.send_handshake_msg(hsk)!
			_ := ses.ks.append_hskmsg_and_update_hash(hsk)!
			// TODO: early keys calcs
			//
			// for initial ClientHello, change state to .server_hello
		} else {
			assert ses.second_client_hello()
			// Second ClientHello responding to a HelloRetryRequest, the client must
			// use the same random value as it did in the initial ClientHello
			// TODO: build new CLientHello respons to HelloRetryRequest
			newch := ClientHello{
				legacy_version:             tls_v12
				random:                     ses.firstch.random
				legacy_session_id:          ses.firstch.legacy_session_id
				cipher_suites:              ses.firstch.cipher_suites
				legacy_compression_methods: ses.firstch.legacy_compression_methods
				extensions:                 ses.firstch.extensions
			}
			hsk := HandshakePayload(newch).pack_to_handshake()!
			_ := ses.send_handshake_msg(hsk)!
			n := ses.ks.append_hskmsg_and_update_hash(hsk)!
			assert n == hsk.packed_length()

			// change state to wait second valid server_hello
			ses.change_tls_state(.ts_server_hello_2)
		}
	}
	return error('Bad state: ${ses.tls_state()} to perform ${@METHOD}')
}

fn (mut ses Session) parse_tls_alert(a Alert) ! {
	log.info('${@FN}')
	match a.level {
		.warning {
			// Increment the count of consecutive warning alerts
			ses.alert_count += 1
			if ses.alert_count > max_warning_alerts {
				return error('unexpected_message: alert warning count exceed')
			}
			match a.desc {
				.close_notify {
					// The close_notify alert is used to indicate orderly closure of one
					// direction of the connection.  Upon receiving such an alert, the TLS
					// implementation SHOULD indicate end-of-data to the application.
					// This alert notifies the recipient that the sender will
					// not send any more messages on this connection.  Any data received
					// after a closure alert has been received MUST be ignored.
					ses.rcv_close_notify = true

					// Prepare for closing
					if ses.tls_state() == .ts_application_data {
						ses.change_tls_state(.ts_closing)
					}
				}
				.user_canceled {
					// This alert notifies the recipient that the sender is canceling the
					// handshake for some reason unrelated to a protocol failure.
					// If a user cancels an operation after the handshake is
					// complete, just closing the connection by sending a close_notify
					// is more appropriate.  This alert SHOULD be followed by a close_notify
					if ses.hsk_connected {
						ses.write_alert(new_alert(.warning, .close_notify))!
						ses.change_tls_state(.ts_closing)
					}
				}
				else {
					// Otherwise treated as fatal error
					// Whenever an implementation encounters a fatal error condition, it
					// SHOULD send an appropriate fatal alert and MUST close the connection
					// without sending or receiving any additional data.

					// ses.write_alert(mut wr, a)!
					ses.change_tls_state(.ts_closed)
					return tls_error(a)
				}
			}
		}
		.fatal {
			// A fatal alert message has been received
			ses.rcv_fatal_alert = true

			// Alert messages with a level of fatal result in the immediate
			// termination of the connection
			ses.change_tls_state(.ts_closed)

			// forget any session identifiers
			// ses.do_cleanup()
			ses.close()!
			return tls_error(a)
		}
	}
}

fn (mut ses Session) do_key_update() ! {
	return error('not implemented')
}

fn (mut ses Session) parse_handshake_msg(hsk Handshake) ! {
	// we only support parse server msg
	ses.parse_server_hsk_msg(hsk)!
}

fn (mut ses Session) parse_client_hsk_msg(hsk Handshake) ! {
	match hsk.msg_type {
		.client_hello {}
		.certificate_request {}
		.certificate {}
		.certificate_verify {}
		.key_update {}
		else {
			return error('not supported client hsk msg')
		}
	}
}

fn (mut ses Session) parse_server_hello(sh ServerHello) ! {
	log.info('${@FN}')
	// TODO: parse again associated ClientHello
	if ses.tls_state() != .ts_server_hello && ses.tls_state() != .ts_server_hello_2 {
		return error('bad state: ${ses.tls_state()}')
	}
	// check legacy_version
	if sh.legacy_version != tls_v12 {
		return error('version not supported')
	}
	// compression method, upon receipt of a HelloRetryRequest, the client must check that the
	// legacy_compression_method is 0
	if sh.legacy_compression_method != u8(0x00) {
		return error('decoding_failed: invalid compression method')
	}
	// check ServerHello.legacy_session_id_echo
	if sh.legacy_session_id_echo.len > 32 || sh.legacy_session_id_echo.len > sh.packed_length() {
		return error('decoding_failed: bad legacy_session_id')
	}

	// check for matching legacy_session_id
	// A client which receives a legacy_session_id_echo field that does not match what
	// it sent in the ClientHello MUST abort the handshake with an .illegal_parameter alert
	// Check again initial or updated ClientHello
	if ses.tls_state() != .ts_server_hello_2 {
		// Initial
		if !hmac.equal(ses.firstch.legacy_session_id, sh.legacy_session_id_echo) {
			ses.change_tls_state(.ts_closed)
			return error('Server and Client sessid does not match')
		}
	} else {
		// updated ClientHello
		assert ses.ks.hsx.len == 3 && ses.ks.hsx[2].msg_type == .client_hello
		second_ch := ClientHello.unpack(ses.ks.hsx[2].payload)!
		if !hmac.equal(second_ch.legacy_session_id, sh.legacy_session_id_echo) {
			ses.change_tls_state(.ts_closed)
			return error('Server and Client sessid does not match')
		}
	}

	// Perform downgrade check
	// TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below
	// MUST check that the last 8 bytes are not equal to either of these
	// values.  TLS 1.2 clients SHOULD also check that the last 8 bytes are
	// not equal to the second value if the ServerHello indicates TLS 1.1 or
	// below.  If a match is found, the client MUST abort the handshake with
	// an illegal_parameter alert
	last8 := sh.random[24..31]
	if hmac.equal(last8, tls12_random_magic) || hmac.equal(last8, tls12_random_magic) {
		ses.change_tls_state(.ts_closed)
		return error('Bad downgrade ServerHello.random detected')
	}

	// A client which receives a cipher suite that was not offered MUST abort the handshake
	if !ses.firstch.cipher_suites.is_exist(sh.cipher_suite) {
		ses.change_tls_state(.ts_closed)
		return error('ClientHello.cipher_suites does not contains server cipher_suite')
	}

	// Check whether the ServerHello message is received in response to the initial or the updated ClientHello
	if ses.tls_state() != .ts_server_hello_2 {
		// response to initial ClientHello
	} else {
		// Clients must check that the cipher suite supplied in the ServerHello
		// is the same as that in the HelloRetryRequest and otherwise abort the
		// handshake with an illegal_parameter alert
		assert ses.ks.hsx.len == 2 && ses.ks.hsx[1].is_hrr()!
		hrr := ServerHello.unpack(ses.ks.hsx[1].payload)!
		if sh.cipher_suite != hrr.cipher_suite {
			return error('illegal_parameter')
		}
	}

	// If the supported_versions extension in the ServerHello contains a version not offered
	// by the client or contains a version prior to TLS 1.3, the client MUST abort
	// the handshake with an illegal_parameter alert.
	srv_spv := sh.extensions.filtered_exts_with_type(.supported_versions) // []Extension
	if srv_spv.len == 0 {
		ses.change_tls_state(.ts_closed)
		return error('ServerHello.extensions does not contains SupportedVersions extension')
	}
	if srv_spv.len > 1 {
		ses.change_tls_state(.ts_closed)
		return error('Server.extensions contains multiples SupportedVersions extension')
	}
	spv := srv_spv[0] // Extension with .supported_versions type
	spver := SupportedVersions.unpack(spv.data, .server_hello)! // SupportedVersions
	sh_spv := spver as ServerHRetrySpV // cast to Server SupportedVersions
	// we check and only support for tls_v13
	if sh_spv.version != tls_v13 {
		ses.change_tls_state(.ts_closed)
		return error('Server.extensions SupportedVersions does not contains tls v1.3')
	}

	// check for KeyShare
	srv_kse := sh.extensions.filtered_exts_with_type(.key_share) // []Extension
	if srv_kse.len == 0 {
		ses.change_tls_state(.ts_closed)
		return error('ServerHello.extensions does not contains KeyShare extension')
	}
	if srv_kse.len > 1 {
		ses.change_tls_state(.ts_closed)
		return error('Server.extensions contains multiples KeyShare extension')
	}
	kse0 := srv_kse[0] // Extension with .key_share type
	is_hrr := sh.is_hrr()
	kxe := KeyShareExtension.unpack_from_extension(kse0, .server_hello, is_hrr)!
	// check if keyshare.group matching with supported client
	if kxe.server_share.group != NamedGroup.x25519 {
		ses.change_tls_state(.ts_closed)
		return error('ServerHello.extensions KeyShare group does not matching with .x25519')
	}
}

fn (mut ses Session) parse_hello_retry_request(sh ServerHello) ! {
	if sh.is_hrr() {
		// Currently, its not possible to achieve HelloRetryRequest
		// We can not provide updates to first ClientHello, we have no
		// more alternatives when server can't accept first ClientHello.
		// so, we return error instead.
		// TODO: add support for this message
		ses.change_tls_state(.ts_closing)
		return error('Bad response, recv HelloRetryRequest')
	}
	// If a client receives a second HelloRetryRequest in the same connection,
	// it must abort the handshake with an unexpected_message alert
	// This tells we have received HelloRetryRequest previously
	if ses.rcv_hello_retry {
		return error('unexpected_message: recv HelloRetryRequest')
	}
	ses.parse_server_hello(sh)!
}

fn (mut ses Session) send_key_update(ku KeyUpdate) ! {
}

fn (mut ses Session) calc_shared_secret() ! {
	hello_ctx, _ := ses.ks.hsx.take_hello_context()!
	mut hsk := Handshake{}
	contains_hrr := hello_ctx.contains_hrr()!

	// if hello_ctx contains hrr, ServerHello is the 4th msg in arrays
	// otherwise, is 2nd msg
	if contains_hrr {
		hsk = hello_ctx[3]
	} else {
		hsk = hello_ctx[1]
	}

	assert hsk.msg_type == .server_hello
	sh := ServerHello.unpack(hsk.payload)!

	// Shared Secret calculation
	// Client privkey has been calculated and setted in .init_client_hello() step
	kslist := sh.extensions.validate_with_filter(.key_share)! // []Extension
	ext_ks := kslist[0]
	// TODO: maybe HelloRetryRequest, adds support for this
	kssh := KeyShareExtension.unpack_from_extension(ext_ks, .server_hello, false)!
	srvshare := kssh.server_share.key_exchange
	server_pubkey := ecdhe.pubkey_with_key(srvshare, ecdhe.Curve.x25519)!
	// set context shared_sec
	// privkey := ses.exchanger.private_key_from_key(ses.privkey)!
	ses.shared_sec = ses.exchanger.shared_secret(ses.privkey, server_pubkey)!
}

fn (mut ses Session) derive_early_traffic_keys() ! {
	keys := if ses.psk_enabled { ses.psk_bytes } else { nullbytes }
	// TODO: calc more keys
	ses.ks.early_secret = ses.ks.early_secret(keys)!
}

fn (mut ses Session) derive_handshake_traffic_keys() ! {
	assert ses.shared_sec.len != 0
	ses.ks.hsk_secret = ses.ks.handshake_secret(ses.ks.early_secret, ses.shared_sec)!
	ses.ks.master_secret = ses.ks.master_secret(ses.ks.hsk_secret)!

	// HelloContext for this step, contains [ClientHello..ServerHello]
	hello_ctx, _ := ses.ks.hsx.take_hello_context()!

	assert hello_ctx.contains(HandshakeType.client_hello)
	assert hello_ctx.contains(HandshakeType.server_hello)

	// TODO: add support for HelloRetryRequest
	ses.ks.srv_hsk_tsecret = ses.ks.server_handshake_traffic_secret(ses.ks.hsk_secret,
		hello_ctx)!
	ses.ks.cln_hsk_tsecret = ses.ks.client_handshake_traffic_secret(ses.ks.hsk_secret,
		hello_ctx)!

	// hanshake write_key and write_iv
	// server
	ses.ks.srv_hsk_wrkey = ses.ks.server_handshake_write_key(ses.ks.srv_hsk_tsecret, ses.reclayer.cipher.key_size())!
	ses.ks.srv_hsk_wriv = ses.ks.server_handshake_write_iv(ses.ks.srv_hsk_tsecret, ses.reclayer.cipher.nonce_size())!
	// client
	ses.ks.cln_hsk_wrkey = ses.ks.client_handshake_write_key(ses.ks.cln_hsk_tsecret, ses.reclayer.cipher.key_size())!
	ses.ks.cln_hsk_wriv = ses.ks.client_handshake_write_iv(ses.ks.cln_hsk_tsecret, ses.reclayer.cipher.nonce_size())!
}

fn (mut ses Session) derive_app_traffic_keys() ! {
	// TODO: app traffic Calculation

	// application traffic Key calculation
	// In this stage, we have all handshake messages needed for application key derivation
	// KeyScheduler.hsx, arrays of handshakes message should contains [ClientHello ... server Finished]
	// application_traffic_secret calculation, hsx_ctx = [ClientHello...server Finished]
	//
	assert ses.ks.master_secret.len != 0
	ses.ks.srv_app_tsecret = ses.ks.server_application_traffic_secret_0(ses.ks.master_secret,
		ses.ks.hsx)!
	ses.ks.cln_app_tsecret = ses.ks.client_application_traffic_secret_0(ses.ks.master_secret,
		ses.ks.hsx)!

	ses.ks.srv_app_wrkey = ses.ks.server_application_write_key(ses.ks.srv_app_tsecret,
		ses.reclayer.cipher.key_size())!
	ses.ks.srv_app_wriv = ses.ks.server_application_write_iv(ses.ks.srv_app_tsecret, ses.reclayer.cipher.nonce_size())!

	ses.ks.cln_app_wrkey = ses.ks.client_application_write_key(ses.ks.cln_app_tsecret,
		ses.reclayer.cipher.key_size())!
	ses.ks.cln_app_wriv = ses.ks.client_application_write_iv(ses.ks.cln_app_tsecret, ses.reclayer.cipher.nonce_size())!
}

fn (mut ses Session) parse_key_update(ku KeyUpdate) ! {
	// Ensure the value of the KeyUpdate.req_update field is valid
	if ku.req_update != .update_not_requested && ku.req_update != .update_requested {
		// If an implementation receives any other value, it must terminate the
		// connection with an illegal_parameter alert
		return error('ERROR_ILLEGAL_PARAMETER')
	}

	// Implementations that receive a KeyUpdate prior to receiving a Finished
	// message must terminate the connection with an unexpected_message alert
	if ses.tls_state() != .ts_application_data && ses.tls_state() != .ts_closing {
		// Report an error
		return error('ERROR_UNEXPECTED_MESSAGE')
	}
}

fn (mut ses Session) parse_new_session_ticket(nst NewSessionTicket) ! {
}

fn (mut ses Session) parse_encrypted_extensions(ee EncryptedExtensions) ! {
	if ses.tls_state() != .ts_encrypted_extensions {
		return error('Not in .encrypted_extensions state')
	}
}

fn (mut ses Session) parse_cert_request(cr CertificateRequest) ! {
}

fn (mut ses Session) parse_certificate(cert Certificate) ! {
}

fn (mut ses Session) handle_cert_verify(cv CertificateVerify) ! {
}

fn (mut ses Session) parse_server_finished(fin Finished) ! {
	// TODO: check server Finished.verify_data
}

// Utility function
//
// first_client_hello checks whether this is initial ClientHello sent to server
fn (ses Session) first_client_hello() bool {
	return ses.ks.hsx.len == 0
}

// second_client_hello checks whether this is updated ClientHello after receiving HelloRetryRequest
fn (ses Session) second_client_hello() bool {
	// [ClientHello, ServerHello with hrr)
	if ses.ks.hsx.len != 2 {
		return false
	}
	hrr := ses.ks.hsx[1].is_hrr() or { false }

	return ses.rcv_hello_retry && ses.ks.hsx.len == 2 && hrr
}

fn (mut ses Session) make_keypair() !(ecdhe.PrivateKey, ecdhe.PublicKey) {
	privkey := ses.exchanger.generate_private_key()!
	pubkey := ses.exchanger.public_key(privkey)!

	return privkey, pubkey
}

// build_initial_client_hello builds supported ClientHello for this implementation
fn (mut ses Session) build_initial_client_hello() !ClientHello {
	// make key pair for key exchange
	privkey, pubkey := ses.make_keypair()!
	// set Session privkey and pubkey
	ses.privkey = privkey
	ses.pubkey = pubkey

	// initial ClientHello, generates CLientHello random using `crypto.rand`
	crandom := rand.read(32)!
	// In compatibility mode the session ID field must be non-empty
	if ses.compat_support {
		if ses.sessid.len == 0 {
			// A client not offering a pre-TLS 1.3 session must generate a
			// new 32-byte value. This value need not be random but should
			// be unpredictable to avoid implementations fixating on a
			// specific value (refer to RFC 8446, section 4.1.2)
			ses.sessid = rand.read(32)!
		}
	} else {
		//  Otherwise, it MUST be set as a zero-length vector (i.e., a zero-valued single byte length field).
		ses.sessid = nullbytes
	}
	ciphersuites := [CipherSuite.tls_chacha20_poly1305_sha256]

	mut exts := []Extension{}
	// server_name extension
	host, _ := ses.peer_address()!
	srvname := new_server_name(host)!
	srvname_list := ServerNameList([srvname])
	srvname_ext := srvname_list.pack_to_extension()!
	exts.append(srvname_ext)

	// SupportedVersions extension, we only support `tls_v13` version
	spv := ClientSpV{
		versions: [tls_v13]
	}
	spv_ext := SupportedVersions(spv).pack_to_extension()!
	exts.append(spv_ext)

	// NamedGroupList, currently, only `x25519` NamedGroup was supported
	ngl := NamedGroupList([NamedGroup.x25519])
	ngl_ext := ngl.pack_to_extension()!
	exts.append(ngl_ext)

	// signaturescheme
	signs_list := SignatureSchemeList([SignatureScheme.ed25519])
	signs_ext := signs_list.pack_to_extension()!
	exts.append(signs_ext)

	// KeyShare extension
	ke_entry0 := KeyShareEntry{
		group:        .x25519
		key_exchange: pubkey.bytes()!
	}

	ks := KeyShareExtension{
		msg_type:      .client_hello
		is_hrr:        false
		client_shares: [ke_entry0]
	}
	ks_ext := ks.pack_to_extension()!
	exts.append(ks_ext)
	// TODO: add another supported extension

	ch := ClientHello{
		random:            crandom
		legacy_session_id: ses.sessid
		cipher_suites:     ciphersuites
		extensions:        exts
	}
	return ch
}
