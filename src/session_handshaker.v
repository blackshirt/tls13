module tls13

import log
import crypto.hmac
import crypto.rand
import blackshirt.ecdhe

// init_handshake initializes Session handshake process.
fn (mut ses Session) init_handshake() ! {
	log.info('Perform ${@METHOD}....')
	for !ses.hsk_started() {
		match ses.state() {
			.closed {
				// just change state to .init
				ses.change_to_state(.init)
			}
			.init {
				// initialize ClientHello message
				ses.init_client_hello()!
			}
			else {
				return error('dont need to init hsk on current state')
			}
		}
	}
}

fn (mut ses Session) init_client_hello() ! {
	log.info('Perform ${@METHOD}....')
	assert ses.state() == .init
	if ses.recv_hrr {
		return error('we dont support hrr this time')
	}
	// build needed random bytes
	privkey := ses.exchanger.generate_private_key()!
	pubkey := ses.exchanger.public_key(privkey)!

	// set Session privkey and pubkey
	ses.privkey = privkey
	ses.pubkey = pubkey

	random := rand.read(32)!
	sessid := []u8{}
	ciphersuites := [CipherSuite.tls_chacha20_poly1305_sha256]

	mut exts := []Extension{}
	// server_name extension
	host, _ := ses.peer_address()!
	srvname := new_server_name(host)!
	srvname_list := ServerNameList([srvname])
	srvname_ext := srvname_list.pack_to_extension()!
	exts.append(srvname_ext)

	// SupportedVersions extension
	spv := ClientSpV{
		versions: [tls_v13]
	}
	spv_ext := SupportedVersions(spv).pack_to_extension()!
	exts.append(spv_ext)

	// NamedGroupList
	ngl := NamedGroupList([NamedGroup.x25519])
	ngl_ext := ngl.pack_to_extension()!
	exts.append(ngl_ext)

	// signaturescheme
	signs_list := SignatureSchemeList([SignatureScheme.ed25519])
	signs_ext := signs_list.pack_to_extension()!
	exts.append(signs_ext)

	// KeyShare extension
	ke_entry0 := KeyShareEntry{
		group: .x25519
		key_exchange: pubkey.bytes()!
	}

	ks := KeyShareExtension{
		msg_type: .client_hello
		is_hrr: false
		client_shares: [ke_entry0]
	}
	ks_ext := ks.pack_to_extension()!
	exts.append(ks_ext)
	// TODO: add another supported extension

	ch := ClientHello{
		random: random
		legacy_session_id: sessid
		cipher_suites: ciphersuites
		extensions: exts
	}

	ses.firstch = ch
	ses.change_to_state(.start)
}

// do_handshake performs full TLS 1.3 handshake process
pub fn (mut ses Session) do_handshake() ! {
	ses.init_handshake()!
	for ses.hsk_not_completed() {
		log.info('Entering session state: ${ses.state()}')
		match ses.state() {
			.start {
				ses.say_first_hello()!
			}
			.wait_sh {
				// for this time, read_handshake_msg should does not need perform decryption
				// hsk := ses.read_handshake_msg(.server_hello, []u8{}, []u8{})!
				_, recsh := ses.read_with_skipped_ccs_record()!

				hsk := Handshake.unpack(recsh.payload)!
				if hsk.is_hrr()! {
					ses.recv_hrr = true
					log.info('${ses.state()}: recv serverhello HelloRetyrRequest')
					// should back to .start state with new clienthello
					return error('Unsupported ServerHello with HRR')
				}

				sh := ServerHello.unpack(hsk.payload)!
				ses.handle_server_hello(sh)!
				n := ses.ks.append_hskmsg_and_update_hash(hsk)!
				assert n == hsk.packed_length()

				// Shared Secret calculation
				// Client privkey has been calculated and setted in .init_client_hello() step
				kslist := sh.extensions.validate_with_filter(.key_share)! // []Extension
				ext_ks := kslist[0]
				// TODO: maybe HelloRetryRequest, adds support for this
				kssh := KeyShareExtension.unpack_from_extension(ext_ks, .server_hello,
					false)!
				srvshare := kssh.server_share.key_exchange
				server_pubkey := ecdhe.pubkey_with_key(srvshare, ecdhe.Curve.x25519)!
				// set context shared_sec
				// privkey := ses.exchanger.private_key_from_key(ses.privkey)!
				ses.shared_sec = ses.exchanger.shared_secret(ses.privkey, server_pubkey)!

				// Traffic keys calculation
				//
				ses.ks.early_secret = ses.ks.early_secret(nullbytes)!
				ses.ks.hsk_secret = ses.ks.handshake_secret(ses.ks.early_secret, ses.shared_sec)!
				ses.ks.master_secret = ses.ks.master_secret(ses.ks.hsk_secret)!

				// HelloContext for this step, contains [ClientHello..ServerHello]
				// hello_ctx, _ := ses.ks.hsx.take_hello_context()!
				// TODO: add support for HelloRetryRequest
				ses.ks.srv_hsk_tsecret = ses.ks.server_handshake_traffic_secret(ses.ks.hsk_secret,
					ses.ks.hsx)!
				ses.ks.cln_hsk_tsecret = ses.ks.client_handshake_traffic_secret(ses.ks.hsk_secret,
					ses.ks.hsx)!

				// hanshake write_key and write_iv
				// server
				ses.ks.srv_hsk_wrkey = ses.ks.server_handshake_write_key(ses.ks.srv_hsk_tsecret,
					ses.reclayer.cipher.key_size())!
				ses.ks.srv_hsk_wriv = ses.ks.server_handshake_write_iv(ses.ks.srv_hsk_tsecret,
					ses.reclayer.cipher.nonce_size())!
				// client
				ses.ks.cln_hsk_wrkey = ses.ks.client_handshake_write_key(ses.ks.cln_hsk_tsecret,
					ses.reclayer.cipher.key_size())!
				ses.ks.cln_hsk_wriv = ses.ks.client_handshake_write_iv(ses.ks.cln_hsk_tsecret,
					ses.reclayer.cipher.nonce_size())!

				// read ccs type,
				// TOOD: better handling of ChangeCipherSpec message, its maybe presents on current state or other
				// state on the handshake phase.
				_, rec := ses.read_raw_record()!
				assert rec.ctn_type == .change_cipher_spec

				// after this onwards, encryption should be activated
				ses.secure_state = true
				ses.change_to_state(.wait_ee)
			}
			.wait_ee {
				assert ses.state() == .wait_ee
				// read next record
				// TODO: handling of change_cipher_spec message, its maybe appear in the handshake context
				_, rec := ses.read_with_skipped_ccs_record()!

				// Server send EncryptedExtensions message immediately after the ServerHello message.
				// This is the first message that is encrypted under keys derived from the `server_handshake_traffic_secret`.
				// NOTE: for Client to decrypt this message, keys used for purposes is SAME AS
				// with server write traffic keys used for encrypting this handshake message.

				// for server_handshake_write_key and server_handshake_write_iv, it was calculated before this on previous state
				// so, we just assert it for correctness
				assert ses.ks.srv_hsk_wrkey.len != 0
				assert ses.ks.srv_hsk_wriv.len != 0
				pxt, _ := ses.decrypt_record(rec, ses.ks.srv_hsk_wrkey, ses.ks.srv_hsk_wriv)!

				hsk := Handshake.unpack(pxt.fragment)!
				_ := ses.ks.append_hskmsg_and_update_hash(hsk)!

				ee := EncryptedExtensions.unpack(hsk.payload)!
				ses.handle_encrypted_extensions(ee)!

				ses.change_to_state(.wait_cert_or_certreq)
			}
			.wait_cert_or_certreq {
				assert ses.state() == .wait_cert_or_certreq
				_, rec := ses.read_raw_record()!

				pxt, _ := ses.decrypt_record(rec, ses.ks.srv_hsk_wrkey, ses.ks.srv_hsk_wriv)!
				hsk := Handshake.unpack(pxt.fragment)!

				match hsk.msg_type {
					.certificate_request {
						cr := CertificateRequest.unpack(hsk.payload)!
						ses.handle_cert_request(cr)!
						n := ses.ks.append_hskmsg_and_update_hash(hsk)!
						assert n == pxt.fragment.len
						ses.change_to_state(.wait_certificate)
					}
					.certificate {
						cert := Certificate.unpack(hsk.payload)!
						log.info('Get Certificate: cert_list length:${cert.cert_list.len}')
						ses.handle_certificate(cert)!
						n := ses.ks.append_hskmsg_and_update_hash(hsk)!
						assert n == pxt.fragment.len
						ses.change_to_state(.wait_certverify)
					}
					else {
						alert := new_alert(.fatal, .unexpected_message)
						// ses.write_alert(mut wr, alert)!
						ses.change_to_state(.closed)
						return tls_error(alert, 'recv ${hsk.msg_type}, expected .certificate or .certificate_request')
					}
				}
			}
			.wait_certificate {
				assert ses.state() == .wait_certificate
				_, rec := ses.read_with_skipped_ccs_record()!

				pxt, _ := ses.decrypt_record(rec, ses.ks.srv_hsk_wrkey, ses.ks.srv_hsk_wriv)!

				hsk := Handshake.unpack(pxt.fragment)!
				cert := Certificate.unpack(hsk.payload)!
				log.info('Get Certificate: certificate list length:${cert.cert_list.len}')
				ses.handle_certificate(cert)!
				n := ses.ks.append_hskmsg_and_update_hash(hsk)!
				assert n == hsk.packed_length()
				ses.change_to_state(.wait_certverify)
			}
			.wait_certverify {
				assert ses.state() == .wait_certverify

				_, rec := ses.read_with_skipped_ccs_record()!
				pxt, _ := ses.decrypt_record(rec, ses.ks.srv_hsk_wrkey, ses.ks.srv_hsk_wriv)!
				hsk := Handshake.unpack(pxt.fragment)!

				cv := CertificateVerify.unpack(hsk.payload)!
				ses.handle_cert_verify(cv)!
				log.info('Get CertificateVerify: algorithm:${cv.algorithm}')

				n := ses.ks.append_hskmsg_and_update_hash(hsk)!
				assert n == hsk.packed_length()
				ses.change_to_state(.wait_finished)
			}
			.wait_finished {
				assert ses.state() == .wait_finished
				_, rec := ses.read_with_skipped_ccs_record()!
				pxt, _ := ses.decrypt_record(rec, ses.ks.srv_hsk_wrkey, ses.ks.srv_hsk_wriv)!
				hsk := Handshake.unpack(pxt.fragment)!

				fin := Finished.unpack(hsk.payload)!
				log.info('Get finished data: ${fin.verify_data.hex()}')
				ses.ks.append_hskmsg_and_update_hash(hsk)!

				// application traffic Key calculation
				// In this stage, we have all handshake messages needed for application key derivation
				// KeyScheduler.hsx, arrays of handshakes message should contains [ClientHello ... server Finished]
				// application_traffic_secret calculation, hsx_ctx = [ClientHello...server Finished]
				assert ses.ks.master_secret.len != 0
				ses.ks.srv_app_tsecret = ses.ks.server_application_traffic_secret_0(ses.ks.master_secret,
					ses.ks.hsx)!
				ses.ks.cln_app_tsecret = ses.ks.client_application_traffic_secret_0(ses.ks.master_secret,
					ses.ks.hsx)!

				ses.ks.srv_app_wrkey = ses.ks.server_application_write_key(ses.ks.srv_app_tsecret,
					ses.reclayer.cipher.key_size())!
				ses.ks.srv_app_wriv = ses.ks.server_application_write_iv(ses.ks.srv_app_tsecret,
					ses.reclayer.cipher.nonce_size())!

				ses.ks.cln_app_wrkey = ses.ks.client_application_write_key(ses.ks.cln_app_tsecret,
					ses.reclayer.cipher.key_size())!
				ses.ks.cln_app_wriv = ses.ks.client_application_write_iv(ses.ks.cln_app_tsecret,
					ses.reclayer.cipher.nonce_size())!

				// we handl finished after application key derivation step
				ses.handle_server_finished(fin)!

				// client FInished calculation
				cln_finkey := ses.ks.client_finished_key(ses.ks.cln_hsk_tsecret)!
				// dump(ses.ks.hsx)
				cln_verify_data := ses.ks.verify_data(cln_finkey, ses.ks.hsx)!
				client_fin := Finished{
					verify_data: cln_verify_data
				}
				cfh := HandshakePayload(client_fin).pack_to_handshake()!
				// append this client Finished msg to arrays
				ses.ks.append_hskmsg_and_update_hash(cfh)!

				// dump(cfh.payload.hex())
				// send EndofEarlyData if we support it
				// ed := EndOfEarlyData{}
				// _ := ses.send_endof_earlydata(ed)!

				// optional send Certificate and CertificateVerify
				ses.send_client_certificate()!
				ses.send_client_certificate_verify()!

				// send Client Finished
				_ := ses.send_client_finished(client_fin)!
				// calc client application keys
				// TODO: app key calculation
				ses.change_to_state(.connected)
			}
			.connected {
				// TODO: verify all Session state
				ses.hsk_completed = true
				log.info('State ${ses.state()}...Handshake completed')

				// after this onward, we should use app_write_key (iv) for encrypt or decrypt
				// so, we reset the counter
				ses.reclayer.reset_read_seq()
				ses.reclayer.reset_write_seq()

				ses.change_to_state(.application_data)
			}
			.application_data {
				log.info('Processing on state: ${ses.state()}...')
			}
			else {
				return error('unhandled message')
			}
		}
	}
}

// The main purposes of handle_server_hello is to parse ServerHello message.
fn (mut ses Session) handle_server_hello(sh ServerHello) ! {
	log.info('Performing ${@FN} ...')
	ae := Alert{
		level: .fatal
		desc: .illegal_parameter
	}
	// check for HelloRetryRequest
	if sh.is_hrr() {
		// ses.handle_retry_request()!
		// we currently does not support HelloRetryRequest
		ses.change_to_state(.closed)
		return tls_error(ae, 'ServerHello is HelloRetryRequest')
	}
	// Perform downgrade check
	// TLS 1.3 clients receiving a ServerHello indicating TLS 1.2 or below
	// MUST check that the last 8 bytes are not equal to either of these
	// values.  TLS 1.2 clients SHOULD also check that the last 8 bytes are
	// not equal to the second value if the ServerHello indicates TLS 1.1 or
	// below.  If a match is found, the client MUST abort the handshake with
	// an "illegal_parameter" alert
	last8 := sh.random[24..31]
	if hmac.equal(last8, tls12_random_magic) || hmac.equal(last8, tls12_random_magic) {
		ses.change_to_state(.closed)
		return tls_error(ae, 'Bad downgrade ServerHello.random detected')
	}

	// A client which receives a cipher suite that was not offered MUST abort the handshake
	if !ses.firstch.cipher_suites.is_exist(sh.cipher_suite) {
		ses.change_to_state(.closed)
		return tls_error(ae, "ClientHello.cipher_suites doesn't contains server cipher_suite")
	}

	// check for matching legacy_session_id
	// A client which receives a legacy_session_id_echo field that does not match what
	// it sent in the ClientHello MUST abort the handshake with an "illegal_parameter" alert
	if !hmac.equal(ses.firstch.legacy_session_id, sh.legacy_session_id_echo) {
		ses.change_to_state(.closed)
		return tls_error(ae, "Server and Client sessid doesn't match")
	}

	// If the "supported_versions" extension in the ServerHello contains a version not offered
	// by the client or contains a version prior to TLS 1.3, the client MUST abort
	// the handshake with an "illegal_parameter" alert.
	srv_spv := sh.extensions.filtered_exts_with_type(.supported_versions) // []Extension
	if srv_spv.len == 0 {
		ses.change_to_state(.closed)
		return tls_error(ae, 'ServerHello.extensions does not contains SupportedVersions extension')
	}
	if srv_spv.len > 1 {
		ses.change_to_state(.closed)
		return tls_error(ae, 'Server.extensions contains multiples SupportedVersions extension')
	}
	spv := srv_spv[0] // Extension with .supported_versions type
	spver := SupportedVersions.unpack(spv.data, .server_hello)! // SupportedVersions
	sh_spv := spver as ServerHRetrySpV // cast to Server SupportedVersions
	// we check and only support for tls_v13
	if sh_spv.version != tls_v13 {
		ses.change_to_state(.closed)
		return tls_error(ae, 'Server.extensions SupportedVersions does not contains tls v1.3')
	}

	// check for KeyShare
	srv_kse := sh.extensions.filtered_exts_with_type(.key_share) // []Extension
	if srv_kse.len == 0 {
		ses.change_to_state(.closed)
		return tls_error(ae, 'ServerHello.extensions does not contains KeyShare extension')
	}
	if srv_kse.len > 1 {
		ses.change_to_state(.closed)
		return tls_error(ae, 'Server.extensions contains multiples KeyShare extension')
	}
	kse0 := srv_kse[0] // Extension with .key_share type
	is_hrr := sh.is_hrr()
	kxe := KeyShareExtension.unpack_from_extension(kse0, .server_hello, is_hrr)!
	// check if keyshare.group matching with supported client
	if kxe.server_share.group != NamedGroup.x25519 {
		ses.change_to_state(.closed)
		return tls_error(ae, 'ServerHello.extensions KeyShare group does not matching with .x25519')
	}
}

fn (mut ses Session) handle_encrypted_extensions(ee EncryptedExtensions) ! {
	log.info('Performing ${@FN} ...')
}

fn (mut ses Session) handle_cert_request(cr CertificateRequest) ! {
	log.info('Performing ${@FN} ...')
}

fn (mut ses Session) handle_certificate(cert Certificate) ! {
	log.info('Performing ${@FN} ...')
}

fn (mut ses Session) handle_cert_verify(cv CertificateVerify) ! {
	log.info('Performing ${@FN} ...')
}

fn (mut ses Session) handle_server_finished(fin Finished) ! {
	log.info('Performing ${@FN} ...')
	// its does in .finished state
	assert ses.state() == .wait_finished
	// TODO: check server Finished.verify_data
}

fn (mut ses Session) say_hello_with_clienthello(ch ClientHello) ! {
	assert ses.state() == .start
	log.info('Performing ${@FN} ...')
	// TODD: do right thing for sending clienthello msg
	// msgs := ch.pack()!
	// build TLSPlaintext arrays
	// pxt_list := ses.reclayer.do_fragment(msgs, ContentType.handshake)!
	// we should only 1 packet here
	// assert pxt_list.len == 1
	// mut num := 0
	// mut pxt := pxt_list[0]
	// pxt.set_version(tls_v11)!
	// for p in pxt_list {
	//	obj := p.pack()!
	//	n := ses.write(obj)!
	//	num += n
	//}
	hsk := HandshakePayload(ch).pack_to_handshake()!
	pxt := TLSPlaintext.from_handshake(hsk)!
	obj := pxt.pack()!
	n := ses.write(obj)!
	assert n == pxt.packed_length()

	// append the first ClientHello to handshake context
	_ := ses.ks.append_hskmsg_and_update_hash(hsk)!

	// Calculates binder key and early traffic secret if supported
	// ses.ks.extern_bindkey = ses.ks.ext_binder_key(nullbytes)!
	// ses.ks.resump_bindkey = ses.ks.res_binder_key(nullbytes)!
	// ch_msg := HandshakePayload(ch).pack_to_handshake_bytes()!
	// ses.ks.client_easec = ses.ks.client_early_traffic_secret(nullbytes, ch_msg)!
	// ses.ks.export_easec = ses.ks.early_exporter_master_secret(nullbytes, ch_msg)!

	ses.change_to_state(.wait_sh)
}

fn (mut ses Session) say_first_hello() ! {
	ses.say_hello_with_clienthello(ses.firstch)!
}

fn (mut ses Session) send_endof_earlydata(ed EndOfEarlyData) !int {
	log.info('Performing ${@FN} ...')
	hsk := HandshakePayload(ed).pack_to_handshake()!
	ses.reclayer.reset_write_seq()
	n := ses.write_handshake(hsk, ses.ks.cln_hsk_wrkey, ses.ks.cln_hsk_wriv)!
	log.info('Sent ${n} EndOfEarlyData message...')
	return n
}

fn (ses Session) send_client_certificate() ! {
	log.info('Performing ${@FN} ...')
}

fn (ses Session) send_client_certificate_verify() ! {
	log.info('Performing ${@FN} ...')
}

fn (mut ses Session) send_client_finished(fin Finished) !int {
	log.info('Performing ${@FN} ...')
	hsk := HandshakePayload(fin).pack_to_handshake()!
	// this is first client message encrypted under key derived from
	// application_traffic_secret,
	// TODO: should we reset internal counter, because the spec says
	// Each sequence number is set to zero at the beginning of a connection and whenever the key is
	// changed; the first record transmitted under a particular traffic key
	// MUST use sequence number 0.
	// ses.reclayer.reset_write_seq()
	n := ses.write_handshake(hsk, ses.ks.cln_hsk_wrkey, ses.ks.cln_hsk_wriv)!
	log.info('Sent ${n} Finished message...')
	return n
}
