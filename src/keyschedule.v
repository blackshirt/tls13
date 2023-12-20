module tls13

import crypto
import blackshirt.hkdf

const empty_hsk_msgs = []Handshake{len: 0}

const nullbytes = []u8{len: 0, cap: 0}

const extern_binder_label = 'ext binder'

const resump_binder_label = 'res binder'

const client_early_label = 'c e traffic'

const early_exporter_label = 'e exp master'

const derived_label = 'derived'

const client_hsksecret_label = 'c hs traffic'

const server_hsksecret_label = 's hs traffic'

const client_appsecret_label = 'c ap traffic'

const server_appsecret_label = 's ap traffic'

const exporter_mastersec_label = 'exp master'

const resump_mastersec_label = 'res master'

const write_key_label = 'key'

const write_iv_label = 'iv'

const traffic_upd_label = 'traffic upd'

const finished_key_label = 'finished'

const resumption_label = 'resumption'

// RFC 8446 7.1.  Key Schedule
struct KeyScheduler {
	// underlying crypto.Hash
	hash crypto.Hash
	// hmac key derivation function based on provided hash
	kdf hkdf.Hkdf
mut:
	// hash transcripter
	tc &Transcripter = unsafe { nil }
	// Handshake messages arrays for context handling. its placed here
	// for simplifying transcript hash integration.
	hsx []Handshake
	// early_secret derived from psk bytes
	early_secret      []u8
	cln_early_tsecret []u8
	cln_early_wrkey   []u8
	cln_early_wriv    []u8
	extern_binderkey  []u8
	resump_binderkey  []u8
	// handshake_secret, derived from psk and ecdhe shared secret
	hsk_secret []u8
	// master_secret derived from above secret
	master_secret []u8
	// handshakes_traffic_secret, its stores here for simplicity,
	// its contains secret from derived_secret process of ClientHello...ServerHello messages
	srv_hsk_tsecret []u8
	cln_hsk_tsecret []u8
	// server client handshake_write_key an write_iv, derived from server/client handshakes_traffic_secret
	srv_hsk_wrkey []u8
	srv_hsk_wriv  []u8
	cln_hsk_wrkey []u8
	cln_hsk_wriv  []u8
	// application_traffic_secret
	srv_app_tsecret []u8
	cln_app_tsecret []u8
	// application write_key and write_iv
	srv_app_wrkey []u8
	srv_app_wriv  []u8
	cln_app_wrkey []u8
	cln_app_wriv  []u8
	// exporter_master_secret
	exp_master_sec []u8
	// resumption_master_secret
	resump_master_sec []u8
}

// new_key_scheduler creates new KeyScheduler
fn new_key_scheduler(h crypto.Hash) !&KeyScheduler {
	kd := &KeyScheduler{
		hash: h
		kdf: hkdf.new(h)
		tc: new_transcripter(h)!
	}
	return kd
}

// transcripter
fn (ks KeyScheduler) transcripter() &Transcripter {
	return ks.tc
}

fn (mut ks KeyScheduler) reset() {
	unsafe {
		// reset the state of the Transcripter
		ks.tc.reset()
		// we doing `array.clear()` instead `array.reset()`. clear clears the array without
		// deallocating the allocated data. It does it by setting the array length to 0
		// where `array.reset()` reset quickly sets the bytes of all elements of the array to 0
		// that can later lead to hard to find bugs.
		ks.hsx.clear()

		ks.early_secret.clear()
		ks.cln_early_tsecret.clear()
		ks.cln_early_wrkey.clear()
		ks.cln_early_wriv.clear()
		ks.extern_binderkey.clear()
		ks.resump_binderkey.clear()

		ks.hsk_secret.clear()
		ks.master_secret.clear()

		ks.srv_hsk_tsecret.clear()
		ks.cln_hsk_tsecret.clear()
		ks.srv_hsk_wrkey.clear()
		ks.srv_hsk_wriv.clear()
		ks.cln_hsk_wrkey.clear()
		ks.cln_hsk_wriv.clear()

		ks.srv_app_tsecret.clear()
		ks.cln_app_tsecret.clear()
		ks.srv_app_wrkey.clear()
		ks.srv_app_wriv.clear()
		ks.cln_app_wrkey.clear()
		ks.cln_app_wriv.clear()

		ks.exp_master_sec.clear()
		ks.resump_master_sec.clear()
	}
}

fn (mut ks KeyScheduler) free() {
	unsafe {
		// frees all memory occupied by the Transcripter
		ks.tc.free()
		ks.hsx.free()

		ks.early_secret.free()
		ks.cln_early_tsecret.free()
		ks.cln_early_wrkey.free()
		ks.cln_early_wriv.free()
		ks.extern_binderkey.free()
		ks.resump_binderkey.free()

		ks.hsk_secret.free()
		ks.master_secret.free()

		ks.srv_hsk_tsecret.free()
		ks.cln_hsk_tsecret.free()
		ks.srv_hsk_wrkey.free()
		ks.srv_hsk_wriv.free()
		ks.cln_hsk_wrkey.free()
		ks.cln_hsk_wriv.free()

		ks.srv_app_tsecret.free()
		ks.cln_app_tsecret.free()
		ks.srv_app_wrkey.free()
		ks.srv_app_wriv.free()
		ks.cln_app_wrkey.free()
		ks.cln_app_wriv.free()

		ks.exp_master_sec.free()
		ks.resump_master_sec.free()
	}
}

// update_hash_with_handshake updates internal state of hash with handshake message
fn (mut ks KeyScheduler) update_hash_with_handshake(h Handshake) !int {
	msg := h.pack()!
	return ks.update_hash_with_bytes(msg)!
}

fn (mut ks KeyScheduler) current_hash() []u8 {
	out := ks.tc.sum([]u8{})
	return out
}

// update_hash_with_bytes updates internal state of hash with bytes
fn (mut ks KeyScheduler) update_hash_with_bytes(b []u8) !int {
	n := ks.tc.write(b)!
	assert n == b.len
	return n
}

fn (mut ks KeyScheduler) append_hskmsg_and_update_hash(h Handshake) !int {
	ks.hsx.append_msg(h)!
	return ks.update_hash_with_handshake(h)!
}

// expand_label is defined as :
// HKDF-Expand-Label(Secret, Label, Context, Length) =
//      HKDF-Expand(Secret, HkdfLabel, Length)
//
fn (ks KeyScheduler) expand_label(secret []u8, label string, context []u8, length int) ![]u8 {
	kdf_lbl := new_hkdf_label(label, context, length)!
	info := kdf_lbl.encode()!
	out := ks.kdf.expand(secret, info, length)!
	return out
}

// derive_secret is defined as Derive-Secret(Secret, Label, Messages)
//				= HKDF-Expand-Label(Secret, Label,  Transcript-Hash(Messages), Hash.length)
fn (mut ks KeyScheduler) derive_secret(secret []u8, label string, messages []Handshake) ![]u8 {
	// TODO: should we use internal `ks.Transcripter` ?
	// if yes, is it affects hash results?
	hashed_msg := ks.transcript_hash(messages)!
	out := ks.expand_label(secret, label, hashed_msg, ks.kdf.size()!)!
	return out
}

fn (mut ks KeyScheduler) transcript_hash(messages []Handshake) ![]u8 {
	mut tc := new_transcripter(ks.hash)!
	defer {
		tc.free()
	}
	msgs := messages.pack_handshakes_msg(ks.hash)!
	n := tc.write(msgs)!
	assert n == msgs.len
	// todo: use .sum() instead
	out := tc.sum(tls13.nullbytes)
	return out
}

// Early Secret handling,
// if we support psk mode, supply it with psk_bytes, otherwise its a nullbytes
//
// PSK ->  HKDF-Extract = Early Secret
//             |
//             +-----> Derive-Secret(., "ext binder" | "res binder", "")
//             |                     = binder_key
//             |
//             +-----> Derive-Secret(., "c e traffic", ClientHello)
//             |                     = client_early_traffic_secret
//             |
//             +-----> Derive-Secret(., "e exp master", ClientHello)
//             |                     = early_exporter_master_secret
//             v
//       Derive-Secret(., "derived", "")
//
fn (mut ks KeyScheduler) early_secret(psk_bytes []u8) ![]u8 {
	if ks.early_secret.len == 0 {
		ks.early_secret = ks.kdf.extract(tls13.nullbytes, psk_bytes)!
	}
	return ks.early_secret
}

fn (mut ks KeyScheduler) ext_binder_key(early_secret []u8) ![]u8 {
	if ks.extern_binderkey.len == 0 {
		ks.extern_binderkey
		ks.derive_secret(early_secret, tls13.extern_binder_label, tls13.empty_hsk_msgs)!
	}

	return ks.extern_binderkey
}

fn (mut ks KeyScheduler) resump_binder_key(early_secret []u8) ![]u8 {
	if ks.resump_binderkey.len == 0 {
		ks.resump_binderkey = ks.derive_secret(early_secret, tls13.resump_binder_label,
			tls13.empty_hsk_msgs)!
	}
	return ks.resump_binderkey
}

// +-----> Derive-Secret(., "c e traffic", ClientHello) = client_early_traffic_secret
fn (mut ks KeyScheduler) client_early_traffic_secret(early_secret []u8, ch ClientHello) ![]u8 {
	hsk := HandshakePayload(ch).pack_to_handshake()!
	if ks.cln_early_tsecret.len == 0 {
		ks.cln_early_tsecret = ks.derive_secret(early_secret, tls13.client_early_label,
			[hsk])!
	}
	return ks.cln_early_tsecret
}

// +-----> Derive-Secret(., "e exp master", ClientHello) = early_exporter_master_secret
fn (mut ks KeyScheduler) early_exporter_master_secret(early_secret []u8, ch ClientHello) ![]u8 {
	hsk := HandshakePayload(ch).pack_to_handshake()!
	early_exporter_ms := ks.derive_secret(early_secret, tls13.early_exporter_label, [
		hsk,
	])!
	return early_exporter_ms
}

// Handshake Secret keys handling
// its accepts psk_bytes if we support psk mode, or shared secret in the form of
// ecdhe_bytes of key exchange mechanism.
//
// Derive-Secret(., "derived", "")
//             |
//             v
//   (EC)DHE -> HKDF-Extract = Handshake Secret
//             |
//             +-----> Derive-Secret(., "c hs traffic",
//             |                     ClientHello...ServerHello)
//             |                     = client_handshake_traffic_secret
//             |
//             +-----> Derive-Secret(., "s hs traffic",
//             |                     ClientHello...ServerHello)
//             |                     = server_handshake_traffic_secret
//             v
//       Derive-Secret(., "derived", "")
fn (mut ks KeyScheduler) handshake_secret(early_secret []u8, ecdhe_bytes []u8) ![]u8 {
	if ks.hsk_secret.len == 0 {
		derived_sec := ks.derive_secret(early_secret, tls13.derived_label, tls13.empty_hsk_msgs)!
		ks.hsk_secret = ks.kdf.extract(derived_sec, ecdhe_bytes)!
	}
	return ks.hsk_secret
}

// -> Derive-Secret(., "c hs traffic", ClientHello...ServerHello) = client_handshake_traffic_secret
fn (mut ks KeyScheduler) client_handshake_traffic_secret(hsk_secret []u8, hello_ctx HelloContext) ![]u8 {
	// TODO: validate HskContext, add support for HRR
	if ks.cln_hsk_tsecret.len == 0 {
		ks.cln_hsk_tsecret = ks.derive_secret(hsk_secret, tls13.client_hsksecret_label,
			hello_ctx)!
	}
	return ks.cln_hsk_tsecret
}

// +-----> Derive-Secret(., "s hs traffic", ClientHello...ServerHello) = server_handshake_traffic_secret
fn (mut ks KeyScheduler) server_handshake_traffic_secret(hsk_secret []u8, hello_ctx HelloContext) ![]u8 {
	if ks.srv_hsk_tsecret.len == 0 {
		ks.srv_hsk_tsecret = ks.derive_secret(hsk_secret, tls13.server_hsksecret_label,
			hello_ctx)!
	}
	return ks.srv_hsk_tsecret
}

// Master Secret key handling
//  Derive-Secret(., "derived", "")
//             |
//             v
//   0 -> HKDF-Extract = Master Secret
//             |
//             +-----> Derive-Secret(., "c ap traffic",
//             |                     ClientHello...server Finished)
//             |                     = client_application_traffic_secret_0
//             |
//             +-----> Derive-Secret(., "s ap traffic",
//             |                     ClientHello...server Finished)
//             |                     = server_application_traffic_secret_0
//             |
//             +-----> Derive-Secret(., "exp master",
//             |                     ClientHello...server Finished)
//             |                     = exporter_master_secret
//             |
//             +-----> Derive-Secret(., "res master",
//                                   ClientHello...client Finished)
//                                   = resumption_master_secret
//
fn (mut ks KeyScheduler) master_secret(hsk_secret []u8) ![]u8 {
	if ks.master_secret.len == 0 {
		drv_secret := ks.derive_secret(hsk_secret, tls13.derived_label, tls13.empty_hsk_msgs)!
		ks.master_secret = ks.kdf.extract(drv_secret, tls13.nullbytes)!
	}
	return ks.master_secret
}

// +-----> Derive-Secret(., "s ap traffic", ClientHello...server Finished) = server_application_traffic_secret_0
fn (mut ks KeyScheduler) server_application_traffic_secret_0(master_secret []u8, hsk_ctx []Handshake) ![]u8 {
	if ks.srv_app_tsecret.len == 0 {
		ks.srv_app_tsecret = ks.derive_secret(master_secret, tls13.server_appsecret_label,
			hsk_ctx)!
	}
	return ks.srv_app_tsecret
}

// +-----> Derive-Secret(., "c ap traffic",  ClientHello...server Finished) = client_application_traffic_secret_0
fn (mut ks KeyScheduler) client_application_traffic_secret_0(master_secret []u8, hsk_ctx []Handshake) ![]u8 {
	if ks.cln_app_tsecret.len == 0 {
		ks.cln_app_tsecret = ks.derive_secret(master_secret, tls13.client_appsecret_label,
			hsk_ctx)!
	}
	return ks.cln_app_tsecret
}

// +-----> Derive-Secret(., "exp master", ClientHello...server Finished) = exporter_master_secret
fn (mut ks KeyScheduler) exporter_master_secret(master_secret []u8, hsk_ctx []Handshake) ![]u8 {
	if ks.exp_master_sec.len == 0 {
		ks.exp_master_sec = ks.derive_secret(master_secret, tls13.exporter_mastersec_label,
			hsk_ctx)!
	}
	return ks.exp_master_sec
}

// +-----> Derive-Secret(., "res master", ClientHello...client Finished) = resumption_master_secret
fn (mut ks KeyScheduler) resumption_master_secret(master_secret []u8, hsk_ctx []Handshake) ![]u8 {
	if ks.resump_master_sec.len == 0 {
		ks.resump_master_sec = ks.derive_secret(master_secret, tls13.resump_mastersec_label,
			hsk_ctx)!
	}
	return ks.resump_master_sec
}

// 7.2.  Updating Traffic Secrets
// The next-generation application_traffic_secret is computed as:
//       application_traffic_secret_N+1 =
//           HKDF-Expand-Label(application_traffic_secret_N,
//                             "traffic upd", "", Hash.length)
fn (mut ks KeyScheduler) next_traffic_secret(traffic_secret []u8) ![]u8 {
	secret := ks.expand_label(traffic_secret, tls13.traffic_upd_label, tls13.nullbytes,
		ks.kdf.size()!)!
	return secret
}

// 7.3.  Traffic Key Calculation
// [sender]_write_key = HKDF-Expand-Label(Secret, "key", "", key_length)
// [sender]_write_iv  = HKDF-Expand-Label(Secret, "iv", "", iv_length)

//  [sender] denotes the sending side.  The value of Secret for each
//  record type is shown in the table below.

//     +-------------------+---------------------------------------+
//     | Record Type       | Secret                                |
//     +-------------------+---------------------------------------+
//     | 0-RTT Application | client_early_traffic_secret           |
//     |                   |                                       |
//     | Handshake         | [sender]_handshake_traffic_secret     |
//     |                   |                                       |
//     | Application Data  | [sender]_application_traffic_secret_N |

// Client Early 0-RTT
//
fn (mut ks KeyScheduler) client_early_write_key(cln_early_tsecret []u8, key_length int) ![]u8 {
	if ks.cln_early_wrkey.len == 0 {
		ks.cln_early_wrkey = ks.expand_label(cln_early_tsecret, tls13.write_key_label,
			tls13.nullbytes, key_length)!
	}
	return ks.cln_early_wrkey
}

fn (mut ks KeyScheduler) client_early_write_iv(cln_early_tsecret []u8, iv_length int) ![]u8 {
	if ks.cln_early_wriv.len == 0 {
		ks.cln_early_wriv = ks.expand_label(cln_early_tsecret, tls13.write_key_label,
			tls13.nullbytes, iv_length)!
	}
	return ks.cln_early_wriv
}

// Handshake Record
//
fn (mut ks KeyScheduler) server_handshake_write_key(server_hsk_tsecret []u8, key_length int) ![]u8 {
	if ks.srv_hsk_wrkey.len == 0 {
		ks.srv_hsk_wrkey = ks.expand_label(server_hsk_tsecret, tls13.write_key_label,
			tls13.nullbytes, key_length)!
	}
	return ks.srv_hsk_wrkey
}

fn (mut ks KeyScheduler) server_handshake_write_iv(server_hsk_tsecret []u8, iv_length int) ![]u8 {
	if ks.srv_hsk_wriv.len == 0 {
		ks.srv_hsk_wriv = ks.expand_label(server_hsk_tsecret, tls13.write_iv_label, tls13.nullbytes,
			iv_length)!
	}
	return ks.srv_hsk_wriv
}

fn (mut ks KeyScheduler) client_handshake_write_key(client_hsk_tsecret []u8, key_length int) ![]u8 {
	if ks.cln_hsk_wrkey.len == 0 {
		ks.cln_hsk_wrkey = ks.expand_label(client_hsk_tsecret, tls13.write_key_label,
			tls13.nullbytes, key_length)!
	}
	return ks.cln_hsk_wrkey
}

fn (mut ks KeyScheduler) client_handshake_write_iv(client_hsk_tsecret []u8, length int) ![]u8 {
	if ks.cln_hsk_wriv.len == 0 {
		ks.cln_hsk_wriv = ks.expand_label(client_hsk_tsecret, tls13.write_iv_label, tls13.nullbytes,
			length)!
	}
	return ks.cln_hsk_wriv
}

// server
// srv_app_tsecret := server_application_traffic_secret_0(master_secret []u8, hsk_ctx []Handshake)!
fn (mut ks KeyScheduler) server_application_write_key(srv_app_tsecret []u8, key_length int) ![]u8 {
	if ks.srv_app_wrkey.len == 0 {
		ks.srv_app_wrkey = ks.expand_label(srv_app_tsecret, tls13.write_key_label, tls13.nullbytes,
			key_length)!
	}
	return ks.srv_app_wrkey
}

// server_application_traffic_secret_0(master_secret []u8, hsk_ctx []Handshake)
fn (mut ks KeyScheduler) server_application_write_iv(srv_app_tsecret []u8, iv_length int) ![]u8 {
	if ks.srv_app_wriv.len == 0 {
		ks.srv_app_wriv = ks.expand_label(srv_app_tsecret, tls13.write_iv_label, tls13.nullbytes,
			iv_length)!
	}

	return ks.srv_app_wriv
}

// client
// client_application_traffic_secret_0(master_secret []u8, hsk_ctx []Handshake8)
fn (mut ks KeyScheduler) client_application_write_key(cln_app_tsecret []u8, key_length int) ![]u8 {
	if ks.cln_app_wrkey.len == 0 {
		ks.cln_app_wrkey = ks.expand_label(cln_app_tsecret, tls13.write_key_label, tls13.nullbytes,
			key_length)!
	}
	return ks.cln_app_wrkey
}

fn (mut ks KeyScheduler) client_application_write_iv(cln_app_tsecret []u8, iv_length int) ![]u8 {
	// FIXME: client_application_traffic_secret_0 should client_application_traffic_secret_n?
	if ks.cln_app_wriv.len == 0 {
		ks.cln_app_wriv = ks.expand_label(cln_app_tsecret, tls13.write_iv_label, tls13.nullbytes,
			iv_length)!
	}
	return ks.cln_app_wriv
}

// finished_key =  HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.4
// finished_key = HKDF-Expand-Label(key: server_secret, label: "finished", ctx: "", len: 48)
fn (mut ks KeyScheduler) finished_key(base_key []u8) ![]u8 {
	finkey := ks.expand_label(base_key, tls13.finished_key_label, tls13.nullbytes, ks.kdf.size()!)!
	return finkey
}

// server_handshake_traffic_secret(hsk_secret []u8, []Handshake)
fn (mut ks KeyScheduler) server_finished_key(srv_hsk_tsecret []u8) ![]u8 {
	server_finkey := ks.expand_label(srv_hsk_tsecret, tls13.finished_key_label, tls13.nullbytes,
		ks.kdf.size()!)!

	return server_finkey
}

fn (mut ks KeyScheduler) client_finished_key(cln_hsk_tsecret []u8) ![]u8 {
	client_finkey := ks.expand_label(cln_hsk_tsecret, tls13.finished_key_label, tls13.nullbytes,
		ks.kdf.size()!)!

	return client_finkey
}

//  verify_data = HMAC(finished_key, Transcript-Hash(Handshake Context, Certificate*, CertificateVerify*))
// FIXME:
// finkey handshake is not included cert and cert_verify

// finished_hash = SHA384(Client Hello ... Server Cert Verify)
// verify_data = HMAC-SHA384(key: finished_key, msg: finished_hash)
// fn verify_data(kd hkdf.Hkdf, )
// for server finished verify data, ClientHello .. server CertificateVerify msg
// for client finished verify_data, ClientHello .. server Finished msg
fn (mut ks KeyScheduler) verify_data(finkey []u8, hsk_ctx []Handshake) ![]u8 {
	// where verify_data take all handshake message to cert_verify if found
	hashed := ks.transcript_hash(hsk_ctx)!
	// fn (k Hkdf) hmac(key []u8, data []u8) ![]u8
	verify_data := ks.kdf.hmac(finkey, hashed)!

	return verify_data
}

// The PSK associated with the ticket is computed as:
// HKDF-Expand-Label(resumption_master_secret, "resumption", ticket_nonce, Hash.length)
// resumption_master_secret = Derive-Secret(., "res master", ClientHello...client Finished)
// messages := ClientHello .. client Finished
// ticket_nonce = HkdfLabel.context
// resump_msec := ks.resumption_master_secret(psk_bytes, ecdhe_bytes, messages)!
fn (mut ks KeyScheduler) generate_tls13_resumption(resump_msec []u8, ticket_nonce []u8, length int) ![]u8 {
	// todo: fix messages handling
	secret := ks.expand_label(resump_msec, tls13.resumption_label, ticket_nonce, length)!
	return secret
}
