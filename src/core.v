// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Some core of TLS 1.3 opaque definition
module tls13

// TLS 1.3 Version
// TLS 1.3 ProtocolVersion;
//
// The rfc8446 document describes TLS 1.3, which uses the version 0x0304.
// This version value is historical, deriving from the use of 0x0301 for TLS 1.0 and 0x0300 for SSL 3.0.
// In order to maximize backward compatibility, a record containing an initial ClientHello SHOULD have
// version 0x0301 (reflecting TLS 1.0) and a record containing a second
// ClientHello or a ServerHello MUST have version 0x0303 (reflecting TLS 1.2).
enum Version as u16 {
	v13 = 0x0304 // TLS 1.3
	v12 = 0x0303 // TLS 1.2
	v11 = 0x0302 // TLS 1.1
	v10 = 0x0301 // TLS 1.0
	v00 = 0x0300 // SSL 3.0, predecessor of TLS
}

// str represents TLS version as a common name string
fn (v Version) str() string {
	match v {
		.v13 { return 'TLS 1.3' }
		.v12 { return 'TLS 1.2' }
		.v11 { return 'TLS 1.1' }
		.v10 { return 'TLS 1.0' }
		.v00 { return 'SSL 3.0' } // TLS 0.0
	}
}

// new_version creates TLS version from u16 value
@[inline]
fn new_version(val u16) !Version {
	match val {
		// vfmt off
		u16(0x0300) { return .v00 }
		u16(0x0301) { return .v10 }
		u16(0x0302) { return .v11 }
		u16(0x0303) { return .v12 }
		u16(0x0304) { return .v13 }
		else {
			return error('unsupported Version value')
		}
		// vfmt on
	}
}

// ContentType is content type of TLS 1.3 record defined as an u8 value
//
enum ContentType as u8 {
	invalid            = 0
	change_cipher_spec = 20
	alert              = 21
	handshake          = 22
	application_data   = 23
	heartbeat          = 24
}

// new_ctntype creates a new ContentType from byte value.
@[inline]
fn new_ctntype(val u8) !ContentType {
	match val {
		// vfmt off
		20 { return .change_cipher_spec }
		21 { return .alert }
		22 { return .handshake }
		23 { return .application_data }
		24 { return .heartbeat }
		0  { return .invalid }
		// otherwise, return as is or an error ?
		else {
			return error('unsupported ContentType value')
		}
		// vfmt on
	}
}

// string representation of ContentType c
fn (c ContentType) str() string {
	match c {
		.invalid { return 'INVALID' }
		.change_cipher_spec { return 'CHANGE_CIPHER_SPEC' }
		.alert { return 'ALERT' }
		.handshake { return 'HANDSHAKE' }
		.application_data { return 'APPLICATION_DATA' }
		.heartbeat { return 'HEARTBEAT' }
	}
}

// B.2.  Alert Messages
//
// enum { warning(1), fatal(2), (255) } AlertLevel;
enum AlertLevel as u8 {
	warning = 0x01
	fatal   = 0x02
	// 255
}

@[inline]
fn new_alert(val u8) !AlertLevel {
	match val {
		0x01 { return .warning }
		0x02 { return .fatal }
		else { return error('unsupported alert level') }
	}
}

@[inline]
fn (al AlertLevel) str() string {
	match al {
		.warning { return 'WARNING' }
		.fatal { return 'FATAL' }
	}
}

// TLS 1.3 AlertDescription
//
enum AlertDescription as u8 {
	close_notify                    = 0
	unexpected_message              = 10
	bad_record_mac                  = 20
	decryption_failed               = 21 // _RESERVED
	record_overflow                 = 22
	decompression_failure           = 30 // _RESERVED
	handshake_failure               = 40
	no_certificate                  = 41 // RESERVED
	bad_certificate                 = 42
	unsupported_certificate         = 43
	certificate_revoked             = 44
	certificate_expired             = 45
	certificate_unknown             = 46
	illegal_parameter               = 47
	unknown_ca                      = 48
	access_denied                   = 49
	decode_error                    = 50
	decrypt_error                   = 51
	export_restriction              = 60 //_RESERVED
	protocol_version                = 70
	insufficient_security           = 71
	internal_error                  = 80
	inappropriate_fallback          = 86
	user_canceled                   = 90
	no_renegotiation                = 100 //_RESERVED
	missing_extension               = 109
	unsupported_extension           = 110
	certificate_unobtainable        = 111 //_RESERVED
	unrecognized_name               = 112
	bad_certificate_status_response = 113
	bad_certificate_hash_value      = 114 //_RESERVED
	unknown_psk_identity            = 115
	certificate_required            = 116
	no_application_protocol         = 120
}

@[inline]
fn new_alertdesc(val u8) !AlertDescription {
	match val {
		0 { return .close_notify }
		10 { return .unexpected_message }
		20 { return .bad_record_mac }
		21 { return .decryption_failed } // _RESERVED
		22 { return .record_overflow }
		30 { return .decompression_failure } // _RESERVED
		40 { return .handshake_failure }
		41 { return .no_certificate } // RESERVED
		42 { return .bad_certificate }
		43 { return .unsupported_certificate }
		44 { return .certificate_revoked }
		45 { return .certificate_expired }
		46 { return .certificate_unknown }
		47 { return .illegal_parameter }
		48 { return .unknown_ca }
		49 { return .access_denied }
		50 { return .decode_error }
		51 { return .decrypt_error }
		60 { return .export_restriction } //_RESERVED
		70 { return .protocol_version }
		71 { return .insufficient_security }
		80 { return .internal_error }
		86 { return .inappropriate_fallback }
		90 { return .user_canceled }
		100 { return .no_renegotiation } //_RESERVED
		109 { return .missing_extension }
		110 { return .unsupported_extension }
		111 { return .certificate_unobtainable } //_RESERVED
		112 { return .unrecognized_name }
		113 { return .bad_certificate_status_response }
		114 { return .bad_certificate_hash_value } //_RESERVED
		115 { return .unknown_psk_identity }
		116 { return .certificate_required }
		120 { return .no_application_protocol }
		else { return error('unsupported AlertDescription value') }
	}
}

// HandshakeType is a TLS 1.3 handshake type defined as an u8 value
//
enum HandshakeType as u8 {
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

// new_hsktype creates HandshakeType from byte value
@[inline]
fn new_hsktype(val u8) !HandshakeType {
	match val {
		// vfmt off
		0x00 { return .hello_request }
		0x01 { return .client_hello }
		0x02 { return .server_hello }
		0x03 { return .hello_verify_request }
		0x04 { return .new_session_ticket }
		0x05 { return .end_of_early_data }
		0x06 { return .hello_retry_request }
		0x08 { return .encrypted_extensions }
		0x0b { return .certificate }
		0x0c { return .server_key_exchange }
		0x0d { return .certificate_request }
		0x0e { return .server_hello_done }
		0x0f { return .certificate_verify }
		0x10 { return .client_key_exchange }
		0x14 { return .finished }
		0x15 { return .certificate_url }
		0x16 { return .certificate_status }
		0x17 { return .supplemental_data }
		0x18 { return .key_update }
		0xfe { return .message_hash }
		else {
			return error('unsupported value for HandshakeType')
		}
		// vfmt on
	}
}

// NameType = u8
enum NameType as u8 {
	host_name    = 0x00
	unknown_name = 0xff
	// .. (255)
}

// new_nametype creates a new NameType from byte value.
@[inline]
fn new_nametype(val u8) !NameType {
	match val {
		0x00 { return .host_name }
		0xff { return .unknown_name }
		else { return error('unsupported NameType value') }
	}
}

// ExtensionType is the type of TLS 1.3 Extension, as u16 value
//
enum ExtensionType as u16 {
	server_name                           = 0
	max_fragment_length                   = 1
	client_certificate_url                = 2
	trusted_ca_keys                       = 3
	truncated_hmac                        = 4
	status_request                        = 5
	user_mapping                          = 6
	client_authz                          = 7
	server_authz                          = 8
	cert_type                             = 9
	supported_groups                      = 10
	ec_point_formats                      = 11
	srp                                   = 12
	signature_algorithms                  = 13
	use_srtp                              = 14
	heartbeat                             = 15
	apln                                  = 16
	status_request_v2                     = 17
	signed_certificate_timestamp          = 18
	client_certificate_type               = 19
	server_certificate_type               = 20
	padding                               = 21
	encrypt_then_mac                      = 22
	extended_master_secret                = 23
	token_binding                         = 24
	cached_info                           = 25
	tls_lts                               = 26
	compress_certificate                  = 27
	record_size_limit                     = 28
	pwd_protect                           = 29
	pwd_clear                             = 30
	password_salt                         = 31
	ticket_pinning                        = 32
	tls_cert_with_extern_psk              = 33
	delegated_credential                  = 34
	session_ticket                        = 35
	tlmsp                                 = 36
	tlmsp_proxying                        = 37
	tlmsp_delegate                        = 38
	supported_ekt_ciphers                 = 39
	reserved_40                           = 40 // Used but never assigned
	pre_shared_key                        = 41
	early_data                            = 42
	supported_versions                    = 43
	cookie                                = 44
	psk_key_exchange_modes                = 45
	reserved_46                           = 46 // Used but never assigned
	certificate_authorities               = 47
	oid_filters                           = 48
	post_handshake_auth                   = 49
	signature_algorithms_cert             = 50
	key_share                             = 51
	transparency_info                     = 52
	connection_id_deprecated              = 53 // deprecated
	connection_id                         = 54
	external_id_hash                      = 55
	external_session_id                   = 56
	quic_transport_parameters             = 57
	ticket_request                        = 58
	dnssec_chain                          = 59
	sequence_number_encryption_algorithms = 60
	reserved_for_private_use              = 65280
	renegotiation_info                    = 65281
	unassigned                            = 0xff
}

// new_exttype creates a new ExtensionType from u16 value
@[inline]
fn new_exttype(val u16) !ExtensionType {
	match val {
		// vfmt off
		0 { return .server_name }
		1 { return .max_fragment_length }
		2 { return .client_certificate_url }
		3 { return .trusted_ca_keys }
		4 { return .truncated_hmac }
		5 { return .status_request }
		6 { return .user_mapping }
		7 { return .client_authz }
		8 { return .server_authz }
		9 { return .cert_type }
		10 { return .supported_groups }
		11 { return .ec_point_formats }
		12 { return .srp }
		13 { return .signature_algorithms }
		14 { return .use_srtp }
		15 { return .heartbeat }
		16 { return .apln }
		17 { return .status_request_v2 }
		18 { return .signed_certificate_timestamp }
		19 { return .client_certificate_type }
		20 { return .server_certificate_type }
		21 { return .padding }
		22 { return .encrypt_then_mac }
		23 { return .extended_master_secret }
		24 { return .token_binding }
		25 { return .cached_info }
		26 { return .tls_lts }
		27 { return .compress_certificate }
		28 { return .record_size_limit }
		29 { return .pwd_protect }
		30 { return .pwd_clear }
		31 { return .password_salt }
		32 { return .ticket_pinning }
		33 { return .tls_cert_with_extern_psk }
		34 { return .delegated_credential }
		35 { return .session_ticket }
		36 { return .tlmsp }
		37 { return .tlmsp_proxying }
		38 { return .tlmsp_delegate }
		39 { return .supported_ekt_ciphers }
		40 { return .reserved_40 } // Used but never assigned
		41 { return .pre_shared_key }
		42 { return .early_data }
		43 { return .supported_versions }
		44 { return .cookie }
		45 { return .psk_key_exchange_modes }
		46 { return .reserved_46 } // Used but never assigned
		47 { return .certificate_authorities }
		48 { return .oid_filters }
		49 { return .post_handshake_auth }
		50 { return .signature_algorithms_cert }
		51 { return .key_share }
		52 { return .transparency_info }
		53 { return .connection_id_deprecated } // deprecated
		54 { return .connection_id }
		55 { return .external_id_hash }
		56 { return .external_session_id }
		57 { return .quic_transport_parameters }
		58 { return .ticket_request }
		59 { return .dnssec_chain }
		60 { return .sequence_number_encryption_algorithms }
		65280 { return .reserved_for_private_use }
		65281 { return .renegotiation_info }
		0xff { return .unassigned }
		else {
			return error('unsupported ExtensionType value')
		}
		// vfmt on
	}
}

// SignatureScheme is a TLS 1.3 Signature sce value, defined as u16 value
//
enum SignatureScheme as u16 {
	rsa_pkcs1_sha256       = 0x0401
	rsa_pkcs1_sha384       = 0x0501
	rsa_pkcs1_sha512       = 0x0601
	ecdsa_secp256r1_sha256 = 0x0403
	ecdsa_secp384r1_sha384 = 0x0503
	ecdsa_secp521r1_sha512 = 0x0603
	rsa_pssrsae_sha256     = 0x0804
	rsa_pssrsae_sha384     = 0x0805
	rsa_pssrsae_sha512     = 0x0806
	ed25519                = 0x0807
	ed448                  = 0x0808
	rsa_psspss_sha256      = 0x0809
	rsa_psspss_sha384      = 0x080a
	rsa_psspss_sha512      = 0x080b
	rsa_pkcs1_sha1         = 0x0201
	ecdsa_sha1             = 0x0203
}

// new_sigscheme creates SignatureScheme from u16 value
@[inline]
fn new_sigscheme(val u16) !SignatureScheme {
	match val {
		0x0401 {
			return .rsa_pkcs1_sha256
		}
		0x0501 {
			return .rsa_pkcs1_sha384
		}
		0x0601 {
			return .rsa_pkcs1_sha512
		}
		0x0403 {
			return .ecdsa_secp256r1_sha256
		}
		0x0503 {
			return .ecdsa_secp384r1_sha384
		}
		0x0603 {
			return .ecdsa_secp521r1_sha512
		}
		0x0804 {
			return .rsa_pssrsae_sha256
		}
		0x0805 {
			return .rsa_pssrsae_sha384
		}
		0x0806 {
			return .rsa_pssrsae_sha512
		}
		0x0807 {
			return .ed25519
		}
		0x0808 {
			return .ed448
		}
		0x0809 {
			return .rsa_psspss_sha256
		}
		0x080a {
			return .rsa_psspss_sha384
		}
		0x080b {
			return .rsa_psspss_sha512
		}
		0x0201 {
			return .rsa_pkcs1_sha1
		}
		0x0203 {
			return .ecdsa_sha1
		}
		else {
			return error('unsupported SignatureScheme value')
		}
	}
}

// str returns string representation of SignatureScheme s.
fn (s SignatureScheme) str() string {
	match s {
		.rsa_pkcs1_sha256 { return 'RSA_PKCS1_SHA256' }
		.rsa_pkcs1_sha384 { return 'RSA_PKCS1_SHA384' }
		.rsa_pkcs1_sha512 { return 'RSA_PKCS1_SHA512' }
		.ecdsa_secp256r1_sha256 { return 'ECDSA_SECP256R1_SHA256' }
		.ecdsa_secp384r1_sha384 { return 'ECDSA_SECP384R1_SHA384' }
		.ecdsa_secp521r1_sha512 { return 'ECDSA_SECP521R1_SHA512' }
		.rsa_pssrsae_sha256 { return 'RSA_PSSRSAE_SHA256' }
		.rsa_pssrsae_sha384 { return 'RSA_PSSRSAE_SHA384' }
		.rsa_pssrsae_sha512 { return 'RSA_PSSRSAE_SHA512' }
		.ed25519 { return 'ED25519' }
		.ed448 { return 'ED448' }
		.rsa_psspss_sha256 { return 'RSA_PSSPSS_SHA256' }
		.rsa_psspss_sha384 { return 'RSA_PSSPSS_SHA384' }
		.rsa_psspss_sha512 { return 'RSA_PSSPSS_SHA512' }
		.rsa_pkcs1_sha1 { return 'RSA_PKCS1_SHA1' }
		.ecdsa_sha1 { return 'ECDSA_SHA1' }
	}
}

// TLS 1.3 NamedGroup
//
enum NamedGroup as u16 {
	secp256r1 = 0x0017
	secp384r1 = 0x0018
	secp521r1 = 0x0019
	x25519    = 0x001D
	x448      = 0x001E
	ffdhe2048 = 0x0100
	ffdhe3072 = 0x0101
	ffdhe4096 = 0x0102
	ffdhe6144 = 0x0103
	ffdhe8192 = 0x0104
}

@[inline]
fn new_group(val u16) !NamedGroup {
	match val {
		0x0017 { return .secp256r1 }
		0x0018 { return .secp384r1 }
		0x0019 { return .secp521r1 }
		0x001D { return .x25519 }
		0x001E { return .x448 }
		0x0100 { return .ffdhe2048 }
		0x0101 { return .ffdhe3072 }
		0x0102 { return .ffdhe4096 }
		0x0103 { return .ffdhe6144 }
		0x0104 { return .ffdhe8192 }
		else { return error('unknown NamedGroup value') }
	}
}

// TLS 1.3 CipherSuite
//
enum CipherSuite as u16 {
	tls_aes128gcm_sha256            = 0x1301
	tls_aes256gcm_sha384            = 0x1302
	tls_chacha20poly1305_sha256     = 0x1303
	tls_aes128ccm_sha256            = 0x1304
	tls_aes128ccm8_sha256           = 0x1305
	tls_emptyrenegotiationinfo_scsv = 0x00ff
}

// new_csuite creates CipherSuite from u16 value
@[inline]
fn new_csuite(v u16) !CipherSuite {
	match v {
		0x1301 { return .tls_aes128gcm_sha256 }
		0x1302 { return .tls_aes256gcm_sha384 }
		0x1303 { return .tls_chacha20poly1305_sha256 }
		0x1304 { return .tls_aes128ccm_sha256 }
		0x1305 { return .tls_aes128ccm8_sha256 }
		0x00ff { return .tls_emptyrenegotiationinfo_scsv }
		else { return error('unsupported ciphersuite value') }
	}
}

// str returns string representation of CipherSuite c
fn (c CipherSuite) str() string {
	match c {
		.tls_aes128gcm_sha256 {
			return 'TLS_AES128GCM_SHA256'
		}
		.tls_aes256gcm_sha384 {
			return 'TLS_AES256GCM_SHA384'
		}
		.tls_chacha20poly1305_sha256 {
			return ''
			TLS_CHACHA20POLY1305_SHA256
		}
		.tls_aes128ccm_sha256 {
			return 'TLS_AES128CCM_SHA256'
		}
		.tls_aes128ccm8_sha256 {
			return 'TLS_AES128CCM8_SHA256'
		}
		.tls_emptyrenegotiationinfo_scsv {
			return 'TLS_EMPTYRENEGOTIATIONINFO_SCSV'
		}
	}
}

// ChangeCipherSpec
enum ChangeCipherSpec as u8 {
	ccs = 0x01
}

@[inline]
fn new_ccs(v u8) !ChangeCipherSpec {
	match v {
		0x01 { return .ccs }
		else { return error('unsupported ccs type') }
	}
}
