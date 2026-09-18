// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Core TLS 1.3 opaque type definitions and wire value helpers.
module tls13

// TLS Version values defined by RFC 8446.
//
// These values are encoded on the wire as a 16-bit protocol version.
// TLS 1.3 uses 0x0304, while older versions remain available for compatibility.
// We define version as a raw u16 value for further future compatibility.
type Version = u16

const tls13_version = Version(0x0304)
const tls12_version = Version(0x0303)
const tls11_version = Version(0x0302)
const tls10_version = Version(0x0301)
const ssl30_version = Version(0x0300)

// str returns the human-readable name for the TLS version.
fn (v Version) str() string {
	return match v {
		tls13_version { 'TLS 1.3' }
		tls12_version { 'TLS 1.2' }
		tls11_version { 'TLS 1.1' }
		tls10_version { 'TLS 1.0' }
		ssl30_version { 'SSL 3.0' }
		else { 'UNKNOWN_TLS_VERSION ${v}' }
	}
}

// new_version converts a raw u16 wire value into a Version enum.
//
// Returns an error for unsupported or invalid version values.
@[inline]
fn new_version(val u16) Version {
	return match val {
		// vfmt off
		0x0300 { ssl30_version }
		0x0301 { tls10_version }
		0x0302 { tls11_version }
		0x0303 { tls12_version }
		0x0304 { tls13_version }
		else { Version(val) }
		// vfmt on
	}
}

// ContentType values for TLS record payloads.
//
// Each content type is encoded as a single byte on the TLS record layer.
type ContentType = u8

const ct_invalid = ContentType(0)
const ct_change_cipher_spec = ContentType(20)
const ct_alert = ContentType(21)
const ct_handshake = ContentType(22)
const ct_application_data = ContentType(23)
const ct_heartbeat = ContentType(24)

// new_content_type creates a TLS ContentType from a raw u8 value.
@[inline]
fn new_content_type(val u8) ContentType {
	return match val {
		// vfmt off
		0 { ct_invalid }
		20 { ct_change_cipher_spec }
		21 { ct_alert }
		22 { ct_handshake }
		23 { ct_application_data }
		24 { ct_heartbeat }
		else { ContentType(val) }
		// vfmt on
	}
}

// str returns the human-readable name for a ContentType.
fn (c ContentType) str() string {
	return match c {
		ct_invalid { 'INVALID_MSG' }
		ct_change_cipher_spec { 'CHANGE_CIPHER_SPEC' }
		ct_alert { 'ALERT' }
		ct_handshake { 'HANDSHAKE' }
		ct_application_data { 'APPLICATION_DATA' }
		ct_heartbeat { 'HEARTBEAT' }
		else { 'UNKNOWN_CONTENT_TYPE ${c}' }
	}
}

// HandshakeType values for TLS handshake messages.
//
// These values appear in the handshake message header and denote the
// specific handshake payload type.
type HandshakeType = u8

const ht_hello_request = HandshakeType(0)
const ht_client_hello = HandshakeType(1)
const ht_server_hello = HandshakeType(2)
const ht_hello_verify_request = HandshakeType(3)
const ht_new_session_ticket = HandshakeType(4)
const ht_end_of_early_data = HandshakeType(5)
const ht_hello_retry_request = HandshakeType(6)
const ht_encrypted_extensions = HandshakeType(8)
const ht_certificate = HandshakeType(11)
const ht_server_key_exchange = HandshakeType(12)
const ht_certificate_request = HandshakeType(13)
const ht_server_hello_done = HandshakeType(14)
const ht_certificate_verify = HandshakeType(15)
const ht_client_key_exchange = HandshakeType(16)
const ht_finished = HandshakeType(20)
const ht_certificate_url = HandshakeType(21)
const ht_certificate_status = HandshakeType(22)
const ht_supplemental_data = HandshakeType(23)
const ht_key_update = HandshakeType(24)
const ht_message_hash = HandshakeType(254)

// string representation of HandshakeType v
fn (v HandshakeType) str() string {
	return match v {
		ht_hello_request { 'HELLO_REQUEST' }
		ht_client_hello { 'CLIENT_HELLO' }
		ht_server_hello { 'SERVER_HELLO' }
		ht_hello_verify_request { 'HELLO_VERIFY_REQUEST' }
		ht_new_session_ticket { 'NEWSESSION_TICKET' }
		ht_end_of_early_data { 'ENDOF_EARLY_DATA' }
		ht_hello_retry_request { 'HELLO_RETRY_REQUEST' }
		ht_encrypted_extensions { 'ENCRYPTED_EXTENSIONS' }
		ht_certificate { 'CERTIFICATE' }
		ht_server_key_exchange { 'SERVER_KEY_EXCHANGE' }
		ht_certificate_request { 'CERTIFICATE_REQUEST' }
		ht_server_hello_done { 'SERVER_HELLO_DONE' }
		ht_certificate_verify { 'CERTIFICATE_VERIFY' }
		ht_client_key_exchange { 'CLIENT_KEY_EXCHANGE' }
		ht_finished { 'FINISHED' }
		ht_certificate_url { 'CERTIFICATE_URL' }
		ht_certificate_status { 'CERTIFICATE_STATUS' }
		ht_supplemental_data { 'SUPPLEMENTAL_DATA' }
		ht_key_update { 'KEY_UPDATE' }
		ht_message_hash { 'MESSAGE_HASH' }
		else { 'UNKNOWN_HANDSHAKE_TYPE ${val}' }
	}
}

// new_hsk_type converts a raw u8 handshake type value into a HandshakeType.
@[inline]
fn new_hsk_type(val u8) HandshakeType {
	return match val {
		// vfmt off
		0x00 { ht_hello_request }
		0x01 { ht_client_hello }
		0x02 { ht_server_hello }
		0x03 { ht_hello_verify_request }
		0x04 { ht_new_session_ticket }
		0x05 { ht_end_of_early_data }
		0x06 { ht_hello_retry_request }
		0x08 { ht_encrypted_extensions }
		0x0b { ht_certificate }
		0x0c { ht_server_key_exchange }
		0x0d { ht_certificate_request }
		0x0e { ht_server_hello_done }
		0x0f { ht_certificate_verify }
		0x10 { ht_client_key_exchange }
		0x14 { ht_finished }
		0x15 { ht_certificate_url }
		0x16 { ht_certificate_status }
		0x17 { ht_supplemental_data }
		0x18 { ht_key_update }
		0xfe { ht_message_hash }
		else { HandshakeType(val) }
		// vfmt on
	}
}

// Alert level values used in TLS alert messages.
//
// These values indicate whether an alert is a warning or fatal condition.
enum Level as u8 {
	warning = 0x01
	fatal   = 0x02
}

// new_level converts a raw alert level byte into a Level enum.
//
// Returns an error when the value is not a recognized alert level.
@[inline]
fn new_level(val u8) !Level {
	match val {
		0x01 { return .warning }
		0x02 { return .fatal }
		else { return error('unsupported alert level') }
	}
}

// str returns the human-readable name for an alert Level.
@[inline]
fn (al Level) str() string {
	match al {
		.warning { return 'WARNING' }
		.fatal { return 'FATAL' }
	}
}

// Alert description values for TLS alert messages.
//
// These codes specify the reason for the alert.
enum Description as u8 {
	close_notify                    = 0
	unexpected_message              = 10
	bad_record_mac                  = 20
	decryption_failed               = 21
	record_overflow                 = 22
	decompression_failure           = 30
	handshake_failure               = 40
	no_certificate                  = 41
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
	export_restriction              = 60
	protocol_version                = 70
	insufficient_security           = 71
	internal_error                  = 80
	inappropriate_fallback          = 86
	user_canceled                   = 90
	no_renegotiation                = 100
	missing_extension               = 109
	unsupported_extension           = 110
	certificate_unobtainable        = 111
	unrecognized_name               = 112
	bad_certificate_status_response = 113
	bad_certificate_hash_value      = 114
	unknown_psk_identity            = 115
	certificate_required            = 116
	no_application_protocol         = 120
}

// new_desc converts a raw alert description byte into a Description enum.
//
// Returns an error for unsupported or invalid alert description values.
@[inline]
fn new_desc(val u8) !Description {
	match val {
		0 { return .close_notify }
		10 { return .unexpected_message }
		20 { return .bad_record_mac }
		21 { return .decryption_failed }
		22 { return .record_overflow }
		30 { return .decompression_failure }
		40 { return .handshake_failure }
		41 { return .no_certificate }
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
		60 { return .export_restriction }
		70 { return .protocol_version }
		71 { return .insufficient_security }
		80 { return .internal_error }
		86 { return .inappropriate_fallback }
		90 { return .user_canceled }
		100 { return .no_renegotiation }
		109 { return .missing_extension }
		110 { return .unsupported_extension }
		111 { return .certificate_unobtainable }
		112 { return .unrecognized_name }
		113 { return .bad_certificate_status_response }
		114 { return .bad_certificate_hash_value }
		115 { return .unknown_psk_identity }
		116 { return .certificate_required }
		120 { return .no_application_protocol }
		else { return error('unsupported Description value') }
	}
}

// str returns string representation of this Description ad.
fn (ad Description) str() string {
	match ad {
		.close_notify { return 'CLOSE_NOTIFY' }
		.unexpected_message { return 'UNEXPECTED_MESSAGE' }
		.bad_record_mac { return 'BAD_RECORD_MAC' }
		.decryption_failed { return 'DECRYPTION_FAILED' }
		.record_overflow { return 'RECORD_OVERFLOW' }
		.decompression_failure { return 'DECOMPRESSION_FAILURE' }
		.handshake_failure { return 'HANDSHAKE_FAILURE' }
		.no_certificate { return 'NO_CERTIFICATE' }
		.bad_certificate { return 'BAD_CERTIFICATE' }
		.unsupported_certificate { return 'UNSUPPORTED_CERTIFICATE' }
		.certificate_revoked { return 'CERTIFICATE_REVOKED' }
		.certificate_expired { return 'CERTIFICATE_EXPIRED' }
		.certificate_unknown { return 'CERTIFICATE_UNKNOWN' }
		.illegal_parameter { return 'ILLEGAL_PARAMETER' }
		.unknown_ca { return 'UNKNOWN_CA' }
		.access_denied { return 'ACCESS_DENIED' }
		.decode_error { return 'DECODE_ERROR' }
		.decrypt_error { return 'DECRYPT_ERROR' }
		.export_restriction { return 'EXPORT_RESTRICTION' }
		.protocol_version { return 'PROTOCOL_VERSION' }
		.insufficient_security { return 'INSUFFICIENT_SECURITY' }
		.internal_error { return 'INTERNAL_ERROR' }
		.inappropriate_fallback { return 'INAPPROPRIATE_FALLBACK' }
		.user_canceled { return 'USER_CANCELED' }
		.no_renegotiation { return 'NO_RENEGOTIATION' }
		.missing_extension { return 'MISSING_EXTENSION' }
		.unsupported_extension { return 'UNSUPPORTED_EXTENSION' }
		.certificate_unobtainable { return 'CERTIFICATE_UNOBTAINABLE' }
		.unrecognized_name { return 'UNRECOGNIZED_NAME' }
		.bad_certificate_status_response { return 'BAD_CERTIFICATE_STATUS_RESPONSE' }
		.bad_certificate_hash_value { return 'BAD_CERTIFICATE_HASH_VALUE' }
		.unknown_psk_identity { return 'UNKNOWN_PSK_IDENTITY' }
		.certificate_required { return 'CERTIFICATE_REQUIRED' }
		.no_application_protocol { return 'NO_APPLICATION_PROTOCOL' }
	}
}

// TLS 1.3 Alert messages
//
@[noinit]
struct Alert {
mut:
	level Level
	desc  Description
}

// new_alert creates a new TLS 1.3 Alert message
@[inline]
fn new_alert(lv Level, desc Description) Alert {
	return Alert{
		level: lv
		desc:  desc
	}
}

// pack_alert encodes alert into 2-bytes array
@[inline]
fn pack_alert(a Alert) []u8 {
	mut out := []u8{cap: 2}
	out << u8(a.level)
	out << u8(a.desc)
	return out
}

// parse_alert decodes bytes as an Alert message
@[direct_array_access; inline]
fn parse_alert(bytes []u8) !Alert {
	if bytes.len < 2 {
		return error('underflow bytes alert')
	}
	return Alert{
		level: new_level(bytes[0])!
		desc:  new_desc(bytes[1])!
	}
}

// NameType = u8 for ServerName extension
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

// TLS 1.3 Extension
//
// ExtensionType is the type of TLS 1.3 Extension, as u16 value
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

// TlS 1.3 SignatureScheme
//
// SignatureScheme is a signature algorithms may be used in digital signatures, defined as u16 value
type SignatureScheme = u16

const sig_rsa_pkcs1_sha256 = SignatureScheme(0x0401)
const sig_rsa_pkcs1_sha384 = SignatureScheme(0x0501)
const sig_rsa_pkcs1_sha512 = SignatureScheme(0x0601)
const sig_ecdsa_gr_secp256r1_sha256 = SignatureScheme(0x0403)
const sig_ecdsa_secp384r1_sha384 = SignatureScheme(0x0503)
const sig_ecdsa_secp521r1_sha512 = SignatureScheme(0x0603)
const sig_rsa_pssrsae_sha256 = SignatureScheme(0x0804)
const sig_rsa_pssrsae_sha384 = SignatureScheme(0x0805)
const sig_rsa_pssrsae_sha512 = SignatureScheme(0x0806)
const sig_ed25519 = SignatureScheme(0x0807)
const sig_ed448 = SignatureScheme(0x0808)
const sig_rsa_psspss_sha256 = SignatureScheme(0x0809)
const sig_rsa_psspss_sha384 = SignatureScheme(0x080a)
const sig_rsa_psspss_sha512 = SignatureScheme(0x080b)
const sig_rsa_pkcs1_sha1 = SignatureScheme(0x0201)
const sig_ecdsa_sha1 = SignatureScheme(0x0203)

// new_signature_scheme creates SignatureScheme from u16 value
@[inline]
fn new_signature_scheme(val u16) SignatureScheme {
	return match val {
		// vfmt off
		0x0401 { sig_rsa_pkcs1_sha256 }
		0x0501 { sig_rsa_pkcs1_sha384 }
		0x0601 { sig_rsa_pkcs1_sha512 }
		0x0403 { sig_ecdsa_gr_secp256r1_sha256 }
		0x0503 { sig_ecdsa_secp384r1_sha384 }
		0x0603 { sig_ecdsa_secp521r1_sha512 }
		0x0804 { sig_rsa_pssrsae_sha256 }
		0x0805 { sig_rsa_pssrsae_sha384 }
		0x0806 { sig_rsa_pssrsae_sha512 }
		0x0807 { sig_ed25519 }
		0x0808 { sig_ed448 }
		0x0809 { sig_rsa_psspss_sha256 }
		0x080a { sig_rsa_psspss_sha384 }
		0x080b { sig_rsa_psspss_sha512 }
		0x0201 { sig_rsa_pkcs1_sha1 }
		0x0203 { sig_ecdsa_sha1 }
		else { SignatureScheme(val) }
		// vfmt on
	}
}


// str returns string representation of SignatureScheme s.
fn (s SignatureScheme) str() string {
	return match s {
		sig_rsa_pkcs1_sha256 { 'RSA_PKCS1_SHA256' }
		sig_rsa_pkcs1_sha384 { 'RSA_PKCS1_SHA384' }
		sig_rsa_pkcs1_sha512 { 'RSA_PKCS1_SHA512' }
		sig_ecdsa_gr_secp256r1_sha256 { 'ECDSA_gr_secp256r1_SHA256' }
		sig_ecdsa_secp384r1_sha384 { 'ECDSA_SECP384R1_SHA384' }
		sig_ecdsa_secp521r1_sha512 { 'ECDSA_SECP521R1_SHA512' }
		sig_rsa_pssrsae_sha256 { 'RSA_PSSRSAE_SHA256' }
		sig_rsa_pssrsae_sha384 { 'RSA_PSSRSAE_SHA384' }
		sig_rsa_pssrsae_sha512 { 'RSA_PSSRSAE_SHA512' }
		sig_ed25519 { 'ED25519' }
		sig_ed448 { 'ED448' }
		sig_rsa_psspss_sha256 { 'RSA_PSSPSS_SHA256' }
		sig_rsa_psspss_sha384 { 'RSA_PSSPSS_SHA384' }
		sig_rsa_psspss_sha512 { 'RSA_PSSPSS_SHA512' }
		sig_rsa_pkcs1_sha1 { 'RSA_PKCS1_SHA1' }
		sig_ecdsa_sha1 { 'ECDSA_SHA1' }
		else { 'UNKNWON_SIGNATURE_SCHEME ${val} ' }
	}
}

// TLS 1.3 NamedGroup
//
// A TLS 1.3 NamedGroup is set of opaques that both the client and server agree upon during
// the handshake to perform the key exchange, securely generating the shared secret keys for the session,
type NamedGroup = u16

const gr_secp256r1 = NamedGroup(0x0017)
const gr_secp384r1 = NamedGroup(0x0018)
const gr_secp521r1 = NamedGroup(0x0019)
const gr_x25519 = NamedGroup(0x001D)
const gr_x448 = NamedGroup(0x001E)
const gr_ffdhe2048 = NamedGroup(0x0100)
const gr_ffdhe3072 = NamedGroup(0x0101)
const gr_ffdhe4096 = NamedGroup(0x0102)
const gr_ffdhe6144 = NamedGroup(0x0103)
const gr_ffdhe8192 = NamedGroup(0x0104)

fn (g NamedGroup) str() string {
	return match g {
		gr_secp256r1 { 'SECP256R1' }
		gr_secp384r1 { 'SECP384R1' }
		gr_secp521r1 { 'SECP521R1' }
		gr_x25519 { 'x25519' }
		gr_x448 { 'x448' }
		gr_ffdhe2048 { 'FFDHE2048' }
		gr_ffdhe3072 { 'FFDHE3072' }
		gr_ffdhe4096 { 'FFDHE4096' }
		gr_ffdhe6144 { 'FFDHE6144' }
		gr_ffdhe8192 { 'FFDHE8192' }
		else { 'UNKNOWN_NAMEDGROUP ${val}' }
	}
}

// new_named_group creates a NamedGroup from u16 value
@[inline]
fn new_named_group(val u16) NamedGroup {
	return match val {
		0x0017 { gr_secp256r1 }
		0x0018 { gr_secp384r1 }
		0x0019 { gr_secp521r1 }
		0x001D { gr_x25519 }
		0x001E { gr_x448 }
		0x0100 { gr_ffdhe2048 }
		0x0101 { gr_ffdhe3072 }
		0x0102 { gr_ffdhe4096 }
		0x0103 { gr_ffdhe6144 }
		0x0104 { gr_ffdhe8192 }
		else { NamedGroup(val) }
	}
}

// B.4.  Cipher Suites
//
// CipherSuite is a symmetric cipher suite defines the pair of the AEAD algorithm and
// hash algorithm to be used with HKDF.
// Its defined as:
// 			  +------------------------------+-------------+
//            | Description                  | Value       |
//            +------------------------------+-------------+
//            | TLS_AES_128_GCM_SHA256       | {0x13,0x01} |
//            |                              |             |
//            | TLS_AES_256_GCM_SHA384       | {0x13,0x02} |
//            |                              |             |
//            | TLS_CHACHA20_POLY1305_SHA256 | {0x13,0x03} |
//            |                              |             |
//            | TLS_AES_128_CCM_SHA256       | {0x13,0x04} |
//            |                              |             |
//            | TLS_AES_128_CCM_8_SHA256     | {0x13,0x05} |
//            +------------------------------+-------------+
//
// See at https://datatracker.ietf.org/doc/html/rfc8446#appendix-B.4
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
			return 'TLS_CHACHA20POLY1305_SHA256'
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

// Helpers for CipherSuite related things
//

// tag_size returns standard size of underlying AEAD tag output defined by this ciphersuite, in bytes.
@[inline]
fn tag_size(c CipherSuite) int {
	match c {
		// normally, this ciphersuite was 16-bytes tag output
		.tls_aes128gcm_sha256, .tls_aes256gcm_sha384, .tls_chacha20poly1305_sha256 {
			return 16
		}
		else {
			eprintln('unsupported ciphersuite')
			exit(1)
		}
	}
}

// nonce_size returns standar of nonce (initialization vector) size in bytes,
// for underlying AEAD defined by this ciphersuite.
@[inline]
fn nonce_size(c CipherSuite) int {
	match c {
		// by default, its only support for 12-bytes nonce
		.tls_aes128gcm_sha256, .tls_aes256gcm_sha384, .tls_chacha20poly1305_sha256 {
			return 12
		}
		else {
			eprintln('unsupported ciphersuite')
			exit(1)
		}
	}
}

// digest_size returns the size of hash (digest) of underlying hash algorithm defined by this ciphersuite.
@[inline]
fn digest_size(c CipherSuite) int {
	match c {
		.tls_chacha20poly1305_sha256 {
			return 32
		}
		.tls_aes128ccm8_sha256 {
			return 32
		}
		.tls_aes128gcm_sha256 {
			return 32
		}
		.tls_aes256gcm_sha384 {
			return 48
		}
		else {
			panic('unsupported cipher suite')
		}
	}
}

// ChangeCipherSpec message
//
enum ChangeCipherSpec as u8 {
	// only support for single byte value, defined as u8(0x01)
	ccs = 0x01
}

// new_ccs creates a new ChangeCipherSpec value from byte value
@[inline]
fn new_ccs(v u8) !ChangeCipherSpec {
	match v {
		0x01 { return .ccs }
		else { return error('unsupported ccs type') }
	}
}
