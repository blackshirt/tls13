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
		else { 'UNKNOWN_TLSVERSION ${v}' }
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
		else { 'UNKNOWN_CONTENTTYPE ${c}' }
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
		else { 'UNKNOWN_HANDSHAKETYPE ${v}' }
	}
}

// new_hsk_type converts a raw u8 handshake type value into a HandshakeType.
@[inline]
fn new_hsk_type(v u8) HandshakeType {
	return match v {
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
		else { HandshakeType(v) }
		// vfmt on
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
type CipherSuite = u16

const tls_aes128gcm_sha256 = CipherSuite(0x1301)
const tls_aes256gcm_sha384 = CipherSuite(0x1302)
const tls_chacha20poly1305_sha256 = CipherSuite(0x1303)
const tls_aes128ccm_sha256 = CipherSuite(0x1304)
const tls_aes128ccm8_sha256 = CipherSuite(0x1305)
const tls_emptyrenegotiationinfo_scsv = CipherSuite(0x00ff)

// new_ciphersuite creates CipherSuite from u16 value
@[inline]
fn new_ciphersuite(v u16) CipherSuite {
	return match v {
		0x1301 { tls_aes128gcm_sha256 }
		0x1302 { tls_aes256gcm_sha384 }
		0x1303 { tls_chacha20poly1305_sha256 }
		0x1304 { tls_aes128ccm_sha256 }
		0x1305 { tls_aes128ccm8_sha256 }
		0x00ff { tls_emptyrenegotiationinfo_scsv }
		else { CipherSuite(v) }
	}
}

// str returns string representation of CipherSuite c
fn (c CipherSuite) str() string {
	return match c {
		tls_aes128gcm_sha256 { 'TLS_AES128GCM_SHA256' }
		tls_aes256gcm_sha384 { 'TLS_AES256GCM_SHA384' }
		tls_chacha20poly1305_sha256 { 'TLS_CHACHA20POLY1305_SHA256' }
		tls_aes128ccm_sha256 { 'TLS_AES128CCM_SHA256' }
		tls_aes128ccm8_sha256 { 'TLS_AES128CCM8_SHA256' }
		tls_emptyrenegotiationinfo_scsv { 'TLS_EMPTYRENEGOTIATIONINFO_SCSV' }
		else { 'UNKNOWN_CIPHERSUITE ${v}' }
	}
}

// TLS 1.3 Extension
//
// ExtensionType is the type of TLS 1.3 Extension, as u16 value
type ExtensionType = u16

const ext_server_name = ExtensionType(0)
const ext_max_fragment_length = ExtensionType(1)
const ext_client_certificate_url = ExtensionType(2)
const ext_trusted_ca_keys = ExtensionType(3)
const ext_truncated_hmac = ExtensionType(4)
const ext_status_request = ExtensionType(5)
const ext_user_mapping = ExtensionType(6)
const ext_client_authz = ExtensionType(7)
const ext_server_authz = ExtensionType(8)
const ext_cert_type = ExtensionType(9)
const ext_supported_groups = ExtensionType(10)
const ext_ec_point_formats = ExtensionType(11)
const ext_srp = ExtensionType(12)
const ext_signature_algorithms = ExtensionType(13)
const ext_use_srtp = ExtensionType(14)
const ext_heartbeat = ExtensionType(15)
const ext_apln = ExtensionType(16)
const ext_status_request_v2 = ExtensionType(17)
const ext_signed_certificate_timestamp = ExtensionType(18)
const ext_client_certificate_type = ExtensionType(19)
const ext_server_certificate_type = ExtensionType(20)
const ext_padding = ExtensionType(21)
const ext_encrypt_then_mac = ExtensionType(22)
const ext_extended_master_secret = ExtensionType(23)
const ext_token_binding = ExtensionType(24)
const ext_cached_info = ExtensionType(25)
const ext_tls_lts = ExtensionType(26)
const ext_compress_certificate = ExtensionType(27)
const ext_record_size_limit = ExtensionType(28)
const ext_pwd_protect = ExtensionType(29)
const ext_pwd_clear = ExtensionType(30)
const ext_password_salt = ExtensionType(31)
const ext_ticket_pinning = ExtensionType(32)
const ext_tlscert_with_extern_psk = ExtensionType(33)
const ext_delegated_credential = ExtensionType(34)
const ext_session_ticket = ExtensionType(35)
const ext_tlmsp = ExtensionType(36)
const ext_tlmsp_proxying = ExtensionType(37)
const ext_tlmsp_delegate = ExtensionType(38)
const ext_supported_ekt_ciphers = ExtensionType(39)
const ext_reserved_40 = ExtensionType(40) // Used but never assigned
const ext_pre_shared_key = ExtensionType(41)
const ext_early_data = ExtensionType(42)
const ext_supported_versions = ExtensionType(43)
const ext_cookie = ExtensionType(44)
const ext_psk_key_exchange_modes = ExtensionType(45)
const ext_reserved_46 = ExtensionType(46) // Used but never assigned
const ext_certificate_authorities = ExtensionType(47)
const ext_oid_filters = ExtensionType(48)
const ext_post_handshake_auth = ExtensionType(49)
const ext_signature_algorithms_cert = ExtensionType(50)
const ext_key_share = ExtensionType(51)
const ext_transparency_info = ExtensionType(52)
const ext_connection_id_deprecated = ExtensionType(53) // deprecated
const ext_connection_id = ExtensionType(54)
const ext_external_id_hash = ExtensionType(55)
const ext_external_sessid = ExtensionType(56)
const ext_quic_transport_parameters = ExtensionType(57)
const ext_ticket_request = ExtensionType(58)
const ext_dnssec_chain = ExtensionType(59)
const ext_seqnum_encryption_algorithms = ExtensionType(60)
const ext_reserved_for_private_use = ExtensionType(65280)
const ext_renegotiation_info = ExtensionType(65281)
const ext_unassigned = ExtensionType(0xffff)

// new_extension_type creates a new ExtensionType from u16 value
@[inline]
fn new_extension_type(v u16) ExtensionType {
	return match v {
		// vfmt off
		0 { ext_server_name }
		1 { ext_max_fragment_length }
		2 { ext_client_certificate_url }
		3 { ext_trusted_ca_keys }
		4 { ext_truncated_hmac }
		5 { ext_status_request }
		6 { ext_user_mapping }
		7 { ext_client_authz }
		8 { ext_server_authz }
		9 { ext_cert_type }
		10 { ext_supported_groups }
		11 { ext_ec_point_formats }
		12 { ext_srp }
		13 { ext_signature_algorithms }
		14 { ext_use_srtp }
		15 { ext_heartbeat }
		16 { ext_apln }
		17 { ext_status_request_v2 }
		18 { ext_signed_certificate_timestamp }
		19 { ext_client_certificate_type }
		20 { ext_server_certificate_type }
		21 { ext_padding }
		22 { ext_encrypt_then_mac }
		23 { ext_extended_master_secret }
		24 { ext_token_binding }
		25 { ext_cached_info }
		26 { ext_tls_lts }
		27 { ext_compress_certificate }
		28 { ext_record_size_limit }
		29 { ext_pwd_protect }
		30 { ext_pwd_clear }
		31 { ext_password_salt }
		32 { ext_ticket_pinning }
		33 { ext_tlscert_with_extern_psk }
		34 { ext_delegated_credential }
		35 { ext_session_ticket }
		36 { ext_tlmsp }
		37 { ext_tlmsp_proxying }
		38 { ext_tlmsp_delegate }
		39 { ext_supported_ekt_ciphers }
		40 { ext_reserved_40 } // Used but never assigned
		41 { ext_pre_shared_key }
		42 { ext_early_data }
		43 { ext_supported_versions }
		44 { ext_cookie }
		45 { ext_psk_key_exchange_modes }
		46 { ext_reserved_46 } // Used but never assigned
		47 { ext_certificate_authorities }
		48 { ext_oid_filters }
		49 { ext_post_handshake_auth }
		50 { ext_signature_algorithms_cert }
		51 { ext_key_share }
		52 { ext_transparency_info }
		53 { ext_connection_id_deprecated } // deprecated
		54 { ext_connection_id }
		55 { ext_external_id_hash }
		56 { ext_external_sessid }
		57 { ext_quic_transport_parameters }
		58 { ext_ticket_request }
		59 { ext_dnssec_chain }
		60 { ext_seqnum_encryption_algorithms }
		65280 { ext_reserved_for_private_use }
		65281 { ext_renegotiation_info }
		0xffff { ext_unassigned }
		else { ExtensionType(v) }
		// vfmt on
	}
}

// string representations of ExtensionType e
fn (e ExtensionType) str() string {
	return match e {
		ext_server_name { 'ext_server_name' }
		ext_max_fragment_length { 'ext_max_fragment_length' }
		ext_client_certificate_url { 'ext_client_certificate_url' }
		ext_trusted_ca_keys { 'ext_trusted_ca_keys' }
		ext_truncated_hmac { 'ext_truncated_hmac' }
		ext_status_request { 'ext_status_request' }
		ext_user_mapping { 'ext_user_mapping' }
		ext_client_authz { 'ext_client_authz' }
		ext_server_authz { 'ext_server_authz' }
		ext_cert_type { 'ext_cert_type' }
		ext_supported_groups { 'ext_supported_groups' }
		ext_ec_point_formats { 'ext_ec_point_formats' }
		ext_srp { 'ext_srp' }
		ext_signature_algorithms { 'ext_signature_algorithms' }
		ext_use_srtp { 'ext_use_srtp' }
		ext_heartbeat { 'ext_heartbeat' }
		ext_apln { 'ext_apln' }
		ext_status_request_v2 { 'ext_status_request_v2' }
		ext_signed_certificate_timestamp { 'ext_signed_certificate_timestamp' }
		ext_client_certificate_type { 'ext_client_certificate_type' }
		ext_server_certificate_type { 'ext_server_certificate_type' }
		ext_padding { 'ext_padding' }
		ext_encrypt_then_mac { 'ext_encrypt_then_mac' }
		ext_extended_master_secret { 'ext_extended_master_secret' }
		ext_token_binding { 'ext_token_binding' }
		ext_cached_info { 'ext_cached_info' }
		ext_tls_lts { 'ext_tls_lts' }
		ext_compress_certificate { 'ext_compress_certificate' }
		ext_record_size_limit { 'ext_record_size_limit' }
		ext_pwd_protect { 'ext_pwd_protect' }
		ext_pwd_clear { 'ext_pwd_clear' }
		ext_password_salt { 'ext_password_salt' }
		ext_ticket_pinning { 'ext_ticket_pinning' }
		ext_tlscert_with_extern_psk { 'ext_tlscert_with_extern_psk' }
		ext_delegated_credential { 'ext_delegated_credential' }
		ext_session_ticket { 'ext_session_ticket' }
		ext_tlmsp { 'ext_tlmsp' }
		ext_tlmsp_proxying { 'ext_tlmsp_proxying' }
		ext_tlmsp_delegate { 'ext_tlmsp_delegate' }
		ext_supported_ekt_ciphers { 'ext_supported_ekt_ciphers' }
		ext_reserved_40 { 'ext_reserved_40' } // Used but never assigned
		ext_pre_shared_key { 'ext_pre_shared_key' }
		ext_early_data { 'ext_early_data' }
		ext_supported_versions { 'ext_supported_versions' }
		ext_cookie { 'ext_cookie' }
		ext_psk_key_exchange_modes { 'ext_psk_key_exchange_modes' }
		ext_reserved_46 { 'ext_reserved_46' } // Used but never assigned
		ext_certificate_authorities { 'ext_certificate_authorities' }
		ext_oid_filters { 'ext_oid_filters' }
		ext_post_handshake_auth { 'ext_post_handshake_auth' }
		ext_signature_algorithms_cert { 'ext_signature_algorithms_cert' }
		ext_key_share { 'ext_key_share' }
		ext_transparency_info { 'ext_transparency_info' }
		ext_connection_id_deprecated { 'ext_connection_id_deprecated' } // deprecated
		ext_connection_id { 'ext_connection_id' }
		ext_external_id_hash { 'ext_external_id_hash' }
		ext_external_sessid { 'ext_external_sessid' }
		ext_quic_transport_parameters { 'ext_quic_transport_parameters' }
		ext_ticket_request { 'ext_ticket_request' }
		ext_dnssec_chain { 'ext_dnssec_chain' }
		ext_seqnum_encryption_algorithms { 'ext_seqnum_encryption_algorithms' }
		ext_reserved_for_private_use { 'ext_reserved_for_private_use' }
		ext_renegotiation_info { 'ext_renegotiation_info' }
		ext_unassigned { 'ext_unassigned' }
		else { 'unknown_extension_type ${e}' }
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
fn new_signature_scheme(v u16) SignatureScheme {
	return match v {
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
		else { SignatureScheme(v) }
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
		else { 'UNKNWON_SIGNATURESCHEME ${v} ' }
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

// string representation of NamedGroup g 
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
		else { 'UNKNOWN_NAMEDGROUP ${g}' }
	}
}

// new_named_group creates a NamedGroup from u16 value
@[inline]
fn new_named_group(v u16) NamedGroup {
	return match v {
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
		else { NamedGroup(v) }
	}
}

// Alert level values used in TLS alert messages.
//
// These values indicate whether an alert is a warning or fatal condition.
type Level = u8

const alert_warning = Level(0x01)
const alert_fatal = Level(0x02)

// new_level converts a raw alert level byte into a Level.
//
@[inline]
fn new_level(val u8) Level {
	return match val {
		0x01 { alert_warning }
		0x02 { alert_fatal }
		else { Level(val) }
	}
}

// str returns the human-readable name for an alert Level.
@[inline]
fn (a Level) str() string {
	match a {
		alert_warning { 'WARNING' }
		alert_fatal { 'FATAL' }
		else { 'UNKNOWN_LEVEL ${a}' }
	}
}

// Alert description values for TLS alert messages.
//
// These codes specify the reason for the alert.
type Description = u8

const desc_close_notify = 0
const desc_unexpected_message = 10
const desc_bad_record_mac = 20
const desc_decryption_failed = 21
const desc_record_overflow = 22
const desc_decompression_failure = 30
const desc_handshake_failure = 40
const desc_no_certificate = 41
const desc_bad_certificate = 42
const desc_unsupported_certificate = 43
const desc_certificate_revoked = 44
const desc_certificate_expired = 45
const desc_certificate_unknown = 46
const desc_illegal_parameter = 47
const desc_unknown_ca = 48
const desc_access_denied = 49
const desc_decode_error = 50
const desc_decrypt_error = 51
const desc_export_restriction = 60
const desc_protocol_version = 70
const desc_insufficient_security = 71
const desc_internal_error = 80
const desc_inappropriate_fallback = 86
const desc_user_canceled = 90
const desc_no_renegotiation = 100
const desc_missing_extension = 109
const desc_unsupported_extension = 110
const desc_certificate_unobtainable = 111
const desc_unrecognized_name = 112
const desc_bad_certificate_status_response = 113
const desc_bad_certificate_hash_value = 114
const desc_unknown_psk_identity = 115
const desc_certificate_required = 116
const desc_no_application_protocol = 120

// new_desc converts a raw alert description byte into a Description enum.
@[inline]
fn new_desc(val u8) Description {
	return match val {
		0 { desc_close_notify }
		10 { desc_unexpected_message }
		20 { desc_bad_record_mac }
		21 { desc_decryption_failed }
		22 { desc_record_overflow }
		30 { desc_decompression_failure }
		40 { desc_handshake_failure }
		41 { desc_no_certificate }
		42 { desc_bad_certificate }
		43 { desc_unsupported_certificate }
		44 { desc_certificate_revoked }
		45 { desc_certificate_expired }
		46 { desc_certificate_unknown }
		47 { desc_illegal_parameter }
		48 { desc_unknown_ca }
		49 { desc_access_denied }
		50 { desc_decode_error }
		51 { desc_decrypt_error }
		60 { desc_export_restriction }
		70 { desc_protocol_version }
		71 { desc_insufficient_security }
		80 { desc_internal_error }
		86 { desc_inappropriate_fallback }
		90 { desc_user_canceled }
		100 { desc_no_renegotiation }
		109 { desc_missing_extension }
		110 { desc_unsupported_extension }
		111 { desc_certificate_unobtainable }
		112 { desc_unrecognized_name }
		113 { desc_bad_certificate_status_response }
		114 { desc_bad_certificate_hash_value }
		115 { desc_unknown_psk_identity }
		116 { desc_certificate_required }
		120 { desc_no_application_protocol }
		else { Description(val) }
	}
}

// str returns string representation of this Description d.
fn (d Description) str() string {
	return match d {
		desc_close_notify { 'CLOSE_NOTIFY' }
		desc_unexpected_message { 'UNEXPECTED_MESSAGE' }
		desc_bad_record_mac { 'BAD_RECORD_MAC' }
		desc_decryption_failed { 'DECRYPTION_FAILED' }
		desc_record_overflow { 'RECORD_OVERFLOW' }
		desc_decompression_failure { 'DECOMPRESSION_FAILURE' }
		desc_handshake_failure { 'HANDSHAKE_FAILURE' }
		desc_no_certificate { 'NO_CERTIFICATE' }
		desc_bad_certificate { 'BAD_CERTIFICATE' }
		desc_unsupported_certificate { 'UNSUPPORTED_CERTIFICATE' }
		desc_certificate_revoked { 'CERTIFICATE_REVOKED' }
		desc_certificate_expired { 'CERTIFICATE_EXPIRED' }
		desc_certificate_unknown { 'CERTIFICATE_UNKNOWN' }
		desc_illegal_parameter { 'ILLEGAL_PARAMETER' }
		desc_unknown_ca { 'UNKNOWN_CA' }
		desc_access_denied { 'ACCESS_DENIED' }
		desc_decode_error { 'DECODE_ERROR' }
		desc_decrypt_error { 'DECRYPT_ERROR' }
		desc_export_restriction { 'EXPORT_RESTRICTION' }
		desc_protocol_version { 'PROTOCOL_VERSION' }
		desc_insufficient_security { 'INSUFFICIENT_SECURITY' }
		desc_internal_error { 'INTERNAL_ERROR' }
		desc_inappropriate_fallback { 'INAPPROPRIATE_FALLBACK' }
		desc_user_canceled { 'USER_CANCELED' }
		desc_no_renegotiation { 'NO_RENEGOTIATION' }
		desc_missing_extension { 'MISSING_EXTENSION' }
		desc_unsupported_extension { 'UNSUPPORTED_EXTENSION' }
		desc_certificate_unobtainable { 'CERTIFICATE_UNOBTAINABLE' }
		desc_unrecognized_name { 'UNRECOGNIZED_NAME' }
		desc_bad_certificate_status_response { 'BAD_CERTIFICATE_STATUS_RESPONSE' }
		desc_bad_certificate_hash_value { 'BAD_CERTIFICATE_HASH_VALUE' }
		desc_unknown_psk_identity { 'UNKNOWN_PSK_IDENTITY' }
		desc_certificate_required { 'CERTIFICATE_REQUIRED' }
		desc_no_application_protocol { 'NO_APPLICATION_PROTOCOL' }
		else { 'UNKNOWN_DESCRIPTION ${d}' }
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

// NameType = u8 for ServerName extension
type NameType = u8

const nt_host_name = NameType(0x00)

// new_name_type creates a new NameType from byte value.
@[inline]
fn new_name_type(val u8) NameType {
	return match val {
		0x00 { nt_host_name }
		else { NameType(val) }
	}
}
