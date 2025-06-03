module tls13

// B.2.  Alert Messages

// enum { warning(1), fatal(2), (255) } AlertLevel;
enum AlertLevel as u8 {
	warning = 0x01
	fatal   = 0x02
	// 255
}

@[inline]
fn (a AlertLevel) pack() ![]u8 {
	if a > max_u8 {
		return error('AlertLevel value exceed')
	}
	return [u8(a)]
}

@[direct_array_access; inline]
fn AlertLevel.unpack(b []u8) !AlertLevel {
	if b.len != 1 {
		return error('b.len != 1 for AlertLevel')
	}
	return AlertLevel.from_u8(b[0])!
}

@[inline]
fn AlertLevel.from_u8(v u8) !AlertLevel {
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
fn (ad AlertDescription) pack() ![]u8 {
	if ad > max_u8 {
		return error('AlertDescription exceed limit')
	}
	return [u8(ad)]
}

@[direct_array_access; inline]
fn AlertDescription.unpack(b []u8) !AlertDescription {
	if b.len != 1 {
		return error('b.len != 1 for AlertDescription')
	}
	return AlertDescription.from_u8(b[0])!
}

@[inline]
fn AlertDescription.from_u8(val u8) !AlertDescription {
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

struct Alert {
	level AlertLevel
	desc  AlertDescription
}

@[inline]
fn (a Alert) pack() ![]u8 {
	mut res := []u8{}
	res << a.level.pack()!
	res << a.desc.pack()!

	return res
}

@[direct_array_access; inline]
fn Alert.unpack(b []u8) !Alert {
	if b.len != 2 {
		return error('b.len != 2 for Alert.unpack')
	}
	level := AlertLevel.from_u8(b[0])!
	desc := AlertDescription.from_u8(b[1])!

	return Alert{
		level: level
		desc:  desc
	}
}

// new_alert creates new Alert instance
@[inline]
pub fn new_alert(level AlertLevel, desc AlertDescription) Alert {
	alert := Alert{
		level: level
		desc:  desc
	}
	return alert
}

// AlertError is custom error type represents Alert
struct AlertError {
	Alert
}

// custom error types through the IError interface. The interface requires two methods: msg() string and code() int.
// Every type that implements these methods can be used as an error
fn (a AlertError) msg() string {
	return 'Alert: ${a.level.str()}.${a.desc.str()}'
}

fn (a AlertError) code() int {
	return int(a.desc)
}

fn tls_error(ae Alert) AlertError {
	return AlertError{ae}
}

fn (ad AlertDescription) str() string {
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
