module tls13

import math

enum AlertLevel {
	warning = 1
	fatal   = 2
}

fn (a AlertLevel) pack() ![]u8 {
	if int(a) > math.max_u8 {
		return error('AlertLevel value exceed')
	}
	return [u8(a)]
}

fn AlertLevel.unpack(b []u8) !AlertLevel {
	if b.len != 1 {
		return error('b.len != 1 for AlertLevel')
	}
	val := b[0]
	return unsafe { AlertLevel(val) }
}

fn (al AlertLevel) str() string {
	match al {
		.warning { return 'WARNING' }
		.fatal { return 'FATAL' }
	}
}

enum AlertDescription {
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

fn (ad AlertDescription) pack() ![]u8 {
	if int(ad) > math.max_u8 {
		return error('AlertDescription exceed limit')
	}
	val := [u8(ad)]
	return val
}

fn AlertDescription.unpack(b []u8) !AlertDescription {
	if b.len != 1 {
		return error('b.len != 1 for AlertDescription')
	}
	val := b[0]
	return unsafe { AlertDescription(val) }
}

struct Alert {
	level AlertLevel
	desc  AlertDescription
}

fn (a Alert) pack() ![]u8 {
	mut res := []u8{}
	res << a.level.pack()!
	res << a.desc.pack()!

	return res
}

fn Alert.unpack(b []u8) !Alert {
	if b.len != 2 {
		return error('b.len != 2 for Alert.unpack')
	}
	lvl := b[0]
	desc := b[1]

	alert := Alert{
		level: unsafe { AlertLevel(lvl) }
		desc: unsafe { AlertDescription(desc) }
	}

	return alert
}

// new_alert creates new Alert instance
pub fn new_alert(level AlertLevel, desc AlertDescription) Alert {
	alert := Alert{
		level: level
		desc: desc
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
