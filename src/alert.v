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
	if u8(a) > max_u8 {
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
fn (ad AlertDescription) pack() ![]u8 {
	if u8(ad) > max_u8 {
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
