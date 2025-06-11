module tls13

import encoding.binary

// ExtensionType = u16
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

@[inline]
fn (et ExtensionType) pack() ![]u8 {
	if u16(et) > max_u16 {
		return error('ExtensionType exceed limit')
	}
	mut out := []u8{len: u16size}
	binary.big_endian_put_u16(mut out, u16(et))
	return out
}

@[inline]
fn ExtensionType.from_u16(val u16) !ExtensionType {
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

@[direct_array_access; inline]
fn ExtensionType.unpack(b []u8) !ExtensionType {
	if b.len != 2 {
		return error('Bad ExtensionType bytes')
	}
	val := binary.big_endian_u16(b)
	if val > max_u16 {
		return error('ExtensionType value exceed limit')
	}
	return ExtensionType.from_u16(val)!
}

const min_extension_size = 4

struct Extension {
mut:
	tipe   ExtensionType // u16 value
	length int           // u16
	data   []u8          // <0..2^16-1>
}

@[inline]
fn (e Extension) packed_length() int {
	return min_extension_size + e.data.len
}

@[inline]
fn (e Extension) pack() ![]u8 {
	if e.length != e.data.len {
		return error('Mismatched extension length')
	}
	if e.data.len > max_u16 {
		return error('Extension data exceed limit')
	}

	mut len_buf := []u8{len: u16size}
	binary.big_endian_put_u16(mut len_buf, u16(e.length))

	mut out := []u8{}

	// writes out the data into output buffer
	out << e.tipe.pack()!
	out << len_buf
	out << e.data

	return out
}

@[direct_array_access; inline]
fn Extension.unpack(b []u8) !Extension {
	if b.len < min_extension_size {
		return error('Bad Extension bytes')
	}
	mut r := Buffer.new(b)!

	// read ExtensionType
	t := r.read_u16()!
	tipe := ExtensionType.from_u16(t)!

	// read length
	length := r.read_u16()!
	// bytes of extension data
	ext_data := r.read_at_least(int(length))!

	e := Extension{
		tipe:   tipe
		length: int(length)
		data:   ext_data
	}
	return e
}

fn (mut exts []Extension) append(e Extension) {
	if e in exts {
		return
	}
	// If one already exists with this type, replace it
	for mut item in exts {
		if item.tipe == e.tipe {
			item.data = e.data
			continue
		}
	}
	// otherwise append
	exts << e
}

// Extension extensions<8..2^16-1>;
fn (exts []Extension) pack() ![]u8 {
	mut ext_list := []u8{}
	for ex in exts {
		o := ex.pack()!
		ext_list << o
	}
	if ext_list.len > max_u16 {
		return error('Bad Extension list length')
	}
	mut len := []u8{len: 2}
	binary.big_endian_put_u16(mut len, u16(ext_list.len))

	mut out := []u8{}
	out << len
	out << ext_list

	return out
}

fn (exts []Extension) packed_length() int {
	mut n := 0
	n += 2
	for e in exts {
		n += e.packed_length()
	}
	return n
}

type ExtensionList = []Extension

fn (exl []Extension) filtered_exts_with_type(extype ExtensionType) []Extension {
	return exl.filter(it.tipe == extype)
}

fn (exl []Extension) validate_with_filter(tipe ExtensionType) ![]Extension {
	filtered := exl.filter(it.tipe == tipe)
	if filtered.len != 1 {
		return error('null or multiples tipe')
	}
	return filtered
}

@[direct_array_access; inline]
fn ExtensionList.unpack(b []u8) !ExtensionList {
	if b.len < 2 {
		return error('Bad ExtensionList bytes')
	}
	mut r := Buffer.new(b)!
	length := r.read_u16()!
	exts_bytes := r.read_at_least(int(length))!
	mut i := 0
	mut exts := []Extension{}
	for i < length {
		x := Extension.unpack(exts_bytes[i..])!
		exts.append(x)
		i += 2 // for tipe
		i += 2 // for data.len
		i += x.data.len
	}
	return ExtensionList(exts)
}
