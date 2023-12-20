module tls13

import math
import encoding.binary
import blackshirt.buffer

// ExtensionType = u16
enum ExtensionType {
	server_name                            = 0
	max_fragment_length                    = 1
	client_certificate_url                 = 2
	trusted_ca_keys                        = 3
	truncated_hmac                         = 4
	status_request                         = 5
	user_mapping                           = 6
	client_authz                           = 7
	server_authz                           = 8
	cert_type                              = 9
	supported_groups                       = 10
	ec_point_formats                       = 11
	srp                                    = 12
	signature_algorithms                   = 13
	use_srtp                               = 14
	heartbeat                              = 15
	application_layer_protocol_negotiation = 16
	status_request_v2                      = 17
	signed_certificate_timestamp           = 18
	client_certificate_type                = 19
	server_certificate_type                = 20
	padding                                = 21
	encrypt_then_mac                       = 22
	extended_master_secret                 = 23
	token_binding                          = 24
	cached_info                            = 25
	tls_lts                                = 26
	compress_certificate                   = 27
	record_size_limit                      = 28
	pwd_protect                            = 29
	pwd_clear                              = 30
	password_salt                          = 31
	ticket_pinning                         = 32
	tls_cert_with_extern_psk               = 33
	delegated_credential                   = 34
	session_ticket                         = 35
	tlmsp                                  = 36
	tlmsp_proxying                         = 37
	tlmsp_delegate                         = 38
	supported_ekt_ciphers                  = 39
	reserved_40                            = 40 // Used but never assigned
	pre_shared_key                         = 41
	early_data                             = 42
	supported_versions                     = 43
	cookie                                 = 44
	psk_key_exchange_modes                 = 45
	reserved_46                            = 46 // Used but never assigned
	certificate_authorities                = 47
	oid_filters                            = 48
	post_handshake_auth                    = 49
	signature_algorithms_cert              = 50
	key_share                              = 51
	transparency_info                      = 52
	connection_id_deprecated               = 53 // deprecated
	connection_id                          = 54
	external_id_hash                       = 55
	external_session_id                    = 56
	quic_transport_parameters              = 57
	ticket_request                         = 58
	dnssec_chain                           = 59
	sequence_number_encryption_algorithms  = 60
	reserved_for_private_use               = 65280
	renegotiation_info                     = 65281
	unassigned                             = 0xff
}

fn (et ExtensionType) pack() ![]u8 {
	if int(et) > int(math.max_u16) {
		return error('ExtensionType exceed limit')
	}
	mut out := []u8{len: u16size}
	binary.big_endian_put_u16(mut out, u16(et))
	return out
}

fn ExtensionType.unpack(b []u8) !ExtensionType {
	if b.len != 2 {
		return error('Bad ExtensionType bytes')
	}
	val := binary.big_endian_u16(b)
	if val > math.max_u16 {
		return error('ExtensionType value exceed limit')
	}
	return unsafe { ExtensionType(val) }
}

struct Extension {
mut:
	tipe   ExtensionType
	length int
	data   []u8 // <0..2^16-1>
}

fn (e Extension) packed_length() int {
	mut n := 0
	n += 2
	n += 2
	n += e.data.len

	return n
}

fn (e Extension) pack() ![]u8 {
	if e.length != e.data.len {
		return error('Mismatched extension length')
	}
	if e.data.len > int(math.max_u16) {
		return error('Extension data exceed limit')
	}

	t := e.tipe.pack()!
	mut len := []u8{len: u16size}
	binary.big_endian_put_u16(mut len, u16(e.length))

	mut out := []u8{}
	out << t
	out << len
	out << e.data

	return out
}

fn Extension.unpack(b []u8) !Extension {
	if b.len < 4 {
		return error('Bad Extension bytes')
	}
	mut r := buffer.new_reader(b)

	// read ExtensionType
	t := r.read_u16()!
	tipe := unsafe { ExtensionType(t) }

	// read length
	length := r.read_u16()!
	// bytes of extension data
	ext_data := r.read_at_least(int(length))!

	e := Extension{
		tipe: tipe
		length: int(length)
		data: ext_data
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
	if ext_list.len > int(math.max_u16) {
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

fn ExtensionList.unpack(b []u8) !ExtensionList {
	if b.len < 2 {
		return error('Bad ExtensionList bytes')
	}
	mut r := buffer.new_reader(b)
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
