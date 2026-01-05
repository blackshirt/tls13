// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// TLS 1.3 Extension
// See the details on the sec. 4.2.  Extensions of RFC 8446
module tls13

import encoding.binary

// minimal extension size, in bytes
const min_extension_size = 4

// Raw TLS 1.3 Extension
//
@[noinit]
struct Extension {
mut:
	tipe Extensiotipe // u16 value
	data []u8         // <0..2^16-1>
}

// size_ext returns the size of serialized Extension, in bytes.
@[inline]
fn size_ext(r Extension) int {
	return min_extension_size + r.data.len
}

// the size of serialized extension list without the length
@[direct_array_access; inline]
fn size_extlist(xs []Extension) int {
	return size_objlist[Extension](xs, size_ext)
}

// the size of serialized extension list with n-bytes length
@[direct_array_access; inline]
fn size_extlist_withlen(xs []Extension, n SizeT) int {
	return size_objlist_withlen[Extension](xs, size_ext, n)
}

// pack_ext encodes Extension into bytes array
@[inline]
fn pack_ext(r Extension) ![]u8 {
	mut out := []u8{cap: size_ext(r)}
	// serialize Extensiotipe, its a u16 value
	out << pack_u16item[Extensiotipe](r.tipe)

	// serialize extension data, includes this data length as u16 value
	out << pack_raw_withlen(r.data, .size2)!

	// returns the output
	return out
}

// pack_extlist encodes extension list xs into bytes array. Its dont encode the length.
@[direct_array_access; inline]
fn pack_extlist(xs []Extension) ![]u8 {
	return pack_objlist[Extension](xs, pack_ext, size_ext)!
}

// pack_extlist_withlen encodes extension list xs into bytes array, includes the n-bytes length
// specified in n parameter. Its commonly use u16-sized length, by specifying .size2 enum value.
@[direct_array_access; inline]
fn pack_extlist_withlen(xs []Extension, n SizeT) ![]u8 {
	return pack_objlist_withlen[Extension](xs, pack_ext, size_ext, n)!
}

// parse_ext decodes bytes array into Extension
@[direct_array_access; inline]
fn parse_ext(bytes []u8) !Extension {
	// minimally its should contain extension type and payload length
	if bytes.len < min_extension_size {
		return error('Bad Extension bytes')
	}
	mut r := new_buffer(bytes)!

	// read Extensiotipe
	t := r.read_u16()!
	tipe := new_exttype(t)!

	// read data length
	length := r.read_u16()!
	// read bytes of extension data
	ext_data := r.read_at_least(int(length))!

	return Extension{
		tipe: tipe
		data: ext_data
	}
}

// append adds one item e into arrays xs
@[direct_array_access]
fn (mut xs []Extension) append(e Extension) {
	if e in xs {
		return
	}
	// If one already exists with this type, replace it
	for mut item in xs {
		if item.tipe == e.tipe {
			item.data = e.data
			continue
		}
	}
	// otherwise append
	xs << e
}

// parse_extlist_withlen decodes bytes into arrays of Extension with 2-bytes length
@[direct_array_access]
fn parse_extlist_withlen(bytes []u8) ![]Extension {
	if bytes.len < 2 {
		return error('Bad ExtensionList bytes')
	}
	mut r := new_buffer(bytes)!
	length := r.read_u16()!
	xs_bytes := r.read_at_least(int(length))!
	return parse_extlist(xs_bytes)!
}

// parse_extlist decodes bytes into arrays of Extension, without prepended length
@[direct_array_access; inline]
fn parse_extlist(bytes []u8) ![]Extension {
	mut i := 0
	mut xs := []Extension{cap: bytes.len / 4}
	for i < bytes.len {
		x := parse_ext(bytes[i..])!
		xs.append(x)
		// one length of serialized extension
		i += min_extension_size + x.data.len
	}
	return xs
}

// filtered_by_tipe filters xs by tipe and returns the new result.
@[direct_array_access]
fn (xs []Extension) filtered_by_tipe(tipe Extensiotipe) []Extension {
	return xs.filter(it.tipe == tipe)
}

// returns if only single valid result filtered by tipe
@[direct_array_access]
fn (xs []Extension) validate_with_filter(tipe Extensiotipe) ![]Extension {
	filtered := xs.filter(it.tipe == tipe)
	if filtered.len != 1 {
		return error('null or multiples tipe')
	}
	return filtered
}

// Helpers for creating TLS 1.3 Extension from supported extension type
//

// TLS 1.3 ServerName extension
//
// https://datatracker.ietf.org/doc/html/rfc6066#section-3
// struct {
//        NameType tipe;
//        select (tipe) {
//            case host_name: HostName;
//        } name;
//    } ServerName;
//
//    enum {
//        host_name(0), (255)
//    } NameType;
//
//    opaque HostName<1..2^16-1>;
//
//    struct {
//        ServerName server_name_list<1..2^16-1>
//    } ServerNameList;
// opaque HostName<1..2^16-1>
//
const min_srvname_size = 3

// Hostname was non-null bytes array, limit to max_u16 bytes
type HostName = []u8

@[noinit]
struct ServerName {
mut:
	tipe NameType
	name []u8
}

// new new_srvname was server name identification (SNI)
@[inline]
fn new_srvname(name string) !ServerName {
	if !name.is_ascii() {
		return error('not ASCII encoded byte string')
	}
	return ServerName{
		tipe: .host_name
		name: name.bytes()
	}
}

@[inline]
fn size_srvname(s ServerName) int {
	mut n := 0
	n += 1 // for tipe
	match s.tipe {
		.host_name {
			n += size_raw_withlen(s.name, .size2)
		}
		else {
			panic('unsupported name type')
		}
	}
	return n
}

// pack_srvname encodes ServerName s into bytes array
@[inline]
fn pack_srvname(s ServerName) ![]u8 {
	mut out := []u8{cap: size_srvname(s)}

	out << u8(s.tipe)
	match s.tipe {
		.host_name {
			n += pack_raw_withlen(s.name, .size2)
		}
		else {
			return error('unsupported name type')
		}
	}
	return out
}

@[direct_array_access; inline]
fn parse_srvname(b []u8) !ServerName {
	if b.len < min_srvname_size {
		return error('srvname parse bytes underflow')
	}
	mut r := new_buffer(b)!

	// read one byte of tipe
	nt := r.read_u8()!
	if nt != u8(NameType.host_name) {
		return error('unsupported NameType')
	}
	// read host_name length
	n := r.read_u16()!
	hn := r.read_at_least(int(n))!

	sv := ServerName{
		tipe: new_nametype(nt)!
		name: hn
	}

	return sv
}

// 4.2.1.  Supported Versions extension
//
// struct {
//        select (Handshake.msg_type) {
//            case client_hello:
//                 ProtocolVersion versions<2..254>;
//
//            case server_hello: /* and HelloRetryRequest */
//                 ProtocolVersion selected_version;
//        };
//    } SupportedVersions;
//
const default_supported_version = [Version.v13]

@[noinit]
struct SupportedVersions {
mut:
	msg_type HandshakeType
	// verlist is an array of Version. For server_hello or hello_retry_request message,
	// its only take single item of version, ie, take only the first item.
	verlist []Version
}

// new_spv creates SupportedVersions from msg_type and version list supplied.
@[direct_array_access; inline]
fn new_spv(msg_type HandshakeType, vers []Version) !SupportedVersions {
	match msg_type {
		.client_hello {
			if 2 * vers.len > max_u8 {
				return error('version list exceeed max_u8')
			}
			// TODO: should be sorted ?
			return SupportedVersions{
				msg_type: msg_type
				verlist:  vers
			}
		}
		.server_hello, .hello_retry_request {
			if vers.len > 1 {
				return error('multiples version for server_hello (hello_retry_request)')
			}
			return SupportedVersions{
				msg_type: msg_type
				verlist:  vers
			}
		}
		else {
			return error('invalid msg_type for supported_versions')
		}
	}
}

// size_spv returns the size of encoded SupportedVersions s
// for client_hello message, its also adds the version list 1-byte length
@[inline]
fn size_spv(s SupportedVersions) int {
	match s.msg_type {
		.server_hello, .hello_retry_request {
			return 2
		}
		.client_hello {
			// for client_hello, its prepended with 1-byte length
			return 1 + 2 * s.verlist.len
		}
		else {
			panic('invalid msg_type for supported_versions')
		}
	}
}

// pack_spv encodes SupportedVersions into bytes array
@[inline]
fn pack_spv(s SupportedVersions) ![]u8 {
	mut out := []u8{cap: size_spv(s)}
	match s.msg_type {
		.client_hello {
			// encodes with 1-byte length
			out << pack_u16list_withlen[Version](s.verlist, .size1)!
		}
		.server_hello, .hello_retry_request {
			out << pack_u16item[Version](s.verlist[0])!
		}
	}
}

// parse_spv decodes bytes into SupportedVersions, its accepts msg_type param to determine
// if this intended for client_hello or server_hello (and or hello_retry_request) message
@[direct_array_access; inline]
fn parse_spv(bytes []u8, msg_type HandshakeType) !SupportedVersions {
	mut r := new_buffer(bytes)!
	match msg_type {
		.client_hello {
			// minimally 1-byte length plus one of version item
			if bytes.len < 3 {
				return error('bytes underflow for client_hello supported_versions')
			}
			bol1 := r.read_u8()!
			bol1_bytes := r.read_at_least(int(bol1))!
			vers := parse_u16list[Version](bol1_bytes, new_version)!
			return SupportedVersions{
				msg_type: msg_type
				verlist:  vers
			}
		}
		.server_hello, .hello_retry_request {
			// read 2-bytes value
			val2 := r.read_u16()!
			ver := new_version(val2)!
			return SupportedVersions{
				msg_type: msg_type
				verlist:  [ver]
			}
		}
		else {
			return error('invalid msg_type for supported_versions')
		}
	}
}

// 4.2.2.  Cookie extension
//
// struct {
//          opaque cookie<1..2^16-1>;
//      } Cookie;
//
const min_cookie_size = 1
const max_cookie_size = max_u16

// TLS 1.3 Cookie extension
type Cookie = []u8

// new_cookie creates cookies extension from bytes array.
@[direct_array_access; inline]
fn new_cookie(bytes []u8) !Cookie {
	if bytes < min_cookie_size || btyes.len > max_cookie_size {
		return error('invalid bytes length')
	}
	return Cookie(bytes)
}

// ext_from_cookie creates a new Cookie type of Extension
@[inline]
fn ext_from_cookie(c Cookie) !Extension {
	return Extension{
		tipe: .cookie
		data: pack_raw_withlen(c, .size2)!
	}
}

// 4.2.3.  Signature Algorithms
//
// The "extension_data" field of these extensions contains a SignatureSchemeList value:
//
const default_supported_sigschemes = [SignatureScheme.ed25519]

// struct {
//        SignatureScheme supported_signature_algorithms<2..2^16-2>;
//    } SignatureSchemeList;
//
type SignatureSchemeList = []SignatureScheme

// pack_sigscheme_list encodes array of SignatureScheme into bytes array with 2-bytes length
@[direct_array_access; inline]
fn pack_sigscheme_list(ss []SignatureScheme) ![]u8 {
	return pack_u16list_withlen[SignatureScheme](ss, .size2)!
}

// parse_sigcheme_list decodes bytes into array of SignatureScheme
@[direct_array_access; inline]
fn parse_sigcheme_list(bytes []u8) ![]SignatureScheme {
	return parse_u16list_withlen[SignatureScheme](bytes, new_sigscheme, .size2)!
}

// ext_from_sigschemes creates .signature_algorithms extension type from arrays of SignatureScheme
@[direct_array_access]
fn ext_from_sigschemes(ss []SignatureScheme) !Extension {
	xs_payload := pack_u16list_with_len[SignatureScheme](ss, .size2)!
	return Extension{
		tipe: .signature_algorithms
		data: xs_payload
	}
}

// 4.2.7.  Supported Groups
//
// When sent by the client, the "supported_groups" extension indicates
// the named groups which the client supports for key exchange, ordered
// from most preferred to least preferred.
// The "extension_data" field of this extension contains a "NamedGroupList" value
//
const default_supported_namegroups = [NamedGroup.x25519]

// struct {
//     NamedGroup named_group_list<2..2^16-1>;
// } NamedGroupList;
//
type NamedGroupList = []NamedGroup

// pack_namegroup_list encodes array of NamedGroup into bytes array with 2-bytes length
@[direct_array_access; inline]
fn pack_namegroup_list(ns []NamedGroup) ![]u8 {
	return pack_u16list_withlen[NamedGroup](ns, .size2)!
}

// parse_namegroup_list decodes bytes into array of NamedGroup
@[direct_array_access; inline]
fn parse_namegroup_list(bytes []u8) ![]NamedGroup {
	return parse_u16list_withlen[NamedGroup](bytes, new_group, .size2)!
}

// ext_from_namegroups creates .supported_groups extension type from array of NamedGroup
@[direct_array_access]
fn ext_from_namegroups(ns []NamedGroup) !Extension {
	ns_payload := pack_u16list_with_len[NamedGroup](ns, .size2)!
	return Extension{
		tipe: .supported_groups
		data: ns_payload
	}
}
