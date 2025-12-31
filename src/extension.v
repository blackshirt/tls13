// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// TLS 1.3 Extension
// See the details on the sec. 4.2.  Extensions of RFC 8446
module tls13

import encoding.binary

const min_extension_size = 4

// Raw TLS 1.3 Extension
@[noinit]
struct TlsExtension {
mut:
	tipe ExtensionType // u16 value
	data []u8          // <0..2^16-1>
}

// packlen_ext returns the length of serialized TlsExtension, in bytes.
@[inline]
fn packlen_ext(r TlsExtension) int {
	return min_extension_size + r.data.len
}

// pack_ext encodes TlsExtension into bytes array
@[inline]
fn pack_ext(r TlsExtension) ![]u8 {
	mut out := []u8{cap: packlen_ext(r)}
	// serialize ExtensionType, its a u16 value
	xtipe := pack_u16item[ExtensionType](r.tipe)
	out << xtipe

	// serialize extension data, includes this data length as u16 value
	data_len := pack_u16item[int](data.len)
	out << data_len
	// finally puts the extesnion data
	out << r.data

	// returns the output
	return out
}

// parse_ext decodes bytes array into TlsExtension
@[direct_array_access; inline]
fn parse_ext(bytes []u8) !TlsExtension {
	// minimally its should contain extension type and payload length
	if bytes.len < min_extension_size {
		return error('Bad TlsExtension bytes')
	}
	mut r := new_buffer(bytes)!

	// read ExtensionType
	t := r.read_u16()!
	tipe := new_exttype(t)!

	// read data length
	length := r.read_u16()!
	// read bytes of extension data
	ext_data := r.read_at_least(int(length))!

	return TlsExtension{
		tipe: tipe
		data: ext_data
	}
}

// append adds one item e into arrays xs
@[direct_array_access]
fn (mut xs []TlsExtension) append(e TlsExtension) {
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

// pack_xslist encodes arrays of TlsExtension into bytes array.
@[direct_array_access; inline]
fn pack_xslist(xs []TlsExtension) ![]u8 {
	mut out := []u8{cap: packlen_xslist(xs)}
	for x in xs {
		out << pack_ext(x)!
	}
	return out
}

// pack_xslist_withlen encodes xs into bytes arrays prepended with 2-bytes length (u16-sized)
@[direct_array_access; inline]
fn pack_xslist_withlen(xs []TlsExtension) ![]u8 {
	mut out := []u8{cap: packlen_xslist_withlen(xs)}

	// encoded extension payload length
	mut bol2 := []u8{len: 2}
	binary.big_endian_put_u16(mut bol2, packlen_xslist(xs))
	out << bol2

	// serializes the extension payload
	out << pack_xslist(xs)!

	return out
}

// packlen_xslist_withlen returns the length of serialized xs prepended with the u16-sized length
@[direct_array_access; inline]
fn packlen_xslist_withlen(xs []TlsExtension) int {
	return 2 + packlen_xslist(xs)
}

// packlen_xslist tells the length of serialized xs, without the prepended length
@[direct_array_access; inline]
fn packlen_xslist(xs []TlsExtension) int {
	mut n := 0
	for e in xs {
		n += packlen_ext(e)
	}
	return n
}

// parse_xslist_withlen decodes bytes into arrays of TlsExtension with prepended length
@[direct_array_access]
fn parse_xslist_withlen(bytes []u8) ![]TlsExtension {
	if bytes.len < 2 {
		return error('Bad ExtensionList bytes')
	}
	mut r := new_buffer(bytes)!
	length := r.read_u16()!
	xs_bytes := r.read_at_least(int(length))!
	return parse_xslist(xs_bytes)!
}

// parse_xslist decodes bytes into arrays of TlsExtension, without prepended length
@[direct_array_access; inline]
fn parse_xslist(bytes []u8) ![]TlsExtension {
	mut i := 0
	mut xs := []TlsExtension{cap: bytes.len / 4}
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
fn (xs []TlsExtension) filtered_by_tipe(tipe ExtensionType) []TlsExtension {
	return xs.filter(it.tipe == tipe)
}

// returns if only single valid result filtered by tipe
@[direct_array_access]
fn (xs []TlsExtension) validate_with_filter(tipe ExtensionType) ![]TlsExtension {
	filtered := xs.filter(it.tipe == tipe)
	if filtered.len != 1 {
		return error('null or multiples tipe')
	}
	return filtered
}

// Helpers for creating TLS 1.3 Extension from supported extension type
//

// ext_from_sigscheme_list creates .signature_algorithms extesnion type from arrays of SignatureScheme
@[direct_array_access]
fn ext_from_sigscheme_list(ss []SignatureScheme) !TlsExtension {
	// The "extension_data" field of these extensions contains a SignatureSchemeList value
	// where its values was limited by <2..2^16-2>;
	xs_payload := pack_u16list_with_len[SignatureScheme](ss, 2)!
	return TlsExtension{
		tipe: .signature_algorithms
		data: xs_payload
	}
}
