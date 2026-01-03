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
	tipe ExtensionType // u16 value
	data []u8          // <0..2^16-1>
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
	// serialize ExtensionType, its a u16 value
	out << pack_u16item[ExtensionType](r.tipe)

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

	// read ExtensionType
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
fn (xs []Extension) filtered_by_tipe(tipe ExtensionType) []Extension {
	return xs.filter(it.tipe == tipe)
}

// returns if only single valid result filtered by tipe
@[direct_array_access]
fn (xs []Extension) validate_with_filter(tipe ExtensionType) ![]Extension {
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
fn ext_from_sigscheme_list(ss []SignatureScheme) !Extension {
	// The "extension_data" field of these extensions contains a SignatureSchemeList value
	// where its values was limited by <2..2^16-2>;
	xs_payload := pack_u16list_with_len[SignatureScheme](ss, .size2)!
	return Extension{
		tipe: .signature_algorithms
		data: xs_payload
	}
}
