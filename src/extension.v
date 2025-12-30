// Copyright ©2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
module tls13

import encoding.binary

const min_extension_size = 4

@[noinit]
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
