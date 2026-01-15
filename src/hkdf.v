module tls13

import crypto
import encoding.binary
import hkdf

const max_hkdflabel_size = 255
const max_hkdfcontext_size = 255
const label_prefix = 'tls13 '

// HKDF-Expand-Label(Secret, Label, Context, Length) =
//            HKDF-Expand(Secret, HkdfLabel, Length)
//
//     Where HkdfLabel is specified as:
//
//     struct {
//         uint16 length = Length;
//           opaque label<7..255> = "tls13 " + Label;
//         opaque context<0..255> = Context;
//     } HkdfLabel;
//
//     Derive-Secret(Secret, Label, Messages) =
//          HKDF-Expand-Label(Secret, Label, Transcript-Hash(Messages), Hash.length)
//
@[direct_array_access]
fn hkdf_expand_label(h crypto.Hash, secret []u8, label string, context []u8, length int) ![]u8 {
	klabel := new_hklabel(label, context, length)!
	info := klabel.encode()!
	return hkdf.expand(h, secret, info, length)!
}

// This add support for HKDF-Expand-Label and other machinery for TLS 1.3
// from RFC8446 Section 7.1 Key Schedule and others.
// see https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
// struct {
//      uint16 length = Length;
//      opaque label<7..255> = 'tls13 ' + Label;
//      opaque context<0..255> = Context;
// } HkdfLabel;
//
@[noinit]
struct HkdfLabel {
mut:
	length  int    // uint16 length = Length;u16
	label   string // ascii string, "tls13 " + label
	context []u8   // < 255 len
}

// Length value
@[inline]
fn (h HkdfLabel) label_size() int {
	mut n := 0
	n += 1 + h.label.bytes().len
	n += 1 + h.context.len
	return n
}

// encoded size
@[inline]
fn (h HkdfLabel) packed_length() int {
	return 2 + h.label_size()
}

// new_hklabel creates new HkdfLabel, where label is label string without prefix
@[direct_array_access; inline]
fn new_hklabel(label string, context []u8, length int) !HkdfLabel {
	combined_label := label_prefix + label
	hl := HkdfLabel{
		length:  length
		label:   combined_label
		context: context
	}
	hl.verify()!
	return hl
}

@[inline]
fn (hl HkdfLabel) verify() ! {
	// label should an ascii string
	if !hl.label.is_ascii() {
		return error('HkdfLabel.label contains non-ascii string')
	}

	if hl.label.len > max_hkdflabel_size {
		return error('label.len exceed limit')
	}
	if hl.context.len > max_hkdfcontext_size {
		return error('hkdflabel context.len exceed limit')
	}

	if hl.length > max_u16 {
		return error('hl.length exceed limit')
	}
}

@[inline]
fn (hl HkdfLabel) encode() ![]u8 {
	hl.verify()!
	mut out := []u8{cap: hl.packed_length()}

	out << pack_u16item[int](hl.length)
	out << pack_raw(hl.label.bytes(), .size1)!
	out << pack_raw(hl.context, .size1)!

	return out
}

@[direct_array_access]
fn decode_hklabel(b []u8) !HkdfLabel {
	mut r := new_buffer(b)!
	// read two bytes length
	length := r.read_u16()!
	// one byte label length
	label_len := r.read_byte()!
	// read label contents
	label := r.read_at_least(int(label_len))!
	// one byte context len
	ctx_len := r.read_byte()!
	// read context bytes
	ctx := r.read_at_least(int(ctx_len))!

	hklabel := HkdfLabel{
		length:  length
		label:   label.bytestr()
		context: ctx
	}
	return hklabel
}
