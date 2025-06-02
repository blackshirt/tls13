module tls13

import math
import encoding.binary
import blackshirt.buffer

const max_hkdf_label_length = 255

const max_hkdf_context_length = 255

const tls13_label_prefix = 'tls13 '

// This add support for HKDF-Expand-Label and other machinery for TLS 1.3
// from RFC8446 Section 7.1 Key Schedule and others.
// see https://datatracker.ietf.org/doc/html/rfc8446#section-7.1
// struct {
//      uint16 length = Length;
//      opaque label<7..255> = 'tls13 ' + Label;
//      opaque context<0..255> = Context;
// } HkdfLabel;
//
struct HkdfLabel {
	length      int    // uint16 length = Length;u16
	tls13_label string // ascii string, "tls13 " + label
	context     []u8   // < 255 len
}

// Length value
fn (h HkdfLabel) hkdflabel_length() int {
	mut n := 0

	n += 1
	n += h.tls13_label.bytes().len
	n += 1
	n += h.context.len

	return n
}

fn (h HkdfLabel) packed_length() int {
	mut n := 0
	n += 2
	n += 1
	n += h.tls13_label.bytes().len
	n += 1
	n += h.context.len

	return n
}

// new_hkdf_label creates new HkdfLabel, where label is label string without prefix
fn new_hkdf_label(label string, context []u8, length int) !HkdfLabel {
	combined_label := tls13_label_prefix + label
	hl := HkdfLabel{
		length:      length
		tls13_label: combined_label
		context:     context
	}
	hl.verify()!
	return hl
}

fn (hl HkdfLabel) verify() ! {
	// label should an ascii string
	if !hl.tls13_label.is_ascii() {
		return error('HkdfLabel.tls13_label contains non-ascii string')
	}

	if hl.tls13_label.len > max_hkdf_label_length {
		return error('tls13_label.len exceed limit')
	}
	if hl.context.len > max_hkdf_context_length {
		return error('hkdflabel context.len exceed limit')
	}

	if hl.length > math.max_u16 {
		return error('hl.length exceed limit')
	}
}

fn (hl HkdfLabel) encode() ![]u8 {
	hl.verify()!
	mut out := []u8{}

	// writes hkdf length
	mut ln := []u8{len: 2}
	binary.big_endian_put_u16(mut ln, u16(hl.length))
	out << ln

	// writes label length
	label_length := hl.tls13_label.len // should fit in one byte
	out << u8(label_length)
	out << hl.tls13_label.bytes()

	out << u8(hl.context.len)
	out << hl.context

	return out
}

fn HkdfLabel.decode(b []u8) !HkdfLabel {
	mut r := buffer.new_reader(b)
	// read two bytes length
	length := r.read_u16()!
	// one byte label length
	label_len := r.read_byte()!
	// read label contents
	tls13_label := r.read_at_least(int(label_len))!
	// one byte context len
	ctx_len := r.read_byte()!
	// read context bytes
	ctx := r.read_at_least(int(ctx_len))!

	hklabel := HkdfLabel{
		length:      length
		tls13_label: tls13_label.bytestr()
		context:     ctx
	}
	return hklabel
}
