module tls13

import math
import encoding.binary
import blackshirt.buffer

// TODO: its depend on curve used
const min_point_coordinate_length = 32

// https://datatracker.ietf.org/doc/html/rfc8446#autoid-101
struct UncompressedPointRepresentation {
	point_length int = min_point_coordinate_length
	legacy_form  u8  = 0x04
	pointx       []u8 // X[coordinate_length]
	pointy       []u8 // Y[coordinate_length]
}

fn (up UncompressedPointRepresentation) pack() ![]u8 {
	mut out := []u8{}

	out << up.legacy_form
	out << up.pointx
	out << up.pointy

	return out
}

fn UncompressedPointRepresentation.unpack(b []u8) !UncompressedPointRepresentation {
	if b.len < 1 + 2 * min_point_coordinate_length {
		return error('bad UncompressedPointRepresentation bytes')
	}
	mut r := buffer.new_reader(b)
	legform := r.read_byte()!
	if legform != u8(0x04) {
		return error('Bad legacy_form')
	}
	pointx := r.read_at_least(min_point_coordinate_length)!
	pointy := r.read_at_least(min_point_coordinate_length)!

	up := UncompressedPointRepresentation{
		legacy_form: legform
		pointx:      pointx
		pointy:      pointy
	}
	return up
}

// PskKeyExchangeMode = u8
enum PskKeyExchangeMode as u8 {
	psk_ke     = 0
	psk_dhe_ke = 1
	//(255)
}

fn (pxm PskKeyExchangeMode) pack() ![]u8 {
	if pxm > max_u8 {
		return error('pxm exceed')
	}
	return [u8(pxm)]
}

fn PskKeyExchangeMode.unpack(b []u8) !PskKeyExchangeMode {
	if b.len != 1 {
		return error('bad PskKeyExchangeMode bytes')
	}
	return PskKeyExchangeMode.from_u8(b[0])!
}

fn PskKeyExchangeMode.from_u8(val u8) !PskKeyExchangeMode {
	match val {
		0x00 { return .psk_ke }
		0x01 { return .psk_dhe_ke }
		else { return error('unsupported PskKeyExchangeMode value') }
	}
}

fn (pxs []PskKeyExchangeMode) packed_length() int {
	mut n := 0
	n += 1
	n += pxs.len

	return n
}

fn (pxs []PskKeyExchangeMode) pack() ![]u8 {
	if pxs.len > math.max_u8 {
		return error('PskKeyExchangeMode list exceed')
	}
	mut out := []u8{}
	out << u8(pxs.len)
	for k in pxs {
		ob := k.pack()!
		out << ob
	}
	return out
}

type PskKeyExchangeModeList = []PskKeyExchangeMode // <1..255>

fn PskKeyExchangeModeList.unpack(b []u8) !PskKeyExchangeModeList {
	if b.len < 1 {
		return error('Bad PskKeyExchangeModeList bytes')
	}
	mut r := buffer.new_reader(b)
	length := r.read_byte()!
	bytes := r.read_at_least(int(length))!
	mut i := 0
	mut pkms := []PskKeyExchangeMode{}
	for i < length {
		kem := PskKeyExchangeMode.unpack(bytes[i..])!
		pkms << kem
		i += 1
	}
	return PskKeyExchangeModeList(pkms)
}

struct Empty {}

fn (e Empty) pack() []u8 {
	return nullbytes
}

struct EarlyDataIndication {
	msg_type        HandshakeType
	max_eadata_size u32
	empty           Empty
	// select (Handshake.msg_type) {
	//  case new_session_ticket:  uint32 max_early_data_size
	// case client_hello:         Empty
	// case encrypted_extensions: Empty
	//}
}

fn (ed EarlyDataIndication) packed_length() int {
	match ed.msg_type {
		.new_session_ticket { return 4 }
		.client_hello, .encrypted_extensions { return 0 }
		else { return error('invalid msg_type of EarlyDataIndication') }
	}
}

fn (ed EarlyDataIndication) pack() ![]u8 {
	match ed.msg_type {
		.new_session_ticket {
			mut max_easize := []u8{len: 4}
			binary.big_endian_put_u32(mut max_easize, ed.max_eadata_size)
			return max_easize
		}
		.client_hello, .encrypted_extensions {
			return ed.empty.pack()
		}
		else {
			return error('bad msg_type')
		}
	}
}

// 4.2.11.  Pre-Shared Key Extension
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
//
struct PskIdentity {
	identity   []u8 // <1..2^16-1>;
	obf_tktage u32
}

@[inline]
fn (psi PskIdentity) packed_length() int {
	return 6 + psi.identity.len
}

@[inline]
fn (psi PskIdentity) pack() ![]u8 {
	if psi.identity.len > max_u16 {
		return error('PskIdentity.identity exceed')
	}
	mut out := []u8{}
	mut pid := []u8{len: 2}
	binary.big_endian_put_u16(mut pid, u16(psi.identity.len))

	out << pid
	out << psi.identity

	mut obt := []u8{len: 4}
	binary.big_endian_put_u32(mut obt, psi.obf_tktage)
	out << obt

	return out
}

@[direct_array_access; inline]
fn PskIdentity.unpack(b []u8) !PskIdentity {
	if b.len < 6 {
		return error('PskIdentity bytes underflow')
	}
	mut r := buffer.new_reader(b)
	idlen := r.read_u16()!
	idb := r.read_at_least(int(idlen))!
	obf := r.read_u32()!

	psi := PskIdentity{
		identity:   idb
		obf_tktage: obf
	}
	return psi
}

// Minimal size = 2 (for length) + 7
const min pskidentitylist_size = 9

type PskIdentityList = []PskIdentity // <7..2^16-1>;

fn (ps []PskIdentity) packed_length() int {
	mut n := 0
	n += 2 // for the length
	for p in ps {
		ln := p.packed_length()
		n += ln
	}
	return n
}

@[direct_array_access; inline]
fn (ps []PskIdentity) pack() ![]u8 {
	mut size := 0
	for p in ps {
		size += p.packed_length()
	}
	if size > max_u16 {
		return error('PskIdentity list exceed')
	}
	mut pslen := []u8{len: 2}
	binary.big_endian_put_u16(mut pslen, u16(size))
	mut out := []u8{}
	out << pslen
	for p in ps {
		obj := p.pack()!
		out << obj
	}
	return out
}

@[direct_array_access; inline]
fn PskIdentityList.unpack(b []u8) !PskIdentityList {
	if b.len < pskidentitylist_size {
		return error('bad PskIdentityList bytes')
	}
	mut r := buffer.new_reader(b)
	length := r.read_u16()!
	bytes := r.read_at_least(int(length))!
	mut pkl := []PskIdentity{}
	mut i := 0
	for i < length {
		obj := PskIdentity.unpack(bytes[i..])!
		pkl << obj
		i += obj.packed_length()
	}
	return PskIdentityList(pkl)
}

const min_pskbinderentry_size = 33 // 1 + 32

type PskBinderEntry = []u8 // <32..255>;

fn (pb PskBinderEntry) packed_length() int {
	return 1 + pb.len
}

@[direct_array_access; inline]
fn (pb PskBinderEntry) pack() ![]u8 {
	if pb.len < 32 || pb.len > 255 {
		return error('PskBinderEntry under or overflow')
	}
	mut out := []u8{}
	out << u8(pb.len)
	out << pb

	return out
}

@[direct_array_access; inline]
fn PskBinderEntry.unpack(b []u8) !PskBinderEntry {
	if b.len < min_pskbinderentry_size {
		return error('PskBinderEntry bytes underflow')
	}
	mut r := buffer.new_reader(b)
	length := r.read_byte()!
	bytes := r.read_at_least(int(length))!
	return PskBinderEntry(bytes)
}

// PskBinderEntryList are arrays of PskBinderEntry
//
const min_pskbinderentrylist_size = 2 + min_pskbinderentry_size

type PskBinderEntryList = []PskBinderEntry // PskBinderEntry binders<33..2^16-1>;

@[direct_array_access; inline]
fn (pbl []PskBinderEntry) packed_length() int {
	mut n := 0
	n += 2
	for p in pbl {
		n += p.packed_length()
	}
	return n
}

@[direct_array_access; inline]
fn (pbl []PskBinderEntry) pack() ![]u8 {
	mut pba := []u8{}
	for p in pbl {
		o := p.pack()!
		pba << o
	}
	if pba.len < 33 || pba.len > max_u16 {
		return error('PskBinderEntry list under or overflow')
	}
	mut out := []u8{}
	mut length := []u8{len: 2}
	binary.big_endian_put_u16(mut length, u16(pba.len))

	out << length
	out << pba

	return out
}



@[direct_array_access; inline]
fn PskBinderEntryList.unpack(b []u8) !PskBinderEntryList {
	if b.len < min_pskbinderentrylist_size {
		return error('bad PskBinderEntryList bytes')
	}
	mut r := buffer.new_reader(b)
	length := r.read_u16()!
	bytes := r.read_at_least(int(length))!

	mut i := 0
	mut pbl := []PskBinderEntry{}
	for i < length {
		o := PskBinderEntry.unpack(bytes[i..])!
		pbl << o
		i += o.packed_length()
	}
	return PskBinderEntryList(pbl)
}

// OfferedPsks
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11

// min = 2 + 7 + 2 + 33
const min_offeredpsks_msg_size = 44

struct OfferedPsks {
	identities []PskIdentity    // <7..2^16-1>;
	binders    []PskBinderEntry // <33..2^16-1>;
}

@[inline]
fn (ofp OfferedPsks) packed_length() int {
	mut n := 0
	n += ofp.identities.packed_length()
	n += ofp.binders.packed_length()
	return n
}

@[direct_array_access; inline]
fn (ofp OfferedPsks) pack() ![]u8 {
	mut out := []u8{}
	out << ofp.identities.pack()!
	out << ofp.binders.pack()!
	return out
}

@[direct_array_access; inline]
fn OfferedPsks.unpack(b []u8) !OfferedPsks {
	if b.len < min_offeredpsks_msg_size {
		return error('bad OfferedPsks bytes')
	}
	mut r := buffer.new_reader(b)
	idn_len := r.peek_u16()!
	idn_bytes := r.read_at_least(int(idn_len) + 2)!
	idn := PskIdentityList.unpack(idn_bytes)!

	bind_len := r.peek_u16()!
	binders_bytes := r.read_at_least(int(bind_len) + 2)!
	binders := PskBinderEntryList.unpack(binders_bytes)!

	ofp := OfferedPsks{
		identities: idn
		binders:    binders
	}
	return ofp
}

struct PreSharedKeyExtension {
	msg_type    HandshakeType = .client_hello
	off_psks    OfferedPsks
	selected_id u16
	// select (Handshake.msg_type) {
	//  case client_hello: OfferedPsks;
	//  case server_hello: uint16 selected_identity;
	// }
}

fn (psx PreSharedKeyExtension) packed_length() !int {
	mut n := 0
	match psx.msg_type {
		.client_hello {
			nc := psx.off_psks.packed_length()
			n += nc
		}
		.server_hello {
			n += 2 // selected_identity
		}
		else {
			return error('bad msg_type for PreSharedKeyExtension')
		}
	}
	return n
}

fn (psx PreSharedKeyExtension) pack() ![]u8 {
	match psx.msg_type {
		.client_hello {
			out := psx.off_psks.pack()!
			return out
		}
		.server_hello {
			mut out := []u8{len: 2}
			binary.big_endian_put_u16(mut out, psx.selected_id)
			return out
		}
		else {
			return error('bad msg_type for PreSharedKeyExtension')
		}
	}
}

fn PreSharedKeyExtension.unpack(b []u8, msg_type HandshakeType) !PreSharedKeyExtension {
	match msg_type {
		.client_hello {
			ofp := OfferedPsks.unpack(b)!
			psx := PreSharedKeyExtension{
				msg_type: msg_type
				off_psks: ofp
			}
			return psx
		}
		.server_hello {
			if b.len != 2 {
				return error('bad bytes for selected_identity')
			}
			val := binary.big_endian_u16(b)
			psx := PreSharedKeyExtension{
				msg_type:    .server_hello
				selected_id: val
			}
			return psx
		}
		else {
			return error('bad msg_type for PreSharedKeyExtension')
		}
	}
}
