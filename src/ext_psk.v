module tls13

import encoding.binary

// 4.2.9.  Pre-Shared Key Exchange Modes
//
// PskKeyExchangeMode = u8
enum PskKeyExchangeMode as u8 {
	psk_ke     = 0
	psk_dhe_ke = 1
	//(255)
}

// new_pskxmode creates a new PskKeyExchangeMode from byte value val
@[inline]
fn new_pskxmode(val u8) !PskKeyExchangeMode {
	match val {
		0x00 { return .psk_ke }
		0x01 { return .psk_dhe_ke }
		else { return error('unsupported PskKeyExchangeMode value') }
	}
}

// struct {
//          PskKeyExchangeMode ke_modes<1..255>;
//     } PskKeyExchangeModes;
type PskKeyExchangeModeList = []PskKeyExchangeMode

@[inline]
fn size_psxmode_list(ks PskKeyExchangeModeList) int {
	return size_u8list_withlen[PskKeyExchangeMode](ks, .size1)
}

@[direct_array_access; inline]
fn pack_psxmode_list(ks PskKeyExchangeModeList) ![]u8 {
	return pack_u8list_withlen[PskKeyExchangeMode](ks, .size1)!
}

// parse_psxmode_list decodes bytes with 1-btye length
@[direct_array_access]
fn parse_psxmode_list(bytes []u8) !PskKeyExchangeModeList {
	if bytes.len < 1 {
		return error('Bad PskKeyExchangeModeList bytes')
	}
	mut r := new_buffer(bytes)!
	length := r.read_u8()!
	kemodes_bytes := r.read_at_least(int(length))!

	mut i := 0
	mut pkms := []PskKeyExchangeMode{cap: int(length)}
	for i < length {
		pkms << new_pskxmode(kemodes_bytes[i])!
		i += 1
	}
	return PskKeyExchangeModeList(pkms)
}

// 4.2.11.  Pre-Shared Key Extension
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11
//
@[noinit]
struct PskIdentity {
mut:
	identity []u8 // <1..2^16-1>;
	tktage   u32
}

// size_pskidentity returns the size of encoded PskIdentity p
@[inline]
fn size_pskidentity(p PskIdentity) int {
	return 6 + psi.identity.len
}

@[inline]
fn pack_pskidentity(p PskIdentity) ![]u8 {
	mut out := []u8{cap: size_pskidentity(p)}
	out << pack_raw_withlen(p.identity, .size2)!
	mut obt := []u8{len: 4}
	binary.big_endian_put_u32(mut obt, psi.tktage)
	out << obt

	return out
}

@[direct_array_access; inline]
fn parse_pskidentity(bytes []u8) !PskIdentity {
	if b.len < 6 {
		return error('PskIdentity bytes underflow')
	}
	mut r := new_buffer(bytes)!
	idlen := r.read_u16()!
	idb := r.read_at_least(int(idlen))!
	obf := r.read_u32()!

	psi := PskIdentity{
		identity: idb
		tktage:   obf
	}
	return psi
}

// Minimal size = 2 (for length) + 7
const min_pskidentitylist_size = 9

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
	if b.len < min_pskidentitylist_size {
		return error('bad PskIdentityList bytes')
	}
	mut r := Buffer.new(b)!
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
	mut r := Buffer.new(b)!
	length := r.read_u8()!
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
	mut r := Buffer.new(b)!
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
	mut r := Buffer.new(b)!
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
