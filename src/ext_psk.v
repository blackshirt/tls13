// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Pre-Shared Key Extension
module tls13

import encoding.binary

// 4.2.11.  Pre-Shared Key Extension
//
// The "pre_shared_key" extension is used to negotiate the identity of
// the pre-shared key to be used with a given handshake in association
// with PSK key establishment.
// The "extension_data" field of this extension contains a "PskExtension" value
//
const min_pskext_size = 2

// PskExtension
//
@[noinit]
struct PskExtension {
mut:
	msg_type HandshakeType
	off_psks OfferedPsks
	selected u16
	// select (Handshake.msg_type) {
	//  case client_hello: OfferedPsks;
	//  case server_hello: uint16 selected_identity;
	// }
}

// ext_from_psk creates a new Extension from pre_shared_key extension p
@[inline]
fn ext_from_psk(p PskExtension) !Extension {
	return Extension{
		tipe: .pre_shared_key
		data: pack_pskext(p)!
	}
}

// size_pskext returns the size of encoded PskExtension p. Its depends on msg_type of this PskExtension.
@[inline]
fn size_pskext(p PskExtension) int {
	match p.msg_type {
		.client_hello {
			return size_offeredpsks(p.off_psks)
		}
		// the size of p.selected part
		.server_hello, .hello_retry_request {
			return 2
		}
		else {
			panic('invalid msg_type ofr pre_shared_key extension')
		}
	}
}

// pack_pskext encodes PskExtension p into bytes array
@[inline]
fn pack_pskext(p PskExtension) ![]u8 {
	match p.msg_type {
		.client_hello {
			return pack_offeredpsks(p.off_psks)!
		}
		.server_hello, .hello_retry_request {
			return pack_u16item[u16](p.selected)
		}
		else {
			return error('bad msg_type for PskExtension')
		}
	}
}

// parse_pskext decodes b into PskExtension for specified msg_type
@[direct_array_access; inline]
fn parse_pskext(b []u8, msg_type HandshakeType) !PskExtension {
	match msg_type {
		.client_hello {
			return PskExtension{
				msg_type: .client_hello
				off_psks: parse_offeredpsks(b)!
			}
		}
		.server_hello, .hello_retry_request {
			if b.len < min_pskext_size {
				return error('bytes underflow for pre_shared_key extension')
			}
			return PskExtension{
				msg_type: msg_type
				selected: binary.big_endian_u16(b)
			}
		}
		else {
			return error('bad msg_type for PskExtension')
		}
	}
}

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

// size_psxmode_list returns the size of array of PskKeyExchangeMode
@[inline]
fn size_psxmode_list(ks []PskKeyExchangeMode) int {
	return size_u8list_withlen[PskKeyExchangeMode](ks, .size1)
}

// pack_psxmode_list encodes array of PskKeyExchangeMode into bytes array
@[direct_array_access; inline]
fn pack_psxmode_list(ks []PskKeyExchangeMode) ![]u8 {
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
const min_pskidentity_size = 6

// PskIdentity
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

// pack_pskidentity encodes PskIdentity p into bytes array
@[inline]
fn pack_pskidentity(p PskIdentity) ![]u8 {
	mut out := []u8{cap: size_pskidentity(p)}
	out << pack_raw_withlen(p.identity, .size2)!
	mut obt := []u8{len: 4}
	binary.big_endian_put_u32(mut obt, psi.tktage)
	out << obt

	return out
}

// parse_pskidentity decodes bytes into PskIdentity
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
const min_pskidentitylist_size = 7

type PskIdentityList = []PskIdentity // <7..2^16-1>;

// size_pskidentity_list returns the size of encoded ps included 2-bytes length
@[direct_array_access; inline]
fn size_pskidentity_list(ps []PskIdentity) int {
	return size_objlist_withlen[PskIdentity](ps, size_pskidentity, .size2)
}

// pack_pskidentity_list encodes ps into bytes array, included 2-bytes length
@[direct_array_access; inline]
fn pack_pskidentity_list(ps []PskIdentity) ![]u8 {
	return pack_objlist_withlen[PskIdentity](ps, pack_pskidentity, size_pskidentity, .size2)!
}

// parse_pskidentities_nolen decodes bytes into array of PskIdentity without the length
@[direct_array_access; inline]
fn parse_pskidentities_nolen(bytes []u8) ![]PskIdentity {
	if bytes.len < min_pskidentitylist_size {
		return error('bad PskIdentityList bytes')
	}
	mut ps := []PskIdentity{cap: bytes.len / min_pskidentity_size}
	mut i := 0
	for i < bytes {
		item := parse_pskidentity(bytes[i..])!
		ps << item
		i += size_pskidentity(item)
	}
	return ps
}

// parse_pskidentity_list decodes bytes into array of PskIdentity with 2-bytes length
@[direct_array_access; inline]
fn parse_pskidentity_list(bytes []u8) ![]PskIdentity {
	mut r := new_buffer(bytes)!
	// read 2-btyes length
	ps_len2 := r.read_u16()!
	ps_bytes := r.read_at_least(int(ps_len2))!

	return parse_pskidentities_nolen(ps_bytes)!
}

// PskBinderEntry
//
const min_pskbinderentry_size = 32

type PskBinderEntry = []u8 // <32..255>;

// size_bdentry returns the size of encoded PskBinderEntry b
@[inline]
fn size_bdentry(b PskBinderEntry) int {
	return 1 + pb.len
}

// pack_bdentry encodes PskBinderEntry b into bytes array
@[direct_array_access; inline]
fn pack_bdentry(b PskBinderEntry) ![]u8 {
	mut out := []u8{cap: size_bdentry(b)}
	out << u8(pb.len)
	out << pb

	return out
}

// parse_bdentry decodes bytes into PskBinderEntry
@[direct_array_access; inline]
fn parse_bdentry(b []u8) !PskBinderEntry {
	if b.len < min_pskbinderentry_size {
		return error('PskBinderEntry bytes underflow')
	}
	mut r := new_buffer(b)!
	length := r.read_u8()!
	bytes := r.read_at_least(int(length))!

	return PskBinderEntry(bytes)
}

// PskBinderEntryList are arrays of PskBinderEntry
//
const min_pskbinderentrylist_size = 2 + min_pskbinderentry_size

type PskBinderEntryList = []PskBinderEntry // PskBinderEntry binders<33..2^16-1>;

// size_bdentry_list the size of encoded ps included 2-bytes length
@[direct_array_access; inline]
fn size_bdentry_list(ps []PskBinderEntry) int {
	return size_objlist_withlen[PskBinderEntry](ps, size_bdentry, .size2)
}

// pack_bdentry_list encodes ps into bytes array with 2-bytes length
@[direct_array_access; inline]
fn pack_bdentry_list(ps []PskBinderEntry) ![]u8 {
	return pack_objlist_withlen[PskBinderEntry](ps, pack_bdentry, size_bdentry, .size2)!
}

// parse_bdentry_list_direct oarses bytes into array of PskBinderEntry directly, without the length part.
@[direct_array_access; inline]
fn parse_bdentry_list_direct(bytes []u8) ![]PskBinderEntry {
	mut i := 0
	mut ps := []PskBinderEntry{cap: bytes / min_pskbinderentry_size}
	for i < bytes.len {
		item := parse_bdentry(bytes[i..])!
		ps << item
		i += size_bdentry(item)
	}
	return ps
}

// parse_bdentry_list decodes bytes into array of PskBinderEntry with 2-bytes length
@[direct_array_access; inline]
fn parse_bdentry_list(bytes []u8) ![]PskBinderEntry {
	if b.len < min_pskbinderentrylist_size {
		return error('bad PskBinderEntryList bytes')
	}
	mut r := new_buffer(b)!
	length := r.read_u16()!
	bytes_data := r.read_at_least(int(length))!

	return parse_bdentry_list_direct(bytes_data)!
}

// OfferedPsks
//
// https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11

// min = 2 + 7 + 2 + 33
const min_offeredpsks_size = 44

@[noinit]
struct OfferedPsks {
mut:
	identities []PskIdentity    // <7..2^16-1>;
	binders    []PskBinderEntry // <33..2^16-1>;
}

// size_offeredpsks returns the size of encoded OfferedPsks o
@[inline]
fn size_offeredpsks(o OfferedPsks) int {
	mut n := 0
	n += size_pskidentity_list(o.identities)
	n += size_bdentry_list(o.binders)
	return n
}

// pack_offeredpsks encodes OfferedPsks o into bytes array
@[direct_array_access; inline]
fn pack_offeredpsks(o OfferedPsks) ![]u8 {
	mut out := []u8{cap: size_offeredpsks(o)}
	out << pack_pskidentity_list(o.identities)!
	out << pack_bdentry_list(o.binders)!
	return out
}

// parse_offeredpsks decodes bytes into OfferedPsks
@[direct_array_access; inline]
fn parse_offeredpsks(b []u8) !OfferedPsks {
	if b.len < min_offeredpsks_size {
		return error('bad OfferedPsks bytes')
	}
	mut r := new_buffer(b)!

	// read identities
	ident_len := r.peek_u16()!
	ident_bytes := r.read_at_least(int(idn_len))!
	identities := parse_pskidentities_nolen(ident_bytes)!

	// read binders
	binders_len := r.peek_u16()!
	binders_bytes := r.read_at_least(int(binders_len))!
	binders := parse_bdentry_list_direct(binders_bytes)!

	return OfferedPsks{
		identities: identities
		binders:    binders
	}
}
