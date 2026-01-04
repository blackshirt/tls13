// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// KeyShare TLS 1.3 extension
module tls13

import encoding.binary
import ecdhe

// 4.2.8.  Key Share
//
// non-nul ksdata entry
const min_keyshareentry_size = 5 // 5?

const min_ksdata_size = 1
const max_ksdata_size = max_u16

// struct {
//       NamedGroup group;
//       opaque key_exchange<1..2^16-1>;
//  } KeyShareEntry;
//
@[noinit]
struct KeyShareEntry {
mut:
	// u16-value
	group NamedGroup = .x25519
	// public key bytes
	ksdata []u8 // <1..2^16-1>
}

// new_ksentry creates new KeyShareEntry item.
@[inline]
fn new_ksentry(g NamedGroup, data []u8) !KeyShareEntry {
	if data.len < min_ksdata_size || data.len > max_ksdata_size {
		return error('invalid ksentry data size')
	}

	return KeyShareEntry{
		group:  g
		ksdata: pubkey.bytes()!
	}
}

@[inline]
fn size_ksentry(k KeyShareEntry) int {
	return 2 + size_raw_withlen(k.ksdata, .size2)
}

@[inline]
fn pack_ksentry(k KeyShareEntry) ![]u8 {
	mut out := []u8{cap: size_ksentry(k)}
	out << pack_u16item[NamedGroup](k.group)!
	out << pack_raw_withlen(k.ksdata, .size2)!
	return out
}

@[direct_array_access; inline]
fn pack_ksentries(ks []KeyShareEntry) ![]u8 {
	return pack_objlist[KeyShareEntry](ks, pack_ksentry, size_ksentry)!
}

@[direct_array_access; inline]
fn pack_ksentries_withlen(ks []KeyShareEntry) ![]u8 {
	return pack_objlist_withlen[KeyShareEntry](ks, pack_ksentry, size_ksentry, .size2)!
}

@[direct_array_access; inline]
fn parse_ksentry(b []u8) !KeyShareEntry {
	if b.len < min_keyshareentry_size {
		return error('KeyShareEntry.unpack: underflow')
	}
	mut r := new_buffer(b)!

	// read 2 byte group
	g := r.read_u16()!
	group := new_group(g)!

	// read data length
	kslen := r.read_u16()!
	ksdata := r.read_at_least(int(kslen))!

	return KeyShareEntry{
		group:  group
		ksdata: ksdata
	}
}

@[direct_array_access; inline]
fn parse_ksentries(bytes []u8) ![]KeyShareEntry {
	mut i := 0
	mut ks := []KeyShareEntry{cap: bytes / min_keyshareentry_size}
	for i < bytes.len {
		item := parse_ksentry(bytes[i..])!
		ks.append(item)
		i += size_ksentry
	}
	return ks
}

@[direct_array_access]
fn parse_ksentries_withlen(bytes []u8) ![]u8 {
	mut r := new_buffer(bytes)!

	// length, was u16-sized
	bol2 := r.read_u16()

	ks_bytes := r.read_at_least(int(bol2))!
	return parse_ksentries(ks_bytes)!
}

fn (mut kss []KeyShareEntry) append(ke KeyShareEntry) {
	if ke in kss {
		return
	}
	// If one already exists with this type, replace it
	for mut item in kss {
		if item.group == ke.group {
			item.ksdata = ke.ksdata
			continue
		}
	}
	// otherwise append
	kss << ke
}

// For ClientHello message
// struct {
//    KeyShareEntry client_shares<0..2^16-1>;
// } KeyShareClientHello;
//
// For HelloRetryRequest message
// struct {
//          NamedGroup group;
//      } KeyShareHelloRetryRequest;
//
// For ServerHello message
// struct {
//        KeyShareEntry server_share;
//    } KeyShareServerHello;
//
// KeyShareExtension
//
@[noinit]
struct KeyShareExtension {
mut:
	// underlying msg_type of this key_share extension used
	msg_type HandshakeType
	// for ServerHello type but with hrr magic
	is_hrr bool
	// client_hello message
	client_shares []KeyShareEntry
	// hello_retry_request message
	group NamedGroup = .x25519
	// server_hello message
	server_share KeyShareEntry
}

// pack_ksext encodes KeyShareExtension into bytes array
@[inline]
fn pack_ksext(k KeyShareExtension) ![]u8 {
	match k.msg_type {
		.client_hello {
			return pack_ksentries_withlen(k.client_shares)!
		}
		.server_hello {
			if k.is_hrr {
				// treats as hello_retry_request message
				return pack_u16item[NamedGroup](k.group)!
			}
			// otherwise, its normal server_hello message
			return pack_ksentry(k.server_share)!
		}
		.hello_retry_request {
			return pack_u16item[NamedGroup](k.group)!
		}
		else {
			return error('invalid msg_type for key_share')
		}
	}
}

// parse_ksext decodes bytes into KeyShareExtension for specified msg_type and is_hrr flag
@[direct_array_access; inline]
fn parse_ksext(bytes []u8, msg_type HandshakeType, is_hrr bool) !KeyShareExtension {
	mut kx := KeyShareExtension{}
	match msg_type {
		.client_hello {
			ks := parse_ksentries_withlen(bytes)!
			kx.client_shares = ks
			kx.is_hrr = false
			ks.msg_type = .client_hello
		}
		.server_hello {
			if is_hrr {
				g := parse_u16item[NamedGroup](bytes, new_group)!
				kx.is_hrr = true
				kx.group = g
			} else {
				kx.is_hrr = false
				kx.server_share = parse_ksentry(bytes)!
			}
		}
		.hello_retry_request {
			g := parse_u16item[NamedGroup](bytes, new_group)!
			kx.is_hrr = true
			kx.group = g
		}
		else {
			return error('invalid msg_type param')
		}
	}
	return kx
}
