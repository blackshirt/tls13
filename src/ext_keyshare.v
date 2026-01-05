// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// KeyShare TLS 1.3 extension
module tls13

// 4.2.8.  Key Share
//
// For ClientHello message,
// struct {
//    KeyShareEntry client_shares<0..2^16-1>;
// } KeyShareClientHello;
//
// For HelloRetryRequest message,
// struct {
//          NamedGroup group;
//      } KeyShareHelloRetryRequest;
//
// For ServerHello message,
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
			kx.client_shares = parse_ksentries_withlen(bytes)!
			kx.is_hrr = false
			ks.msg_type = .client_hello
		}
		.server_hello {
			if is_hrr {
				g := parse_u16item[NamedGroup](bytes, new_group)!
				kx.is_hrr = true
				kx.group = g
				kx.msg_type = msg_type
			} else {
				kx.is_hrr = false
				kx.server_share = parse_ksentry(bytes)!
				kx.msg_type = .server_hello
			}
		}
		.hello_retry_request {
			kx.group = parse_u16item[NamedGroup](bytes, new_group)!
			kx.is_hrr = true
			kx.msg_type = .hello_retry_request
		}
		else {
			return error('invalid msg_type param')
		}
	}
	return kx
}

// non-nul ksdata entry
const min_ksentry_size = 5 // 5?

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
		ksdata: data
	}
}

// size_ksentry returns the size of serialized KeyShareEntry k, in bytes.
@[inline]
fn size_ksentry(k KeyShareEntry) int {
	return 2 + size_raw_withlen(k.ksdata, .size2)
}

// pack_ksentry encodes KeyShareEntry k into bytes array
@[inline]
fn pack_ksentry(k KeyShareEntry) ![]u8 {
	mut out := []u8{cap: size_ksentry(k)}
	out << pack_u16item[NamedGroup](k.group)!
	out << pack_raw_withlen(k.ksdata, .size2)!
	return out
}

// pack_ksentries encodes array of KeyShareEntry into bytes array, without the length
@[direct_array_access; inline]
fn pack_ksentries(ks []KeyShareEntry) ![]u8 {
	return pack_objlist[KeyShareEntry](ks, pack_ksentry, size_ksentry)!
}

// pack_ksentries_withlen encodes array of KeyShareEntry into bytes array with 2-bytes length
@[direct_array_access; inline]
fn pack_ksentries_withlen(ks []KeyShareEntry) ![]u8 {
	return pack_objlist_withlen[KeyShareEntry](ks, pack_ksentry, size_ksentry, .size2)!
}

// parse_ksentry decodes bytes b into KeyShareEntry
@[direct_array_access; inline]
fn parse_ksentry(b []u8) !KeyShareEntry {
	if b.len < min_ksentry_size {
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

// parse_ksentries decodes bytes into array of KeyShareEntry, without the length 	
@[direct_array_access; inline]
fn parse_ksentries(bytes []u8) ![]KeyShareEntry {
	mut i := 0
	mut ks := []KeyShareEntry{cap: bytes / min_ksentry_size}
	for i < bytes.len {
		item := parse_ksentry(bytes[i..])!
		ks.append(item)
		i += size_ksentry
	}
	return ks
}

// parse_ksentries_withlen decodes bytes into array of KeyShareEntry with 2-bytes length
@[direct_array_access]
fn parse_ksentries_withlen(bytes []u8) ![]KeyShareEntry {
	mut r := new_buffer(bytes)!

	// length, was u16-sized
	bol2 := r.read_u16()

	ks_bytes := r.read_at_least(int(bol2))!
	return parse_ksentries(ks_bytes)!
}

// append adds KeyShareEntry item ke into array of KeyShareEntry
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
