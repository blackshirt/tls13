module tls13

import encoding.binary
import blackshirt.buffer
import blackshirt.ecdhe

// non-nul key_exchange entry
const min_keyshareentry_size = 5 // 5?

struct KeyShareEntry {
mut:
	group        NamedGroup = .x25519
	key_exchange []u8 // <1..2^16-1>
}

fn new_keyshare_entry(g NamedGroup) !KeyShareEntry {
	c := unsafe { ecdhe.Curve(int(g)) }
	kx := ecdhe.new_exchanger(c)!
	// generates random privkey
	privkey := kx.generate_private_key()!
	pubkey := kx.public_key(privkey)!

	ks := KeyShareEntry{
		group:        g
		key_exchange: pubkey.bytes()!
	}
	return ks
}

@[direct_array_access; inline]
fn (ks KeyShareEntry) pack() ![]u8 {
	// key exchange data should have non-null
	if ks.key_exchange.len < 1 {
		return error('KeyShareEntry length: underflow')
	}
	if ks.key_exchange.len > max_u16 {
		return error('KeyShareEntry length: overflow')
	}
	group := ks.group.pack()!
	mut len := []u8{len: u16size}
	binary.big_endian_put_u16(mut len, u16(ks.data.len))

	mut out := []u8{}
	out << group
	out << len
	out << ks.key_exchange

	return out
}

@[direct_array_access; inline]
fn KeyShareEntry.unpack(b []u8) !KeyShareEntry {
	if b.len < min_keyshareentry_size {
		return error('KeyShareEntry.unpack: underflow')
	}
	mut r := buffer.new_reader(b)

	// read 2 byte group
	g := r.read_u16()!
	group := NamedGroup.from_u16(g)!

	// read data length
	kxlen := r.read_u16()!
	kxdata := r.read_at_least(int(kxlen))!

	return KeyShareEntry{
		group:        group
		key_exchange: kxdata
	}
}

fn (mut kss []KeyShareEntry) append(ke KeyShareEntry) {
	if ke in kss {
		return
	}
	// If one already exists with this type, replace it
	for mut item in kss {
		if item.group == ke.group {
			item.key_exchange = ke.key_exchange
			continue
		}
	}
	// otherwise append
	kss << ke
}

@[direct_array_access]
fn (kse []KeyShareEntry) pack() ![]u8 {
	mut payload := []u8{}
	for k in kse {
		o := k.pack()!
		payload << o
	}
	if payload.len > max_u16 {
		return error('Bad keyshare entry arrays length: overflow')
	}
	mut kse_len := []u8{len: u16size}
	binary.big_endian_put_u16(mut kse_len, u16(payload.len))

	mut out := []u8{}
	out << kse_len
	out << payload

	return out
}

// KeyShareExtension
struct KeyShareExtension {
	msg_type       HandshakeType
	is_hrr         bool
	client_shares  []KeyShareEntry
	selected_group NamedGroup = .x25519
	server_share   KeyShareEntry
}

fn (ks KeyShareExtension) pack() ![]u8 {
	match ks.msg_type {
		.client_hello {
			out := ks.client_shares.pack()!
			return out
		}
		.hello_retry_request {
			out := ks.selected_group.pack()!
			return out
		}
		.server_hello {
			if ks.is_hrr {
				out := ks.selected_group.pack()!
				return out
			}
			return ks.server_share.pack()!
		}
		else {
			return error('Bad msg_type supplied')
		}
	}
}

fn (ks KeyShareExtension) pack_to_extension() !Extension {
	payload := ks.pack()!
	ext := Extension{
		tipe:   .key_share
		length: payload.len
		data:   payload
	}
	return ext
}

fn (ks KeyShareExtension) pack_to_extension_bytes() ![]u8 {
	ext := ks.pack_to_extension()!
	out := ext.pack()!

	return out
}

@[direct_array_access]
fn KeyShareExtension.unpack(b []u8, msg_type HandshakeType, is_hrr bool) !KeyShareExtension {
	ext := Extension.unpack(b)!
	if ext.tipe != .key_share {
		return error('Wrong extension type')
	}
	kse := KeyShareExtension.unpack_from_extension(ext, msg_type, is_hrr)!
	return kse
}

@[direct_array_access]
fn KeyShareExtension.unpack_from_extension(ext Extension, msg_type HandshakeType, is_hrr bool) !KeyShareExtension {
	if ext.tipe != .key_share {
		return error('Wrong extension type')
	}
	kse := KeyShareExtension.unpack_from_extension_payload(ext.data, msg_type, is_hrr)!
	return kse
}

fn KeyShareExtension.unpack_from_extension_payload(data []u8, msg_type HandshakeType, is_hrr bool) !KeyShareExtension {
	// where data is extension.data
	match msg_type {
		.client_hello {
			if data.len < 2 {
				return error('Bad KeyShare for ClientHello bytes: underflow')
			}
			mut r := buffer.new_reader(data)
			length := r.read_u16()!
			rem := r.read_at_least(int(length))!
			mut entries := []KeyShareEntry{}
			mut i := 0
			for i < length {
				e := KeyShareEntry.unpack(rem[i..])!
				entries.append(e)
				i += 2 + 2 + e.data.len
			}
			ksc := KeyShareExtension{
				msg_type:      .client_hello
				is_hrr:        false
				client_shares: entries
			}
			return ksc
		}
		.server_hello {
			if is_hrr {
				// hello_retry_request
				group := NamedGroup.unpack(data)!
				krr := KeyShareExtension{
					msg_type:       .server_hello
					is_hrr:         true
					selected_group: group
				}
				return krr
			} else {
				// server_hello
				server_share := KeyShareEntry.unpack(data)!
				ksh := KeyShareExtension{
					msg_type:     .server_hello
					is_hrr:       false
					server_share: server_share
				}
				return ksh
			}
		}
		.hello_retry_request {
			// hello_retry_request
			group := NamedGroup.unpack(data)!
			krr := KeyShareExtension{
				msg_type:       .hello_retry_request
				is_hrr:         true
				selected_group: group
			}
			return krr
		}
		else {
			return error('bad HandshakeType')
		}
	}
}
