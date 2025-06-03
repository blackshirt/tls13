module tls13

import encoding.binary
import blackshirt.buffer

// NameType = u8
enum NameType as u8 {
	host_name    = 0x00
	unknown_name = 0xff
	// .. (255)
}

@[inline]
fn NameType.from_u8(val u8) !NameType {
	match val {
		0x00 { return .host_name }
		0xff { return .unknown_name }
		else { return error('unsupported NameType value') }
	}
}

@[inline]
fn (n NameType) pack() ![]u8 {
	if n > max_u8 {
		return error('NameType exceed limit')
	}
	return [u8(n)]
}

@[direct_array_access; inline]
fn NameType.unpack(b []u8) !NameType {
	if b.len != 1 {
		return error('bad b.len for NameType')
	}

	return NameType.from_u8(b[0])!
}

// https://datatracker.ietf.org/doc/html/rfc6066#section-3

// opaque HostName<1..2^16-1>
type Hostname = []u8

fn (h Hostname) str() string {
	return h.bytestr()
}

@[direct_array_access; inline]
fn (h Hostname) pack() ![]u8 {
	if h.len <= 0 || h.len > max_u16 {
		return error('invalid hostname length')
	}
	mut out := []u8{}
	mut bol := []u8{len: 2}
	binary.big_endian_put_u16(mut bol, u16(h.len))
	out << bol
	out << h

	return out
}

@[direct_array_access; inline]
fn Hostname.unpack(b []u8) !Hostname {
	mut r := buffer.new_reader(b)
	// read length
	length := r.read_u16()!
	bytes := r.read_at_least(int(length))!

	return unsafe { Hostname(bytes) }
}

struct ServerName {
	name_type NameType
mut:
	name []u8
}

// new server name identification (SNI)
fn new_server_name(name string) !ServerName {
	if !name.is_ascii() {
		return error('not ASCII encoded byte string')
	}
	return ServerName{
		name_type: .host_name
		name:      name.bytes()
	}
}

fn new_hostname(host []u8) !ServerName {
	if !host.bytestr().is_ascii() {
		return error('not ASCII encoded')
	}
	return ServerName{
		name_type: .host_name
		name:      host
	}
}

fn (sn ServerName) packed_length() int {
	mut n := 0
	n += 1
	n += 2
	n += sn.name.len

	return n
}

fn (sn ServerName) pack() ![]u8 {
	mut out := []u8{}
	nt := sn.name_type.pack()!
	out << nt

	match sn.name_type {
		.host_name {
			if sn.name.len < 1 || sn.name.len > math.max_u16 {
				return error('ServerName.name.len underflow or overflow')
			}
			mut hlen := []u8{len: 2}
			binary.big_endian_put_u16(mut hlen, u16(sn.name.len))
			out << hlen
			out << sn.name
		}
		else {
			return error('unsupported name_type')
		}
	}
	return out
}

@[direct_array_access; inline]
fn ServerName.unpack(b []u8) !ServerName {
	if b.len < 2 {
		return error('Bad ServerName.unpack bytes')
	}
	mut r := buffer.new_reader(b)

	// read name_type
	nt := r.read_byte()!
	if nt != u8(NameType.host_name) {
		return error('unsupported NameType')
	}
	// read host_name length
	n := r.read_u16()!
	hostname := r.read_at_least(int(n))!

	sv := ServerName{
		name_type: unsafe { NameType(nt) }
		name:      hostname
	}

	return sv
}

// ServerName server_name_list<1..2^16-1>
type ServerNameList = []ServerName

fn (mut snlist ServerNameList) append(sn ServerName) {
	if sn in snlist {
		return
	}
	// If one already exists with this type, replace it
	// The ServerNameList MUST NOT contain more than one name of the same name_type
	for mut item in snlist {
		if item.name_type == sn.name_type {
			item.name = sn.name
			continue
		}
	}
	// otherwise append
	snlist << sn
}

fn (snlist ServerNameList) packed_length() int {
	mut n := 0
	n += 2
	for sn in snlist {
		n += sn.packed_length()
	}

	return n
}

fn (snlist ServerNameList) pack() ![]u8 {
	mut svn := []u8{}
	for sn in snlist {
		s := sn.pack()!
		svn << s
	}
	if svn.len > math.max_u16 {
		return error('ServerNameList length exceed limit')
	}

	mut snlen := []u8{len: 2}
	binary.big_endian_put_u16(mut snlen, u16(svn.len))

	mut out := []u8{}
	out << snlen
	out << svn

	return out
}

@[direct_array_access; inline]
fn ServerNameList.unpack(b []u8) !ServerNameList {
	if b.len < 3 {
		return error('ServerNameList.unpack: bad bytes')
	}
	mut r := buffer.new_reader(b)
	// read ServerNameList length
	length := r.read_u16()!
	sn_bytes := r.read_at_least(int(length))!

	mut snl := ServerNameList([]ServerName{})
	mut i := 0
	for i < length {
		sn := ServerName.unpack(sn_bytes[i..])!
		snl.append(sn)
		i += 1
		i += 2
		i += sn.name.len
	}

	return snl
}

// The "data" field of this "server_name" extension
// SHALL contain encoded "ServerNameList" payload.
fn (se ServerNameList) pack_to_extension() !Extension {
	payload := se.pack()!
	ext := Extension{
		tipe:   .server_name
		length: payload.len
		data:   payload
	}
	return ext
}

fn ServerNameList.unpack_from_extension(b []u8) !ServerNameList {
	ext := Extension.unpack(b)!
	if ext.tipe != .server_name {
		return error('Wrong extension type')
	}
	snlist := ServerNameList.unpack(ext.data)!
	return snlist
}
