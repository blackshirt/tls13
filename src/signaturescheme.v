module tls13

import math
import encoding.binary
import blackshirt.buffer

// SignatureScheem = u16
enum SignatureScheme {
	// RSASSA-PKCS1-v1_5 algorithms
	rsa_pkcs1_sha256       = 0x0401
	rsa_pkcs1_sha384       = 0x0501
	rsa_pkcs1_sha512       = 0x0601
	// ECDSA algorithms
	ecdsa_secp256r1_sha256 = 0x0403
	ecdsa_secp384r1_sha384 = 0x0503
	ecdsa_secp521r1_sha512 = 0x0603
	// RSASSA-PSS algorithms with public key OID rsaEncryption
	rsa_pss_rsae_sha256    = 0x0804
	rsa_pss_rsae_sha384    = 0x0805
	rsa_pss_rsae_sha512    = 0x0806
	// EdDSA algorithms
	ed25519                = 0x0807
	ed448                  = 0x0808
	// RSASSA-PSS algorithms with public key OID RSASSA-PSS
	rsa_pss_pss_sha256     = 0x0809
	rsa_pss_pss_sha384     = 0x080a
	rsa_pss_pss_sha512     = 0x080b
	// Legacy algorithms
	rsa_pkcs1_sha1         = 0x0201
	ecdsa_sha1             = 0x0203
}

fn (s SignatureScheme) packed_length() int {
	return u16size
}

fn (sig SignatureScheme) pack() ![]u8 {
	if int(sig) > int(math.max_u16) {
		return error('SignatureScheme exceed limit')
	}
	mut out := []u8{len: u16size}
	binary.big_endian_put_u16(mut out, u16(sig))
	return out
}

fn SignatureScheme.unpack(b []u8) !SignatureScheme {
	if b.len != 2 {
		return error('bad SignatureScheme bytes len')
	}
	v := binary.big_endian_u16(b)
	return unsafe { SignatureScheme(v) }
}

type SignatureSchemeList = []SignatureScheme

fn (sgl SignatureSchemeList) packed_length() int {
	mut n := 0
	n += 2
	n += sgl.len * u16size
	return n
}

fn (mut sgl SignatureSchemeList) append(sg SignatureScheme) {
	if sg in sgl {
		return
	}
	sgl << sg
}

fn (sgl SignatureSchemeList) pack() ![]u8 {
	if sgl.len < 1 {
		return error('SignatureSchemeList length: underflow')
	}
	length := sgl.len * u16size
	if length + 1 > int(math.max_u16) {
		return error("SignatureSchemeList length: overflow'")
	}

	mut res := []u8{}

	// write 2 byte length
	mut bol := []u8{len: u16size}
	binary.big_endian_put_u16(mut bol, u16(length))
	res << bol

	// write SignatureSchemeList arrays
	for s in sgl {
		o := s.pack()!
		res << o
	}
	return res
}

fn SignatureSchemeList.unpack(b []u8) !SignatureSchemeList {
	// SignatureSchemeList supported_signature_algorithms<2..2^16-2>;
	// tells us that its should contain minimal one signature algorithm or more.
	if b.len < 4 {
		return error('negative len or unfullfilled minimal length')
	}
	mut r := buffer.new_reader(b)

	// read length part
	n := r.read_u16()!

	bytes := r.read_at_least(int(n))!

	mut sgl := SignatureSchemeList([]SignatureScheme{})
	mut i := 0
	for i < bytes.len {
		buf := bytes[i..i + u16size]
		sg := SignatureScheme.unpack(buf)!
		sgl.append(sg)
		i += u16size
	}
	return sgl
}

fn (sse SignatureSchemeList) pack_to_extension() !Extension {
	signs := sse.pack()!
	ext := Extension{
		tipe: .signature_algorithms
		length: signs.len
		data: signs
	}
	return ext
}

fn (sse SignatureSchemeList) pack_to_extension_bytes() ![]u8 {
	ext := sse.pack_to_extension()!
	out := ext.pack()!

	return out
}

fn SignatureSchemeList.unpack_from_extension_bytes(b []u8) !SignatureSchemeList {
	ext := Extension.unpack(b)!
	if ext.tipe != .signature_algorithms {
		return error('Wong extension type')
	}

	signs := SignatureSchemeList.unpack(ext.data)!
	return signs
}
