// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// TLS 1.3 SignatureScheem
module tls13

import encoding.binary

// SignatureScheem = u16
enum SignatureScheme as u16 {
	rsa_pkcs1_sha256       = 0x0401
	rsa_pkcs1_sha384       = 0x0501
	rsa_pkcs1_sha512       = 0x0601
	ecdsa_secp256r1_sha256 = 0x0403
	ecdsa_secp384r1_sha384 = 0x0503
	ecdsa_secp521r1_sha512 = 0x0603
	rsa_pssrsae_sha256     = 0x0804
	rsa_pssrsae_sha384     = 0x0805
	rsa_pssrsae_sha512     = 0x0806
	ed25519                = 0x0807
	ed448                  = 0x0808
	rsa_psspss_sha256      = 0x0809
	rsa_psspss_sha384      = 0x080a
	rsa_psspss_sha512      = 0x080b
	rsa_pkcs1_sha1         = 0x0201
	ecdsa_sha1             = 0x0203
}

@[inline]
fn (s SignatureScheme) packlen() int {
	return 2
}

// pack encodes SignatureScheme s into bytes array.
@[inline]
fn (s SignatureScheme) pack() ![]u8 {
	mut out := []u8{len: 2}
	binary.big_endian_put_u16(mut out, u16(s))
	return out
}

// sigscheme_parse parses bytes as SignatureScheme
@[direct_array_access; inline]
fn sigscheme_parse(b []u8) !SignatureScheme {
	if b.len != 2 {
		return error('bad SignatureScheme bytes len')
	}
	val := binary.big_endian_u16(b)
	return new_sigscheme(val)!
}

// new_sigscheme creates SignatureScheme from u16 value
@[inline]
fn new_sigscheme(val u16) !SignatureScheme {
	match val {
		0x0401 {
			return .rsa_pkcs1_sha256
		}
		0x0501 {
			return .rsa_pkcs1_sha384
		}
		0x0601 {
			return .rsa_pkcs1_sha512
		}
		0x0403 {
			return .ecdsa_secp256r1_sha256
		}
		0x0503 {
			return .ecdsa_secp384r1_sha384
		}
		0x0603 {
			return .ecdsa_secp521r1_sha512
		}
		0x0804 {
			return .rsa_pssrsae_sha256
		}
		0x0805 {
			return .rsa_pssrsae_sha384
		}
		0x0806 {
			return .rsa_pssrsae_sha512
		}
		0x0807 {
			return .ed25519
		}
		0x0808 {
			return .ed448
		}
		0x0809 {
			return .rsa_psspss_sha256
		}
		0x080a {
			return .rsa_psspss_sha384
		}
		0x080b {
			return .rsa_psspss_sha512
		}
		0x0201 {
			return .rsa_pkcs1_sha1
		}
		0x0203 {
			return .ecdsa_sha1
		}
		else {
			return error('unsupported SignatureScheme value')
		}
	}
}

// str returns string representation of SignatureScheme s.
fn (s SignatureScheme) str() string {
	match s {
		.rsa_pkcs1_sha256 { return 'RSA_PKCS1_SHA256' }
		.rsa_pkcs1_sha384 { return 'RSA_PKCS1_SHA384' }
		.rsa_pkcs1_sha512 { return 'RSA_PKCS1_SHA512' }
		.ecdsa_secp256r1_sha256 { return 'ECDSA_SECP256R1_SHA256' }
		.ecdsa_secp384r1_sha384 { return 'ECDSA_SECP384R1_SHA384' }
		.ecdsa_secp521r1_sha512 { return 'ECDSA_SECP521R1_SHA512' }
		.rsa_pssrsae_sha256 { return 'RSA_PSSRSAE_SHA256' }
		.rsa_pssrsae_sha384 { return 'RSA_PSSRSAE_SHA384' }
		.rsa_pssrsae_sha512 { return 'RSA_PSSRSAE_SHA512' }
		.ed25519 { return 'ED25519' }
		.ed448 { return 'ED448' }
		.rsa_psspss_sha256 { return 'RSA_PSSPSS_SHA256' }
		.rsa_psspss_sha384 { return 'RSA_PSSPSS_SHA384' }
		.rsa_psspss_sha512 { return 'RSA_PSSPSS_SHA512' }
		.rsa_pkcs1_sha1 { return 'RSA_PKCS1_SHA1' }
		.ecdsa_sha1 { return 'ECDSA_SHA1' }
	}
}

// SignatureSchemeList is an array of SignatureScheme
type SignatureSchemeList = []SignatureScheme

// serialized array of SignatureScheme, includes prepended length
fn (sg []SignatureScheme) packlen() int {
	return 2 + sg.len * 2
}

// append adds s into sg
fn (mut sg []SignatureScheme) append(s SignatureScheme) {
	if s in sg {
		return
	}
	sg << s
}

// serializes sg into bytes array
fn (sg []SignatureScheme) pack() ![]u8 {
	// non-empty signature scheme was unallowed
	if sg.len < 1 {
		return error('SignatureSchemeList length: underflow')
	}
	length := sg.len * 2
	if length > max_u16 {
		return error("SignatureSchemeList length: overflow'")
	}

	mut out := []u8{cap: 2 + length}

	// write 2 byte length
	mut bol := []u8{len: 2}
	binary.big_endian_put_u16(mut bol, u16(length))
	out << bol

	// write SignatureScheme arrays
	for s in sg {
		out << s.pack()!
	}
	return res
}

// sigschemelist_parse parse bytes into array of SignatureScheme, includes the length part.
@[direct_array_access; inline]
fn sigschemelist_parse(b []u8) ![]SignatureScheme {
	// SignatureSchemeList supported_signature_algorithms<2..2^16-2>;
	// tells us that its should contain minimal one signature algorithm or more.
	if b.len < 4 {
		return error('negative len or unfullfilled minimal length')
	}
	mut r := new_buffer(b)!

	// read length part
	length := r.read_u16()!
	bytes := r.read_at_least(int(length))!

	return sigschemelist_from_bytes(bytes)!
}

// sigschemelist_from_bytes parses bytes into array of SignatureScheme, without the length part.
@[direct_array_access]
fn sigschemelist_from_bytes(bytes []u8) ![]SignatureScheme {
	if bytes.len % 2 != 0 {
		return error('even bytes length was needed')
	}
	mut sg := []SignatureScheme{}
	mut i := 0
	for i < bytes.len {
		s := sigscheme_parse(bytes[i..i + 2])!
		sg.append(s)
		i += 2
	}
	return sg
}
