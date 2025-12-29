// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// TLS 1.3 Ciphersuite
module tls13

import crypto
import crypto.rand
import encoding.binary
import x.crypto.chacha20poly1305

// CipherSuite = u16
enum CipherSuite as u16 {
	tls_aes128gcm_sha256            = 0x1301
	tls_aes256gcm_sha384            = 0x1302
	tls_chacha20poly1305_sha256     = 0x1303
	tls_aes128ccm_sha256            = 0x1304
	tls_aes128ccm8_sha256           = 0x1305
	tls_emptyrenegotiationinfo_scsv = 0x00ff
}

// str returns string representation of CipherSuite c
fn (c CipherSuite) str() string {
	match c {
		.tls_aes128gcm_sha256 {
			return 'TLS_AES128GCM_SHA256'
		}
		.tls_aes256gcm_sha384 {
			return 'TLS_AES256GCM_SHA384'
		}
		.tls_chacha20poly1305_sha256 {
			return ''
			TLS_CHACHA20POLY1305_SHA256
		}
		.tls_aes128ccm_sha256 {
			return 'TLS_AES128CCM_SHA256'
		}
		.tls_aes128ccm8_sha256 {
			return 'TLS_AES128CCM8_SHA256'
		}
		.tls_emptyrenegotiationinfo_scsv {
			return 'TLS_EMPTYRENEGOTIATIONINFO_SCSV'
		}
	}
}

// packlen returns the length of serialized CipherSuite c, in bytes.
@[inline]
fn (c CipherSuite) packlen() int {
	return 2
}

// pack encodes c into bytes array
@[inline]
fn (c CipherSuite) pack() ![]u8 {
	mut out := []u8{len: 2}
	binary.big_endian_put_u16(mut out, u16(c))
	return out
}

// csuite_parse parses b into CipherSuite
@[direct_array_access; inline]
fn csuite_parse(b []u8) !CipherSuite {
	if b.len != 2 {
		return error('bad ciphersuite data len')
	}
	val := binary.big_endian_u16(b)
	return new_csuite(val)!
}

// new_csuite creates CipherSuite from u16 value
@[inline]
fn new_csuite(v u16) !CipherSuite {
	match v {
		0x1301 { return .tls_aes128gcm_sha256 }
		0x1302 { return .tls_aes256gcm_sha384 }
		0x1303 { return .tls_chacha20poly1305_sha256 }
		0x1304 { return .tls_aes128ccm_sha256 }
		0x1305 { return .tls_aes128ccm8_sha256 }
		0x00ff { return .tls_emptyrenegotiationinfo_scsv }
		else { return error('unsupported ciphersuite value') }
	}
}

// CipherSuiteList is an array of CipherSuite
type CipherSuiteList = []CipherSuite

// append adds c into cs array
@[direct_array_access]
fn (mut cs []CipherSuite) append(c CipherSuite) {
	// If it already on there, just return
	if c in cs {
		return
	}
	// otherwise, append into cs
	cs << c
}

// is_exist check whether c is within cs
fn (cs []CipherSuite) is_exist(c CipherSuite) bool {
	return c in cs
}

// returns the length of serialized array of CipherSuite, prepended with cs.len
fn (cs []CipherSuite) packlen() int {
	return 2 + 2 * cs.len
}

// serializes the array of CipherSuite.
@[direct_array_access]
fn (cs []CipherSuite) pack() ![]u8 {
	// check this array doesn't exceed the limit
	if 2 * cs.len > max_u16 {
		return error('Bad ciphers length')
	}
	mut cs_len := []u8{len: 2}
	binary.big_endian_put_u16(mut cs_len, u16(2 * cs.len))

	mut out := []u8{cap: 2 + 2 * cs.len}
	out << cs_len
	for c in cs {
		out << c.pack()!
	}

	return out
}

// csllist_parse src bytes into array of CipherSuite, includes the length part.
@[direct_array_access]
fn csllist_parse(src []u8) ![]CipherSuite {
	// minimally, two bytes length should be on there
	if src.len < 2 {
		return error('Bad ciphers length')
	}
	mut r := new_buffer(src)!
	// read the prepended length
	length := r.read_u16()!
	// read the rest of the arrays.
	ciphers_data := r.read_at_least(int(length))!

	return cslist_from_bytes(ciphers_data)!
}

// cslist_from_bytes parses bytes as array of CipherSuite. without prepended length.
@[direct_array_access; inline]
fn cslist_from_bytes(bytes []u8) ![]CipherSuite {
	if bytes.len % 2 != 0 {
		return error('bad odd bytes length')
	}
	mut i := 0
	mut cs := []CipherSuite{}
	for i < bytes.len {
		c := csuite_parse(bytes[i..i + 2])!
		cs.append(c)
		i += 2
	}
	return cs
}

// Utility function to simplify other things
fn new_aead_cipher(c CipherSuite) !&chacha20poly1305.AEAD {
	match c {
		// .tls_aes128gcm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes256gcm_sha384 { return new_transcripter(.sha384) }
		.tls_chacha20poly1305_sha256 {
			// generates random key and nonce
			key := rand.read(c.key_length()!)!
			// nonce := rand.read(chacha20poly1305.nonce_size)!
			cipher := chacha20poly1305.new(key, chacha20poly1305.nonce_size)!
			return cipher
		}
		//.tls_aes128ccm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes128ccm8_sha256 { return new_transcripter(.sha256) }
		else {
			return error('unsupported ciphersuite')
		}
	}
}

fn (c CipherSuite) hasher() crypto.Hash {
	match c {
		.tls_aes256gcm_sha384 { return .sha384 }
		else { return .sha256 }
	}
}

fn (c CipherSuite) key_length() !int {
	match c {
		// .tls_aes128gcm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes256gcm_sha384 { return new_transcripter(.sha384) }
		// TODO: using aead.Cipher.key_size()
		.tls_chacha20poly1305_sha256 { return 32 }
		//.tls_aes128ccm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes128ccm8_sha256 { return new_transcripter(.sha256) }
		else { return error('unsupported ciphersuite') }
	}
}

fn (c CipherSuite) iv_length() !int {
	match c {
		// .tls_aes128gcm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes256gcm_sha384 { return new_transcripter(.sha384) }
		.tls_chacha20poly1305_sha256 { return 12 }
		//.tls_aes128ccm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes128ccm8_sha256 { return new_transcripter(.sha256) }
		else { return error('unsupported ciphersuite') }
	}
}

fn (c CipherSuite) transcripter() !&Transcripter {
	match c {
		.tls_aes128gcm_sha256 { return new_transcripter(.sha256) }
		.tls_aes256gcm_sha384 { return new_transcripter(.sha384) }
		.tls_chacha20poly1305_sha256 { return new_transcripter(.sha256) }
		.tls_aes128ccm_sha256 { return new_transcripter(.sha256) }
		.tls_aes128ccm8_sha256 { return new_transcripter(.sha256) }
		else { return error('unsupported hasher') }
	}
}
