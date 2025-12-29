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
	tls_aes_128_gcm_sha256            = 0x1301
	tls_aes_256_gcm_sha384            = 0x1302
	tls_chacha20_poly1305_sha256      = 0x1303
	tls_aes_128_ccm_sha256            = 0x1304
	tls_aes_128_ccm_8_sha256          = 0x1305
	tls_empty_renegotiation_info_scsv = 0x00ff
}

@[inline]
fn (c CipherSuite) packlen() int {
	return 2
}

@[inline]
fn (c CipherSuite) pack() ![]u8 {
	if u16(c) > max_u16 {
		return error('CipherSuite exceed limit')
	}
	mut out := []u8{len: 2}
	binary.big_endian_put_u16(mut out, u16(c))
	return out
}

@[direct_array_access; inline]
fn csuite_parse(b []u8) !CipherSuite {
	if b.len != 2 {
		return error('bad ciphersuite data len')
	}
	val := binary.big_endian_u16(b)
	return csuite_from_u16(val)!
}

// csuite_from_u16 creates CipherSuite from u16 value
@[inline]
fn csuite_from_u16(v u16) !CipherSuite {
	if v > max_u16 {
		return error('value exceed limit')
	}
	match v {
		0x1301 { return .tls_aes_128_gcm_sha256 }
		0x1302 { return .tls_aes_256_gcm_sha384 }
		0x1303 { return .tls_chacha20_poly1305_sha256 }
		0x1304 { return .tls_aes_128_ccm_sha256 }
		0x1305 { return .tls_aes_128_ccm_8_sha256 }
		0x00ff { return .tls_empty_renegotiation_info_scsv }
		else { return error('unsupported ciphersuite value') }
	}
}

fn (mut cs []CipherSuite) append(c CipherSuite) {
	if c in cs {
		return
	}
	cs << c
}

fn (cs []CipherSuite) is_exist(c CipherSuite) bool {
	return c in cs
}

fn (cs []CipherSuite) packlen() int {
	return 2 + 2 * cs.len
}

fn (cs []CipherSuite) pack() ![]u8 {
	mut ciphers := []u8{}
	for c in cs {
		o := c.pack()!
		ciphers << o
	}
	if ciphers.len > max_u16 {
		return error('Bad ciphers length')
	}
	mut len := []u8{len: 2}
	binary.big_endian_put_u16(mut len, u16(ciphers.len))

	mut out := []u8{}
	out << len
	out << ciphers

	return out
}

type CipherSuiteList = []CipherSuite

fn CipherSuiteList.unpack(b []u8) !CipherSuiteList {
	if b.len < 2 {
		return error('Bad ciphers length')
	}
	mut r := Buffer.new(b)!
	length := r.read_u16()!
	ciphers_data := r.read_at_least(int(length))!

	mut i := 0
	mut cs := []CipherSuite{}
	for i < ciphers_data.len {
		c := csuite_parseciphers_data[i..i + 2])!
		cs.append(c)
		i += 2
	}
	return CipherSuiteList(cs)
}

// Utility function to simplify other things
fn new_aead_cipher(c CipherSuite) !&chacha20poly1305.AEAD {
	match c {
		// .tls_aes_128_gcm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes_256_gcm_sha384 { return new_transcripter(.sha384) }
		.tls_chacha20_poly1305_sha256 {
			// generates random key and nonce
			key := rand.read(c.key_length()!)!
			// nonce := rand.read(chacha20poly1305.nonce_size)!
			cipher := chacha20poly1305.new(key, chacha20poly1305.nonce_size)!
			return cipher
		}
		//.tls_aes_128_ccm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes_128_ccm_8_sha256 { return new_transcripter(.sha256) }
		else {
			return error('unsupported ciphersuite')
		}
	}
}

fn (c CipherSuite) hasher() crypto.Hash {
	match c {
		.tls_aes_256_gcm_sha384 { return .sha384 }
		else { return .sha256 }
	}
}

fn (c CipherSuite) key_length() !int {
	match c {
		// .tls_aes_128_gcm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes_256_gcm_sha384 { return new_transcripter(.sha384) }
		// TODO: using aead.Cipher.key_size()
		.tls_chacha20_poly1305_sha256 { return 32 }
		//.tls_aes_128_ccm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes_128_ccm_8_sha256 { return new_transcripter(.sha256) }
		else { return error('unsupported ciphersuite') }
	}
}

fn (c CipherSuite) iv_length() !int {
	match c {
		// .tls_aes_128_gcm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes_256_gcm_sha384 { return new_transcripter(.sha384) }
		.tls_chacha20_poly1305_sha256 { return 12 }
		//.tls_aes_128_ccm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes_128_ccm_8_sha256 { return new_transcripter(.sha256) }
		else { return error('unsupported ciphersuite') }
	}
}

fn (c CipherSuite) transcripter() !&Transcripter {
	match c {
		.tls_aes_128_gcm_sha256 { return new_transcripter(.sha256) }
		.tls_aes_256_gcm_sha384 { return new_transcripter(.sha384) }
		.tls_chacha20_poly1305_sha256 { return new_transcripter(.sha256) }
		.tls_aes_128_ccm_sha256 { return new_transcripter(.sha256) }
		.tls_aes_128_ccm_8_sha256 { return new_transcripter(.sha256) }
		else { return error('unsupported hasher') }
	}
}
