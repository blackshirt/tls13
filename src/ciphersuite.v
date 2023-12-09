module tls13

import math
import crypto
import encoding.binary
import blackshirt.buffer
import blackshirt.aead

// CipherSuite = u16
enum CipherSuite {
	tls_aes_128_gcm_sha256            = 0x1301
	tls_aes_256_gcm_sha384            = 0x1302
	tls_chacha20_poly1305_sha256      = 0x1303
	tls_aes_128_ccm_sha256            = 0x1304
	tls_aes_128_ccm_8_sha256          = 0x1305
	tls_empty_renegotiation_info_scsv = 0x00ff
}

fn (c CipherSuite) packed_length() int {
	return u16size
}

fn (c CipherSuite) pack() ![]u8 {
	if int(c) > int(math.max_u16) {
		return error('CipherSuite exceed limit')
	}
	mut out := []u8{len: u16size}
	binary.big_endian_put_u16(mut out, u16(c))
	return out
}

fn CipherSuite.unpack(b []u8) !CipherSuite {
	if b.len != 2 {
		return error('bad ciphersuite data len')
	}
	c := binary.big_endian_u16(b)
	return unsafe { CipherSuite(c) }
}

fn CipherSuite.from(v int) !CipherSuite {
	if v > int(math.max_u16) {
		return error('value exceed limit')
	}
	match v {
		0x1301 { return CipherSuite.tls_aes_128_gcm_sha256 }
		0x1302 { return CipherSuite.tls_aes_256_gcm_sha384 }
		0x1303 { return CipherSuite.tls_chacha20_poly1305_sha256 }
		0x1304 { return CipherSuite.tls_aes_128_ccm_sha256 }
		0x1305 { return CipherSuite.tls_aes_128_ccm_8_sha256 }
		0x00ff { return CipherSuite.tls_empty_renegotiation_info_scsv }
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

fn (cs []CipherSuite) packed_length() int {
	mut n := 0
	n += 2
	n += cs.len * 2

	return n
}

fn (cs []CipherSuite) pack() ![]u8 {
	mut ciphers := []u8{}
	for c in cs {
		o := c.pack()!
		ciphers << o
	}
	if ciphers.len > int(math.max_u16) {
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
	mut r := buffer.new_reader(b)
	length := r.read_u16()!
	ciphers_data := r.read_at_least(int(length))!

	mut i := 0
	mut cs := []CipherSuite{}
	for i < ciphers_data.len {
		c := CipherSuite.unpack(ciphers_data[i..i + u16size])!
		cs.append(c)
		i += 2
	}
	return CipherSuiteList(cs)
}

// Utility function to simplify others
fn new_aead_cipher(c CipherSuite) !&aead.Cipher {
	match c {
		// .tls_aes_128_gcm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes_256_gcm_sha384 { return new_transcripter(.sha384) }
		.tls_chacha20_poly1305_sha256 { return aead.new_default_chacha20poly1305_cipher() }
		//.tls_aes_128_ccm_sha256 { return new_transcripter(.sha256) }
		//.tls_aes_128_ccm_8_sha256 { return new_transcripter(.sha256) }
		else { return error('unsupported ciphersuite') }
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
