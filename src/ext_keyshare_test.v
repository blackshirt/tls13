// Copyright © 2025 blackshirt.
// Use of this source code is governed by an MIT license
// that can be found in the LICENSE file.
//
// Most of the test materials was taken from https://tls13.xargs.org/
// Credits to original author
module tls13

// test for encode (decode) keyshare extension from client hello extension list
fn test_keyshareextension_from_clienthello_encode_decode() ! {
	// 00 33 00 26 00 24 00 1d 00 20 35 80 72 d6 36 58 80 d1 ae ea 32 9a df 91 21 38 38 51 ed 21 a2 8e 3b 75 e9 65 d0 d2 cd 16 62 54
	// Extension - Key Share
	// 00 33 - assigned value for extension "Key Share"
	// 00 26 - 0x26 (38) bytes of "Key Share" extension data follows
	// 00 24 - 0x24 (36) bytes of key share data follows
	// 00 1d - assigned value for x25519 (key exchange via curve25519)
	// 00 20 - 0x20 (32) bytes of public key follows
	// 35 80 ... 62 54 - public key from the step "Client Key Exchange Generation"
	data := [u8(0x00), 0x33, 0x00, 0x26, u8(0x00), 0x24, 0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72,
		0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51,
		0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54]

	pubkey_bytes := [u8(0x35), 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a,
		0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0,
		0xd2, 0xcd, 0x16, 0x62, 0x54]

	ext := parse_ext(data)!
	assert ext.tipe == .key_share
	assert ext.data.len == 38

	clksh := parse_ksext(ext.data, .client_hello, false)!
	assert clksh.msg_type == .client_hello
	assert clksh.client_shares.len == 1

	group0 := clksh.client_shares[0]
	assert group0.group == .x25519
	assert group0.ksdata.len == 32
	assert group0.ksdata == pubkey_bytes

	// serialize it back
	ks_back := ext_from_ksext(clksh)!
	ks_out := pack_ext(ks_back)!
	assert ks_out == data
}

// test for encode (decode) keyshare extension from server hello extension list
fn test_keyshareextension_encode_decode_for_serverhello() ! {
	// https://tls13.xargs.org/#server-hello
	// 00 33 00 24 00 1d 00 20 9f d7 ad 6d cf f4 29 8d d3 f9 6d 5b 1b 2a f9 10 a0 53 5b 14 88 d7 f8 fa bb 34 9a 98 28 80 b6 15
	// Extension - Key Share
	// 00 33 - assigned value for extension "Key Share"
	// 00 24 - 0x24 (36) bytes of "Key Share" extension data follows
	// 00 1d - assigned value for x25519 (key exchange via curve25519)
	// 00 20 - 0x20 (32) bytes of public key follows
	// 9f d7 ... b6 15 - public key from the step "Server Key Exchange Generation"
	data := [u8(0x00), 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x9f, 0xd7, 0xad, 0x6d, 0xcf,
		0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14,
		0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15]

	// test with KeyShareExtension
	ext := parse_ext(data)!
	assert ext.tipe == .key_share
	assert ext.data.len == 0x24 // 36

	slksh := parse_ksext(ext.data, .server_hello, false)!
	assert slksh.msg_type == .server_hello
	assert slksh.client_shares.len == 0
	assert slksh.group == .x25519
	assert slksh.is_hrr == false

	assert slksh.server_share.group == .x25519
	assert slksh.server_share.ksdata.len == 32
	assert slksh.server_share.ksdata == [u8(0x9f), 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3,
		0xf9, 0x6d, 0x5b, 0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa,
		0xbb, 0x34, 0x9a, 0x98, 0x28, 0x80, 0xb6, 0x15]

	// serialize it back
	ks_back := ext_from_ksext(slksh)!
	ks_out := pack_ext(ks_back)!
	assert ks_out == data
}
