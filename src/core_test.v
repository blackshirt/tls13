module tls13

// test CipherSuite things
fn test_ciphersuites_decode_encode() ! {
	// data was taken from https://tls13.xargs.org/#client-hello/annotated
	// 00 08 13 02 13 03 13 01 00 ff
	data := [u8(0x00), 0x08, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0x00, 0xff]
	// cs := CipherSuiteList.unpack(data)!
	cs := parse_u16list_withlen[CipherSuite](data, new_csuite, .size2)!
	assert cs.len == 4
	assert cs[0] == .tls_aes_256_gcm_sha384
	assert cs[1] == .tls_chacha20_poly1305_sha256
	assert cs[2] == .tls_aes_128_gcm_sha256
	assert cs[3] == .tls_empty_renegotiation_info_scsv

	// encodes it back
	cs_back := pack_u16list_withlen[CipherSuite](cs, .size2)!
	assert cs_back == data
}

// The material was taken from https://tls13.xargs.org/#client-hello/annotated
// on supported groups extension data
fn test_supportedgroupextension_decode_encode() ! {
	// The data as follows:
	// 		00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19 00 18 01 00 01 01 01 02 01 03 01 04
	//
	// This list is presented in descending order of the client's preference.
	// 00 0a - assigned value for extension "supported groups"
	// 00 16 - 0x16 (22) bytes of "supported group" extension data follows
	// 00 14 - 0x14 (20) bytes of data are in the curves list
	// 00 1d - assigned value for the curve "x25519"
	// 00 17 - assigned value for the curve "secp256r1"
	// 00 1e - assigned value for the curve "x448"
	// 00 19 - assigned value for the curve "secp521r1"
	// 00 18 - assigned value for the curve "secp384r1"
	// 01 00 - assigned value for the curve "ffdhe2048"
	// 01 01 - assigned value for the curve "ffdhe3072"
	// 01 02 - assigned value for the curve "ffdhe4096"
	// 01 03 - assigned value for the curve "ffdhe6144"
	// 01 04 - assigned value for the curve "ffdhe8192"
	//
	bytes := [u8(0x00), 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00,
		0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04]

	ext := parse_ext(bytes)!
	assert ext.tipe == .supported_groups
	assert ext.data.len == 22

	groups := parse_namegroup_list(ext.data)!
	assert groups.len == 10
	groups[0] = .x25519

	// pack group back
	groups_back := pack_namegroup_list(groups)!
	assert groups_back == ext.data

	// make an supported_groups  extension, and pack it back
	groups_ext := ext_from_namegroups(groups)!

	bytes_back := pack_ext(groups_ext)!
	assert bytes_back == bytes
}
