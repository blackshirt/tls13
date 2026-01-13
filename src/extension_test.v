module tls13

fn test_extensionlist_pack_unpack_from_serverhello() ! {
	data := [u8(0x00), 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00,
		0x1d, 0x00, 0x20, 0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b,
		0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a,
		0x98, 0x28, 0x80, 0xb6, 0x15]

	exts := parse_extlist(data)!

	assert exts.len == 2
	assert exts[0].tipe == .supported_versions
	ver := parse_u16item[Version](exts[0].data, new_version)!
	assert ver == .v13

	assert exts[1].tipe == .key_share
	ksh := parse_ksext(exts[1].data, .server_hello, false)!
	assert ksh.server_share.group == .x25519
	assert ksh.server_share.ksdata.len == 32
}

fn test_supportedversionsextension_unpack_from_clienthello() ! {
	// 00 2b 00 03 02 03 04
	// The client indicates its support of TLS 1.3. This is the only indication in the Client Hello record
	// that hints the client supports TLS 1.3, since for compatibility reasons it has otherwise pretended
	// to be a TLS 1.2 connection attempt.
	// 00 2b - assigned value for extension "Supported Versions"
	// 00 03 - 3 bytes of "Supported Versions" extension data follows
	// 02 - 2 bytes of TLS versions follow
	// 03 04 - assigned value for TLS 1.3
	//
	bytes := [u8(0x00), 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]
	ext := parse_ext(bytes)!
	assert ext.tipe == .supported_versions
	assert ext.data.len == 3

	cvl := parse_spv(ext.data, .client_hello)!

	// here, cvl is client supported versions
	assert cvl.msg_type == .client_hello
	assert cvl.verlist.len == 1
	assert cvl.verlist[0] == .v13

	// encodes back the client supported version list
	cvl_back := pack_spv(cvl)!
	assert cvl_back == ext.data

	spv_ext := ext_from_spv(cvl.verlist, .client_hello)!
	spv_back := pack_ext(spv_ext)!
	assert spv_back == bytes
}

fn test_supportedversionsextension_pack_unpack_from_serverhello() ! {
	// 00 2b 00 02 03 04
	// Extension - Supported Versions
	// The server indicates the negotiated TLS version of 1.3.
	// 00 2b - assigned value for extension "Supported Versions"
	// 00 02 - 2 bytes of "Supported Versions" extension data follows
	// 03 04 - assigned value for TLS 1.3
	data := [u8(0x00), 0x2b, 0x00, 0x02, 0x03, 0x04]
	ext := parse_ext(data)!
	assert ext.tipe == .supported_versions
	assert ext.data.len == 2

	// parse
	ssv := parse_spv(ext.data, .server_hello)!
	assert ssv.verlist.len == 1
	assert ssv.verlist[0] == .v13

	// pack'ing back to Extension bytes
	// encodes back the client supported version list
	ssv_back := pack_spv(ssv)!
	assert ssv_back == ext.data

	spv_ext := ext_from_spv(ssv.verlist, .server_hello)!
	spv_back := pack_ext(spv_ext)!
	assert spv_back == data
}
