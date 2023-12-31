module tls13

const handshake_data = [u8(0x01), 0x00, 0x00, 0xc0, 0x03, 0x03, 0xcb, 0x34, 0xec, 0xb1, 0xe7, 0x81,
	0x63, 0xba, 0x1c, 0x38, 0xc6, 0xda, 0xcb, 0x19, 0x6a, 0x6d, 0xff, 0xa2, 0x1a, 0x8d, 0x99, 0x12,
	0xec, 0x18, 0xa2, 0xef, 0x62, 0x83, 0x02, 0x4d, 0xec, 0xe7, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13,
	0x03, 0x13, 0x02, 0x01, 0x00, 0x00, 0x91, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06,
	0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0a, 0x00, 0x14, 0x00,
	0x12, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01,
	0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00,
	0x20, 0x99, 0x38, 0x1d, 0xe5, 0x60, 0xe4, 0xbd, 0x43, 0xd2, 0x3d, 0x8e, 0x43, 0x5a, 0x7d, 0xba,
	0xfe, 0xb3, 0xc0, 0x6e, 0x51, 0xc1, 0x3c, 0xae, 0x4d, 0x54, 0x13, 0x69, 0x1e, 0x52, 0x9a, 0xaf,
	0x2c, 0x00, 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x04, 0x03,
	0x05, 0x03, 0x06, 0x03, 0x02, 0x03, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01,
	0x06, 0x01, 0x02, 0x01, 0x04, 0x02, 0x05, 0x02, 0x06, 0x02, 0x02, 0x02, 0x00, 0x2d, 0x00, 0x02,
	0x01, 0x01, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01]

const serverhello_msg = [u8(0x02), 0x00, 0x00, 0x56, 0x03, 0x03, 0xa6, 0xaf, 0x06, 0xa4, 0x12,
	0x18, 0x60, 0xdc, 0x5e, 0x6e, 0x60, 0x24, 0x9c, 0xd3, 0x4c, 0x95, 0x93, 0x0c, 0x8a, 0xc5, 0xcb,
	0x14, 0x34, 0xda, 0xc1, 0x55, 0x77, 0x2e, 0xd3, 0xe2, 0x69, 0x28, 0x00, 0x13, 0x01, 0x00, 0x00,
	0x2e, 0x00, 0x33, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0xc9, 0x82, 0x88, 0x76, 0x11, 0x20, 0x95,
	0xfe, 0x66, 0x76, 0x2b, 0xdb, 0xf7, 0xc6, 0x72, 0xe1, 0x56, 0xd6, 0xcc, 0x25, 0x3b, 0x83, 0x3d,
	0xf1, 0xdd, 0x69, 0xb1, 0xb0, 0x4e, 0x75, 0x1f, 0x0f, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]

const certificate_msg = [u8(0x0b), 0x00, 0x01, 0xb9, 0x00, 0x00, 0x01, 0xb5, 0x00, 0x01, 0xb0,
	0x30, 0x82, 0x01, 0xac, 0x30, 0x82, 0x01, 0x15, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02,
	0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30,
	0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30,
	0x1e, 0x17, 0x0d, 0x31, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a,
	0x17, 0x0d, 0x32, 0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x30,
	0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30,
	0x81, 0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
	0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb4, 0xbb, 0x49, 0x8f,
	0x82, 0x79, 0x30, 0x3d, 0x98, 0x08, 0x36, 0x39, 0x9b, 0x36, 0xc6, 0x98, 0x8c, 0x0c, 0x68, 0xde,
	0x55, 0xe1, 0xbd, 0xb8, 0x26, 0xd3, 0x90, 0x1a, 0x24, 0x61, 0xea, 0xfd, 0x2d, 0xe4, 0x9a, 0x91,
	0xd0, 0x15, 0xab, 0xbc, 0x9a, 0x95, 0x13, 0x7a, 0xce, 0x6c, 0x1a, 0xf1, 0x9e, 0xaa, 0x6a, 0xf9,
	0x8c, 0x7c, 0xed, 0x43, 0x12, 0x09, 0x98, 0xe1, 0x87, 0xa8, 0x0e, 0xe0, 0xcc, 0xb0, 0x52, 0x4b,
	0x1b, 0x01, 0x8c, 0x3e, 0x0b, 0x63, 0x26, 0x4d, 0x44, 0x9a, 0x6d, 0x38, 0xe2, 0x2a, 0x5f, 0xda,
	0x43, 0x08, 0x46, 0x74, 0x80, 0x30, 0x53, 0x0e, 0xf0, 0x46, 0x1c, 0x8c, 0xa9, 0xd9, 0xef, 0xbf,
	0xae, 0x8e, 0xa6, 0xd1, 0xd0, 0x3e, 0x2b, 0xd1, 0x93, 0xef, 0xf0, 0xab, 0x9a, 0x80, 0x02, 0xc4,
	0x74, 0x28, 0xa6, 0xd3, 0x5a, 0x8d, 0x88, 0xd7, 0x9f, 0x7f, 0x1e, 0x3f, 0x02, 0x03, 0x01, 0x00,
	0x01, 0xa3, 0x1a, 0x30, 0x18, 0x30, 0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00,
	0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x0d, 0x06,
	0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00,
	0x85, 0xaa, 0xd2, 0xa0, 0xe5, 0xb9, 0x27, 0x6b, 0x90, 0x8c, 0x65, 0xf7, 0x3a, 0x72, 0x67, 0x17,
	0x06, 0x18, 0xa5, 0x4c, 0x5f, 0x8a, 0x7b, 0x33, 0x7d, 0x2d, 0xf7, 0xa5, 0x94, 0x36, 0x54, 0x17,
	0xf2, 0xea, 0xe8, 0xf8, 0xa5, 0x8c, 0x8f, 0x81, 0x72, 0xf9, 0x31, 0x9c, 0xf3, 0x6b, 0x7f, 0xd6,
	0xc5, 0x5b, 0x80, 0xf2, 0x1a, 0x03, 0x01, 0x51, 0x56, 0x72, 0x60, 0x96, 0xfd, 0x33, 0x5e, 0x5e,
	0x67, 0xf2, 0xdb, 0xf1, 0x02, 0x70, 0x2e, 0x60, 0x8c, 0xca, 0xe6, 0xbe, 0xc1, 0xfc, 0x63, 0xa4,
	0x2a, 0x99, 0xbe, 0x5c, 0x3e, 0xb7, 0x10, 0x7c, 0x3c, 0x54, 0xe9, 0xb9, 0xeb, 0x2b, 0xd5, 0x20,
	0x3b, 0x1c, 0x3b, 0x84, 0xe0, 0xa8, 0xb2, 0xf7, 0x59, 0x40, 0x9b, 0xa3, 0xea, 0xc9, 0xd9, 0x1d,
	0x40, 0x2d, 0xcc, 0x0c, 0xc8, 0xf8, 0x96, 0x12, 0x29, 0xac, 0x91, 0x87, 0xb4, 0x2b, 0x4d, 0xe1,
	0x00, 0x00]

const cert_verify_msg = [u8(0x0f), 0x00, 0x00, 0x84, 0x08, 0x04, 0x00, 0x80, 0x5a, 0x74, 0x7c,
	0x5d, 0x88, 0xfa, 0x9b, 0xd2, 0xe5, 0x5a, 0xb0, 0x85, 0xa6, 0x10, 0x15, 0xb7, 0x21, 0x1f, 0x82,
	0x4c, 0xd4, 0x84, 0x14, 0x5a, 0xb3, 0xff, 0x52, 0xf1, 0xfd, 0xa8, 0x47, 0x7b, 0x0b, 0x7a, 0xbc,
	0x90, 0xdb, 0x78, 0xe2, 0xd3, 0x3a, 0x5c, 0x14, 0x1a, 0x07, 0x86, 0x53, 0xfa, 0x6b, 0xef, 0x78,
	0x0c, 0x5e, 0xa2, 0x48, 0xee, 0xaa, 0xa7, 0x85, 0xc4, 0xf3, 0x94, 0xca, 0xb6, 0xd3, 0x0b, 0xbe,
	0x8d, 0x48, 0x59, 0xee, 0x51, 0x1f, 0x60, 0x29, 0x57, 0xb1, 0x54, 0x11, 0xac, 0x02, 0x76, 0x71,
	0x45, 0x9e, 0x46, 0x44, 0x5c, 0x9e, 0xa5, 0x8c, 0x18, 0x1e, 0x81, 0x8e, 0x95, 0xb8, 0xc3, 0xfb,
	0x0b, 0xf3, 0x27, 0x84, 0x09, 0xd3, 0xbe, 0x15, 0x2a, 0x3d, 0xa5, 0x04, 0x3e, 0x06, 0x3d, 0xda,
	0x65, 0xcd, 0xf5, 0xae, 0xa2, 0x0d, 0x53, 0xdf, 0xac, 0xd4, 0x2f, 0x74, 0xf3]

const finished_msg = [u8(0x14), 0x00, 0x00, 0x20, 0x9b, 0x9b, 0x14, 0x1d, 0x90, 0x63, 0x37, 0xfb,
	0xd2, 0xcb, 0xdc, 0xe7, 0x1d, 0xf4, 0xde, 0xda, 0x4a, 0xb4, 0x2c, 0x30, 0x95, 0x72, 0xcb, 0x7f,
	0xff, 0xee, 0x54, 0x54, 0xb7, 0x8f, 0x07, 0x18]

const hrr_msg = [u8(0x02), 0x00, 0x00, 0xac, 0x03, 0x03, 0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61,
	0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91, 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c,
	0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c, 0x00, 0x13, 0x01, 0x00, 0x00, 0x84, 0x00,
	0x33, 0x00, 0x02, 0x00, 0x17, 0x00, 0x2c, 0x00, 0x74, 0x00, 0x72, 0x71, 0xdc, 0xd0, 0x4b, 0xb8,
	0x8b, 0xc3, 0x18, 0x91, 0x19, 0x39, 0x8a, 0x00, 0x00, 0x00, 0x00, 0xee, 0xfa, 0xfc, 0x76, 0xc1,
	0x46, 0xb8, 0x23, 0xb0, 0x96, 0xf8, 0xaa, 0xca, 0xd3, 0x65, 0xdd, 0x00, 0x30, 0x95, 0x3f, 0x4e,
	0xdf, 0x62, 0x56, 0x36, 0xe5, 0xf2, 0x1b, 0xb2, 0xe2, 0x3f, 0xcc, 0x65, 0x4b, 0x1b, 0x5b, 0x40,
	0x31, 0x8d, 0x10, 0xd1, 0x37, 0xab, 0xcb, 0xb8, 0x75, 0x74, 0xe3, 0x6e, 0x8a, 0x1f, 0x02, 0x5f,
	0x7d, 0xfa, 0x5d, 0x6e, 0x50, 0x78, 0x1b, 0x5e, 0xda, 0x4a, 0xa1, 0x5b, 0x0c, 0x8b, 0xe7, 0x78,
	0x25, 0x7d, 0x16, 0xaa, 0x30, 0x30, 0xe9, 0xe7, 0x84, 0x1d, 0xd9, 0xe4, 0xc0, 0x34, 0x22, 0x67,
	0xe8, 0xca, 0x0c, 0xaf, 0x57, 0x1f, 0xb2, 0xb7, 0xcf, 0xf0, 0xf9, 0x34, 0xb0, 0x00, 0x2b, 0x00,
	0x02, 0x03, 0x04]

const newsessionticket_msg = [u8(0x04), 0x00, 0x00, 0xc9, 0x00, 0x00, 0x00, 0x1e, 0xfa, 0xd6, 0xaa,
	0xc5, 0x02, 0x00, 0x00, 0x00, 0xb2, 0x2c, 0x03, 0x5d, 0x82, 0x93, 0x59, 0xee, 0x5f, 0xf7, 0xaf,
	0x4e, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x26, 0x2a, 0x64, 0x94, 0xdc, 0x48, 0x6d, 0x2c, 0x8a, 0x34,
	0xcb, 0x33, 0xfa, 0x90, 0xbf, 0x1b, 0x00, 0x70, 0xad, 0x3c, 0x49, 0x88, 0x83, 0xc9, 0x36, 0x7c,
	0x09, 0xa2, 0xbe, 0x78, 0x5a, 0xbc, 0x55, 0xcd, 0x22, 0x60, 0x97, 0xa3, 0xa9, 0x82, 0x11, 0x72,
	0x83, 0xf8, 0x2a, 0x03, 0xa1, 0x43, 0xef, 0xd3, 0xff, 0x5d, 0xd3, 0x6d, 0x64, 0xe8, 0x61, 0xbe,
	0x7f, 0xd6, 0x1d, 0x28, 0x27, 0xdb, 0x27, 0x9c, 0xce, 0x14, 0x50, 0x77, 0xd4, 0x54, 0xa3, 0x66,
	0x4d, 0x4e, 0x6d, 0xa4, 0xd2, 0x9e, 0xe0, 0x37, 0x25, 0xa6, 0xa4, 0xda, 0xfc, 0xd0, 0xfc, 0x67,
	0xd2, 0xae, 0xa7, 0x05, 0x29, 0x51, 0x3e, 0x3d, 0xa2, 0x67, 0x7f, 0xa5, 0x90, 0x6c, 0x5b, 0x3f,
	0x7d, 0x8f, 0x92, 0xf2, 0x28, 0xbd, 0xa4, 0x0d, 0xda, 0x72, 0x14, 0x70, 0xf9, 0xfb, 0xf2, 0x97,
	0xb5, 0xae, 0xa6, 0x17, 0x64, 0x6f, 0xac, 0x5c, 0x03, 0x27, 0x2e, 0x97, 0x07, 0x27, 0xc6, 0x21,
	0xa7, 0x91, 0x41, 0xef, 0x5f, 0x7d, 0xe6, 0x50, 0x5e, 0x5b, 0xfb, 0xc3, 0x88, 0xe9, 0x33, 0x43,
	0x69, 0x40, 0x93, 0x93, 0x4a, 0xe4, 0xd3, 0x57, 0x00, 0x08, 0x00, 0x2a, 0x00, 0x04, 0x00, 0x00,
	0x04, 0x00]

fn test_serverhello_with_hrr_msg_from_rfc848() ! {
	hsk := Handshake.unpack(tls13.hrr_msg)!
	assert hsk.msg_type == .server_hello
	assert hsk.is_hrr()! == true

	sh := ServerHello.unpack(hsk.payload)!
	assert sh.random == helloretry_magic
	assert sh.is_hrr() == true

	assert sh.packed_length() == hsk.length
	assert sh.packed_length() == hsk.payload.len

	// pack back
	hp := HandshakePayload(sh)
	back := hp.pack_to_handshake_bytes()!
	assert back == tls13.hrr_msg
}

fn test_clienthello_pack_unpack_from_rfc8448() ! {
	hsk := Handshake.unpack(tls13.handshake_data)!
	assert hsk.msg_type == .client_hello
	ch := ClientHello.unpack(hsk.payload)!
	assert ch.packed_length() == hsk.length
	assert ch.packed_length() == hsk.payload.len

	assert ch.legacy_version == tls_v12
	assert ch.random.len == 32
	assert ch.legacy_session_id.len == 0
	assert ch.cipher_suites.len == 3
	assert ch.legacy_compression_methods == u8(0x00)
	assert ch.extensions.len == 9

	// pack back
	hp := HandshakePayload(ch)
	back := hp.pack_to_handshake_bytes()!
	assert back == tls13.handshake_data
}

fn test_serverhello_pack_unpack_from_rfc8448() ! {
	hsk := Handshake.unpack(tls13.serverhello_msg)!
	assert hsk.msg_type == .server_hello
	sh := ServerHello.unpack(hsk.payload)!
	assert sh.packed_length() == hsk.length
	assert sh.packed_length() == hsk.payload.len

	// pack back
	hp := HandshakePayload(sh)
	back := hp.pack_to_handshake_bytes()!
	assert back == tls13.serverhello_msg
}

fn test_serverhello_pack_unpack_from_tls13_xargs_org() ! {
	serverhello_hsk := [u8(0x02), 0x00, 0x00, 0x76, 0x03, 0x03, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75,
		0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84,
		0x85, 0x86, 0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x20, 0xe0, 0xe1, 0xe2,
		0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1,
		0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x13,
		0x02, 0x00, 0x00, 0x2e, 0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, 0x00, 0x33, 0x00, 0x24, 0x00,
		0x1d, 0x00, 0x20, 0x9f, 0xd7, 0xad, 0x6d, 0xcf, 0xf4, 0x29, 0x8d, 0xd3, 0xf9, 0x6d, 0x5b,
		0x1b, 0x2a, 0xf9, 0x10, 0xa0, 0x53, 0x5b, 0x14, 0x88, 0xd7, 0xf8, 0xfa, 0xbb, 0x34, 0x9a,
		0x98, 0x28, 0x80, 0xb6, 0x15]
	hsk := Handshake.unpack(serverhello_hsk)!
	assert hsk.msg_type == .server_hello
	sh := ServerHello.unpack(hsk.payload)!
	assert sh.packed_length() == hsk.length
	assert sh.packed_length() == hsk.payload.len

	// pack back
	hp := HandshakePayload(sh)
	back := hp.pack_to_handshake_bytes()!
	assert back == serverhello_hsk
}

fn test_certificate_handshake_message_pack_unpack_rfc8448() ! {
	hsk := Handshake.unpack(tls13.certificate_msg)!
	// dump(hsk)
	cert := Certificate.unpack(hsk.payload)!
	assert cert.cert_req_ctx.len == 0
	assert cert.cert_list.len == 1
	assert cert.cert_list[0].certificate_type == .x509

	// unpack back
	cert_back_hsk := HandshakePayload(cert).pack_to_handshake_bytes()!
	assert cert_back_hsk == tls13.certificate_msg
}

fn test_certificate_verify_handshake_message_pack_unpack_rfc8448() ! {
	hsk := Handshake.unpack(tls13.cert_verify_msg)!
	cert_verify := CertificateVerify.unpack(hsk.payload)!
	assert cert_verify.algorithm == .rsa_pss_rsae_sha256

	// unpack back
	certver_back_hsk := HandshakePayload(cert_verify).pack_to_handshake_bytes()!
	assert certver_back_hsk == tls13.cert_verify_msg
}

fn test_certificate_verify_handshake_message_pack_unpack_tls13_xargs_org() ! {
	certverify_data := [u8(0x0f), 0x00, 0x01, 0x04, 0x08, 0x04, 0x01, 0x00, 0x5c, 0xbb, 0x24, 0xc0,
		0x40, 0x93, 0x32, 0xda, 0xa9, 0x20, 0xbb, 0xab, 0xbd, 0xb9, 0xbd, 0x50, 0x17, 0x0b, 0xe4,
		0x9c, 0xfb, 0xe0, 0xa4, 0x10, 0x7f, 0xca, 0x6f, 0xfb, 0x10, 0x68, 0xe6, 0x5f, 0x96, 0x9e,
		0x6d, 0xe7, 0xd4, 0xf9, 0xe5, 0x60, 0x38, 0xd6, 0x7c, 0x69, 0xc0, 0x31, 0x40, 0x3a, 0x7a,
		0x7c, 0x0b, 0xcc, 0x86, 0x83, 0xe6, 0x57, 0x21, 0xa0, 0xc7, 0x2c, 0xc6, 0x63, 0x40, 0x19,
		0xad, 0x1d, 0x3a, 0xd2, 0x65, 0xa8, 0x12, 0x61, 0x5b, 0xa3, 0x63, 0x80, 0x37, 0x20, 0x84,
		0xf5, 0xda, 0xec, 0x7e, 0x63, 0xd3, 0xf4, 0x93, 0x3f, 0x27, 0x22, 0x74, 0x19, 0xa6, 0x11,
		0x03, 0x46, 0x44, 0xdc, 0xdb, 0xc7, 0xbe, 0x3e, 0x74, 0xff, 0xac, 0x47, 0x3f, 0xaa, 0xad,
		0xde, 0x8c, 0x2f, 0xc6, 0x5f, 0x32, 0x65, 0x77, 0x3e, 0x7e, 0x62, 0xde, 0x33, 0x86, 0x1f,
		0xa7, 0x05, 0xd1, 0x9c, 0x50, 0x6e, 0x89, 0x6c, 0x8d, 0x82, 0xf5, 0xbc, 0xf3, 0x5f, 0xec,
		0xe2, 0x59, 0xb7, 0x15, 0x38, 0x11, 0x5e, 0x9c, 0x8c, 0xfb, 0xa6, 0x2e, 0x49, 0xbb, 0x84,
		0x74, 0xf5, 0x85, 0x87, 0xb1, 0x1b, 0x8a, 0xe3, 0x17, 0xc6, 0x33, 0xe9, 0xc7, 0x6c, 0x79,
		0x1d, 0x46, 0x62, 0x84, 0xad, 0x9c, 0x4f, 0xf7, 0x35, 0xa6, 0xd2, 0xe9, 0x63, 0xb5, 0x9b,
		0xbc, 0xa4, 0x40, 0xa3, 0x07, 0x09, 0x1a, 0x1b, 0x4e, 0x46, 0xbc, 0xc7, 0xa2, 0xf9, 0xfb,
		0x2f, 0x1c, 0x89, 0x8e, 0xcb, 0x19, 0x91, 0x8b, 0xe4, 0x12, 0x1d, 0x7e, 0x8e, 0xd0, 0x4c,
		0xd5, 0x0c, 0x9a, 0x59, 0xe9, 0x87, 0x98, 0x01, 0x07, 0xbb, 0xbf, 0x29, 0x9c, 0x23, 0x2e,
		0x7f, 0xdb, 0xe1, 0x0a, 0x4c, 0xfd, 0xae, 0x5c, 0x89, 0x1c, 0x96, 0xaf, 0xdf, 0xf9, 0x4b,
		0x54, 0xcc, 0xd2, 0xbc, 0x19, 0xd3, 0xcd, 0xaa, 0x66, 0x44, 0x85, 0x9c]
	hsk := Handshake.unpack(certverify_data)!
	assert hsk.length == 260
	cert_verify := CertificateVerify.unpack(hsk.payload)!
	assert cert_verify.algorithm == .rsa_pss_rsae_sha256
	// dump(cert_verify)

	// unpack back
	certver_back_hsk := HandshakePayload(cert_verify).pack_to_handshake_bytes()!
	assert certver_back_hsk == certverify_data
}

fn test_handshake_finished_msg_pack_unpack_rfc8448() ! {
	hsk := Handshake.unpack(tls13.finished_msg)!
	assert hsk.length == 32
	fin := Finished.unpack(hsk.payload)!
	assert fin.verify_data.hex() == '9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718'
	// unpack back
	fin_back_hsk := HandshakePayload(fin).pack_to_handshake_bytes()!
	assert fin_back_hsk == tls13.finished_msg
}

fn test_multi_handshake_payload_rfc8448() ! {
	// this data contains multi handshake payload
	hsk_data := [u8(0x08), 0x00, 0x00, 0x24, 0x00, 0x22, 0x00, 0x0a, 0x00, 0x14, 0x00, 0x12, 0x00,
		0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03,
		0x01, 0x04, 0x00, 0x1c, 0x00, 0x02, 0x40, 0x01, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x01,
		0xb9, 0x00, 0x00, 0x01, 0xb5, 0x00, 0x01, 0xb0, 0x30, 0x82, 0x01, 0xac, 0x30, 0x82, 0x01,
		0x15, 0xa0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x02, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86,
		0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a,
		0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30, 0x1e, 0x17, 0x0d, 0x31,
		0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x17, 0x0d, 0x32,
		0x36, 0x30, 0x37, 0x33, 0x30, 0x30, 0x31, 0x32, 0x33, 0x35, 0x39, 0x5a, 0x30, 0x0e, 0x31,
		0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x03, 0x72, 0x73, 0x61, 0x30, 0x81,
		0x9f, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
		0x00, 0x03, 0x81, 0x8d, 0x00, 0x30, 0x81, 0x89, 0x02, 0x81, 0x81, 0x00, 0xb4, 0xbb, 0x49,
		0x8f, 0x82, 0x79, 0x30, 0x3d, 0x98, 0x08, 0x36, 0x39, 0x9b, 0x36, 0xc6, 0x98, 0x8c, 0x0c,
		0x68, 0xde, 0x55, 0xe1, 0xbd, 0xb8, 0x26, 0xd3, 0x90, 0x1a, 0x24, 0x61, 0xea, 0xfd, 0x2d,
		0xe4, 0x9a, 0x91, 0xd0, 0x15, 0xab, 0xbc, 0x9a, 0x95, 0x13, 0x7a, 0xce, 0x6c, 0x1a, 0xf1,
		0x9e, 0xaa, 0x6a, 0xf9, 0x8c, 0x7c, 0xed, 0x43, 0x12, 0x09, 0x98, 0xe1, 0x87, 0xa8, 0x0e,
		0xe0, 0xcc, 0xb0, 0x52, 0x4b, 0x1b, 0x01, 0x8c, 0x3e, 0x0b, 0x63, 0x26, 0x4d, 0x44, 0x9a,
		0x6d, 0x38, 0xe2, 0x2a, 0x5f, 0xda, 0x43, 0x08, 0x46, 0x74, 0x80, 0x30, 0x53, 0x0e, 0xf0,
		0x46, 0x1c, 0x8c, 0xa9, 0xd9, 0xef, 0xbf, 0xae, 0x8e, 0xa6, 0xd1, 0xd0, 0x3e, 0x2b, 0xd1,
		0x93, 0xef, 0xf0, 0xab, 0x9a, 0x80, 0x02, 0xc4, 0x74, 0x28, 0xa6, 0xd3, 0x5a, 0x8d, 0x88,
		0xd7, 0x9f, 0x7f, 0x1e, 0x3f, 0x02, 0x03, 0x01, 0x00, 0x01, 0xa3, 0x1a, 0x30, 0x18, 0x30,
		0x09, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x0b, 0x06, 0x03, 0x55,
		0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x05, 0xa0, 0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48,
		0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00, 0x03, 0x81, 0x81, 0x00, 0x85, 0xaa, 0xd2,
		0xa0, 0xe5, 0xb9, 0x27, 0x6b, 0x90, 0x8c, 0x65, 0xf7, 0x3a, 0x72, 0x67, 0x17, 0x06, 0x18,
		0xa5, 0x4c, 0x5f, 0x8a, 0x7b, 0x33, 0x7d, 0x2d, 0xf7, 0xa5, 0x94, 0x36, 0x54, 0x17, 0xf2,
		0xea, 0xe8, 0xf8, 0xa5, 0x8c, 0x8f, 0x81, 0x72, 0xf9, 0x31, 0x9c, 0xf3, 0x6b, 0x7f, 0xd6,
		0xc5, 0x5b, 0x80, 0xf2, 0x1a, 0x03, 0x01, 0x51, 0x56, 0x72, 0x60, 0x96, 0xfd, 0x33, 0x5e,
		0x5e, 0x67, 0xf2, 0xdb, 0xf1, 0x02, 0x70, 0x2e, 0x60, 0x8c, 0xca, 0xe6, 0xbe, 0xc1, 0xfc,
		0x63, 0xa4, 0x2a, 0x99, 0xbe, 0x5c, 0x3e, 0xb7, 0x10, 0x7c, 0x3c, 0x54, 0xe9, 0xb9, 0xeb,
		0x2b, 0xd5, 0x20, 0x3b, 0x1c, 0x3b, 0x84, 0xe0, 0xa8, 0xb2, 0xf7, 0x59, 0x40, 0x9b, 0xa3,
		0xea, 0xc9, 0xd9, 0x1d, 0x40, 0x2d, 0xcc, 0x0c, 0xc8, 0xf8, 0x96, 0x12, 0x29, 0xac, 0x91,
		0x87, 0xb4, 0x2b, 0x4d, 0xe1, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x84, 0x08, 0x04, 0x00, 0x80,
		0x5a, 0x74, 0x7c, 0x5d, 0x88, 0xfa, 0x9b, 0xd2, 0xe5, 0x5a, 0xb0, 0x85, 0xa6, 0x10, 0x15,
		0xb7, 0x21, 0x1f, 0x82, 0x4c, 0xd4, 0x84, 0x14, 0x5a, 0xb3, 0xff, 0x52, 0xf1, 0xfd, 0xa8,
		0x47, 0x7b, 0x0b, 0x7a, 0xbc, 0x90, 0xdb, 0x78, 0xe2, 0xd3, 0x3a, 0x5c, 0x14, 0x1a, 0x07,
		0x86, 0x53, 0xfa, 0x6b, 0xef, 0x78, 0x0c, 0x5e, 0xa2, 0x48, 0xee, 0xaa, 0xa7, 0x85, 0xc4,
		0xf3, 0x94, 0xca, 0xb6, 0xd3, 0x0b, 0xbe, 0x8d, 0x48, 0x59, 0xee, 0x51, 0x1f, 0x60, 0x29,
		0x57, 0xb1, 0x54, 0x11, 0xac, 0x02, 0x76, 0x71, 0x45, 0x9e, 0x46, 0x44, 0x5c, 0x9e, 0xa5,
		0x8c, 0x18, 0x1e, 0x81, 0x8e, 0x95, 0xb8, 0xc3, 0xfb, 0x0b, 0xf3, 0x27, 0x84, 0x09, 0xd3,
		0xbe, 0x15, 0x2a, 0x3d, 0xa5, 0x04, 0x3e, 0x06, 0x3d, 0xda, 0x65, 0xcd, 0xf5, 0xae, 0xa2,
		0x0d, 0x53, 0xdf, 0xac, 0xd4, 0x2f, 0x74, 0xf3, 0x14, 0x00, 0x00, 0x20, 0x9b, 0x9b, 0x14,
		0x1d, 0x90, 0x63, 0x37, 0xfb, 0xd2, 0xcb, 0xdc, 0xe7, 0x1d, 0xf4, 0xde, 0xda, 0x4a, 0xb4,
		0x2c, 0x30, 0x95, 0x72, 0xcb, 0x7f, 0xff, 0xee, 0x54, 0x54, 0xb7, 0x8f, 0x07, 0x18]
	mutlihsk := unpack_to_multi_handshake(hsk_data)!
	// dump(mutlihsk)

	// unpack back
	multihsk_back := mutlihsk.pack()!
	assert multihsk_back == hsk_data
}

fn test_newsessionticket_msg_pack_unpack() ! {
	hsk := Handshake.unpack(tls13.newsessionticket_msg)!
	// dump(hsk)
	newsessticket := NewSessionTicket.unpack(hsk.payload)!

	// unpack back
	newsessticket_back_hsk := HandshakePayload(newsessticket).pack_to_handshake_bytes()!
	assert newsessticket_back_hsk == tls13.newsessionticket_msg
}
