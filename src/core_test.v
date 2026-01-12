module tls13

// test CipherSuite things
fn test_ciphersuites_decode_encode() ! {
	// data was taken from https://tls13.xargs.org/#client-hello/annotated
	// 00 08 13 02 13 03 13 01 00 ff
	data := [u8(0x00), 0x08, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0x00, 0xff]

	cs := parse_u16list_withlen[CipherSuite](data, new_csuite, .size2)!
	assert cs.len == 4
	assert cs[0] == .tls_aes256gcm_sha384
	assert cs[1] == .tls_chacha20poly1305_sha256
	assert cs[2] == .tls_aes128gcm_sha256
	assert cs[3] == .tls_emptyrenegotiationinfo_scsv

	// encodes it back
	cs_back := pack_u16list_withlen[CipherSuite](cs, .size2)!
	assert cs_back == data
}

// test for SignatureScheme (extension)
// The material was taken from https://tls13.xargs.org/#client-hello/annotated
// especially for SignatureScheme data
fn test_signatureschemeextension_encode_decode() ! {
	// 00 0d 00 1e 00 1c 04 03 05 03 06 03 08 07 08 08 08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01 06 01
	//
	// This list is presented in descending order of the client's preference.
	// 00 0d - assigned value for extension "Signature Algorithms"
	// 00 1e - 0x1E (30) bytes of "Signature Algorithms" extension data follows
	// 00 1c - 0x1C (28) bytes of data are in the following list of algorithms
	// 04 03 - assigned value for ECDSA-SECP256r1-SHA256
	// 05 03 - assigned value for ECDSA-SECP384r1-SHA384
	// 06 03 - assigned value for ECDSA-SECP521r1-SHA512
	// 08 07 - assigned value for ED25519
	// 08 08 - assigned value for ED448
	// 08 09 - assigned value for RSA-PSS-PSS-SHA256
	// 08 0a - assigned value for RSA-PSS-PSS-SHA384
	// 08 0b - assigned value for RSA-PSS-PSS-SHA512
	// 08 04 - assigned value for RSA-PSS-RSAE-SHA256
	// 08 05 - assigned value for RSA-PSS-RSAE-SHA384
	// 08 06 - assigned value for RSA-PSS-RSAE-SHA512
	// 04 01 - assigned value for RSA-PKCS1-SHA256
	// 05 01 - assigned value for RSA-PKCS1-SHA384
	// 06 01 - assigned value for RSA-PKCS1-SHA512
	bytes := [u8(0x00), 0x0d, 0x00, 0x1e, 0x00, 0x1c, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08,
		0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08, 0x06,
		0x04, 0x01, 0x05, 0x01, 0x06, 0x01]

	// parse the extension data
	ext := parse_ext(bytes)!
	assert ext.tipe == .signature_algorithms
	assert ext.data.len == 30

	signaturelist := parse_sigcheme_list(ext.data)!
	assert signaturelist.len == 14
	assert signaturelist[0] == .ecdsa_secp256r1_sha256
	assert signaturelist[1] == .ecdsa_secp384r1_sha384
	assert signaturelist[2] == .ecdsa_secp521r1_sha512
	assert signaturelist[3] == .ed25519
	assert signaturelist[4] == .ed448
	assert signaturelist[5] == .rsa_psspss_sha256
	assert signaturelist[6] == .rsa_psspss_sha384
	assert signaturelist[7] == .rsa_psspss_sha512
	assert signaturelist[8] == .rsa_pssrsae_sha256
	assert signaturelist[9] == .rsa_pssrsae_sha384
	assert signaturelist[10] == .rsa_pssrsae_sha512
	assert signaturelist[11] == .rsa_pkcs1_sha256
	assert signaturelist[12] == .rsa_pkcs1_sha384
	assert signaturelist[13] == .rsa_pkcs1_sha512

	// pack signaturelist back
	siglist_back := pack_sigscheme_list(signaturelist)!
	assert siglist_back == ext.data

	// pack signaturelist into extension
	ext_siglist := ext_from_sigschemes(signaturelist)!
	assert ext_siglist.tipe == .signature_algorithms
	// make an extension from signaturelist
	siglist_extbytes := pack_ext(ext_siglist)!
	// assert for original data
	assert siglist_extbytes == bytes
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

	// parse the extension data
	ext := parse_ext(bytes)!
	assert ext.tipe == .supported_groups
	assert ext.data.len == 22

	groups := parse_namegroup_list(ext.data)!
	assert groups.len == 10
	assert groups[0] == .x25519
	assert groups[1] == .secp256r1
	assert groups[2] == .x448
	assert groups[3] == .secp521r1
	assert groups[4] == .secp384r1
	assert groups[5] == .ffdhe2048
	assert groups[6] == .ffdhe3072
	assert groups[7] == .ffdhe4096
	assert groups[8] == .ffdhe6144
	assert groups[9] == .ffdhe8192

	// pack group list back into bytes array
	groups_back := pack_namegroup_list(groups)!
	assert groups_back == ext.data

	// make an supported_groups  extension, and pack it back
	groups_ext := ext_from_namegroups(groups)!

	bytes_back := pack_ext(groups_ext)!
	assert bytes_back == bytes
}

// Extension - Server Name
fn test_servernameextension_encode_decode() ! {
	// 00 00 00 18 00 16 00 00 13 65 78 61 6d 70 6c 65 2e 75 6c 66 68 65 69 6d 2e 6e 65 74
	//
	// 00 00 - assigned value for extension "server name"
	// 00 18 - 0x18 (24) bytes of "server name" extension data follows
	// 00 16 - 0x16 (22) bytes of first (and only) list entry follows
	// 00 - list entry is type 0x00 "DNS hostname"
	// 00 13 - 0x13 (19) bytes of hostname follows
	// 65 78 61 ... 6e 65 74 - "example.ulfheim.net"
	//
	data := [u8(0x00), 0x00, 0x00, 0x18, 0x00, 0x16, 0x00, 0x00, 0x13, 0x65, 0x78, 0x61, 0x6d,
		0x70, 0x6c, 0x65, 0x2e, 0x75, 0x6c, 0x66, 0x68, 0x65, 0x69, 0x6d, 0x2e, 0x6e, 0x65, 0x74]

	sn_ext := parse_ext(data)!
	assert sn_ext.tipe == .server_name
	assert sn_ext.data.len == 24

	svlist := parse_svnlist(sn_ext.data)!
	assert svlist.len == 1
	assert svlist[0].tipe == .host_name
	assert svlist[0].name.len == 0x13 // 19
	assert svlist[0].name.bytestr() == 'example.ulfheim.net'

	// serializes back svlist into bytes and match with extension data
	svlist_out := pack_svnlist(svlist)!
	assert sn_ext.data == svlist_out

	svlist_ext := ext_from_svnlist(svlist)!
	svlist_ext_out := pack_ext(svlist_ext)!

	// assert for matching original data
	assert svlist_ext_out == data
}
