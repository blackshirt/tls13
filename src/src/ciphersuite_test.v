module tls13

fn test_ciphersuites_pack_unpack() ! {
	data := [u8(0x00), 0x08, 0x13, 0x02, 0x13, 0x03, 0x13, 0x01, 0x00, 0xff]
	cs := CipherSuiteList.unpack(data)!

	assert cs.len == 4
	assert cs[0] == .tls_aes_256_gcm_sha384
	assert cs[1] == .tls_chacha20_poly1305_sha256
	assert cs[2] == .tls_aes_128_gcm_sha256
	assert cs[3] == .tls_empty_renegotiation_info_scsv
}
