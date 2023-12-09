module tls13

// see https://tls13.xargs.org/#client-hello/annotated
fn test_supportedversionsextension_unpack_from_clienthello() ! {
	bytes := [u8(0x00), 0x2b, 0x00, 0x03, 0x02, 0x03, 0x04]
	spv := SupportedVersions.unpack_from_extension_bytes(bytes, .client_hello)!

	// here, spv is ClientSpV
	csv := spv as ClientSpV
	assert csv.versions.len == 1
	assert csv.versions[0] == tls_v13

	spv_ext := SupportedVersions(csv).pack_to_extension()!
	back := spv_ext.pack()!
	assert back == bytes
}

fn test_supportedversionsextension_pack_unpack_from_serverhello() ! {
	data := [u8(0x00), 0x2b, 0x00, 0x02, 0x03, 0x04]
	spv := SupportedVersions.unpack_from_extension_bytes(data, .server_hello)!

	// cast
	ssv := spv as ServerHRetrySpV
	assert ssv.version == tls_v13

	// pack'ing back to Extension bytes
	back := spv.pack_to_extension_bytes()!
	assert back == data
}
