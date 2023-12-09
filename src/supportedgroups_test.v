module tls13

fn test_supportedgroupextension_pack_unpack() ! {
	bytes := [u8(0x00), 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00,
		0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04]

	ext := Extension.unpack(bytes)!
	assert ext.tipe == .supported_groups
	assert ext.length == 22

	groups := NamedGroupList.unpack_from_extension_bytes(bytes)!
	assert groups.len == 10
	assert NamedGroup.x25519 in groups
	assert NamedGroup.x448 in groups

	// pack back
	back := groups.pack_to_extension_bytes()!
	assert back == bytes
}
