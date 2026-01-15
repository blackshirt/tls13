module tls13

import encoding.hex

const salt = '000102030405060708090a0b0c'
const expanded_length = 42
const label = 'test'
const hkdfcontext = 'f9a54250131c827542664bcad131b87c09cdd92f0d5f84db3680ee4c0c0f8ed6' // random
const encoded_label = '002a' + '0a' + hex.encode('tls13 '.bytes()) + hex.encode(label.bytes()) +
	'20' + hkdfcontext
const expanded_label_out = 'a7c2b665154333b14f01762409173a6941d9c4e2edbe380e1cdd3091cb56f4aff8aced829cca286be245'

fn test_hkdf_expand_label() ! {
	secret := hex.decode(salt)!
	context := hex.decode(hkdfcontext)!

	expanded_label := hkdf_expand_label(.sha256, secret, label, context, expanded_length)!
	assert expanded_label.hex() == expanded_label_out
}
