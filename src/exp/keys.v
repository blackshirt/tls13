module tls13

struct Keys {
mut:
	// binder_key
	extern_bindkey []u8 // ext_binder_key
	resump_bindkey []u8 // res_binder_key
	client_easec   []u8 // client_early_traffic_secret
	export_easec   []u8 // early_exporter_master_secret
	// client and server_handshake_traffic_secret
	client_hssec []u8
	server_hssec []u8
	// client and server_application_traffic_secret_0
	client_appsec []u8
	server_appsec []u8
	// exporter adn resumption_master_secret
	export_masec []u8
	resump_masec []u8
	// client handshake write key and iv for record payload protection
	// see https://datatracker.ietf.org/doc/html/rfc8446#section-7.3
	client_hwkey []u8
	client_hwiv  []u8
	server_hwkey []u8
	server_hwiv  []u8
	// client application write key and iv for record payload protection
	client_appwkey []u8
	client_appwiv  []u8
	server_appwkey []u8
	server_appwiv  []u8
}

fn (mut k Keys) reset() {
	unsafe {
		k.client_hwkey.clear()
		k.client_hwiv.clear()
		k.client_appwkey.clear()
		k.client_appwiv.clear()
		k.extern_bindkey.clear()
		k.resump_bindkey.clear()
		k.client_easec.clear()
		k.export_easec.clear()
		k.client_hssec.clear()
		k.server_hssec.clear()
		k.client_appsec.clear()
		k.server_appsec.clear()
		k.export_masec.clear()
		k.resump_masec.clear()
	}
}

fn (mut k Keys) free() {
	unsafe {
		k.client_hwkey.free()
		k.client_hwiv.free()
		k.client_appwkey.free()
		k.client_appwiv.free()
		k.extern_bindkey.free()
		k.resump_bindkey.free()
		k.client_easec.free()
		k.export_easec.free()
		k.client_hssec.free()
		k.server_hssec.free()
		k.client_appsec.free()
		k.server_appsec.free()
		k.export_masec.free()
		k.resump_masec.free()
	}
}
