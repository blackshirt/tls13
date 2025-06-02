module tls13

struct ClientSpV {
	versions []ProtocolVersion // ProtocolVersion versions<2..254>;
}

fn (csv ClientSpV) pack() ![]u8 {
	if csv.versions.len < 1 {
		return error('Bad ClientSpV length: underflow')
	}
	if csv.versions.len > 128 {
		return error('Bad ClientSpV length: overflow')
	}
	vers := csv.versions.pack()!

	return vers
}

fn ClientSpV.unpack(b []u8) !ClientSpV {
	versions := ProtocolVersionList.unpack(b)!
	csv := ClientSpV{
		versions: versions
	}
	return csv
}

struct ServerHRetrySpV {
	version ProtocolVersion
}

fn (shv ServerHRetrySpV) pack() ![]u8 {
	ver := shv.version.pack()!
	return ver
}

fn ServerHRetrySpV.unpack(b []u8) !ServerHRetrySpV {
	ver := ProtocolVersion.unpack(b)!
	shv := ServerHRetrySpV{
		version: ver
	}
	return shv
}

type SupportedVersions = ClientSpV | ServerHRetrySpV

fn (sv SupportedVersions) pack() ![]u8 {
	match sv {
		ClientSpV {
			csv := sv as ClientSpV
			out := csv.pack()!
			return out
		}
		ServerHRetrySpV {
			shv := sv as ServerHRetrySpV
			out := shv.pack()!
			return out
		}
	}
}

fn SupportedVersions.unpack(b []u8, hsk HandshakeType) !SupportedVersions {
	match hsk {
		.client_hello {
			// for clienthello, its minimal contains one of ProtocolVersion
			if b.len < 3 {
				return error('bad SupportedVersions bytes')
			}
			csv := ClientSpV.unpack(b)!
			sv := SupportedVersions(csv)
			return sv
		}
		.server_hello, .hello_retry_request {
			if b.len != 2 {
				return error('Bad SupportedVersions bytes: for sh or hrr its should 2')
			}
			srr := ServerHRetrySpV.unpack(b)!
			sv := SupportedVersions(srr)
			return sv
		}
		else {
			return error('Bad HandshakeType')
		}
	}
}

fn (sve SupportedVersions) pack_to_extension() !Extension {
	payload := sve.pack()!
	ext := Extension{
		tipe:   .supported_versions
		length: payload.len
		data:   payload
	}
	return ext
}

fn (sve SupportedVersions) pack_to_extension_bytes() ![]u8 {
	ext := sve.pack_to_extension()!
	out := ext.pack()!
	return out
}

fn SupportedVersions.unpack_from_extension_bytes(b []u8, hsk HandshakeType) !SupportedVersions {
	ext := Extension.unpack(b)!
	if ext.tipe != .supported_versions {
		return error('Wrong extension type')
	}
	spv := SupportedVersions.unpack(ext.data, hsk)!

	return spv
}
