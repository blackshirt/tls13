# tls13
Limited subset of TLS Protocol Version 1.3 from [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) in pure V language for learning purposes.

## Status
> [!Warning]
>
> Implementing TLS 1.3 is a hard and full of cullprits that you should aware.
> This module does not finished yet and does not recommended for production use,
> Its intended only for learning purposes.
> 
> Basic of messages parsing, handshake processing, decryption/encryption record almost has been implemented.
> With strict and limited configuration of `openssl s_server` command for local testing below,
> It can perform full TLS 1.3 handshake phase and send application data

> [!Note]
> This module depends on some of v modules availables at this github repository.
> Install its before to run some test.

This module only support limited subset of TLS 1.3 standard.
- Client only (server maybe in plan)
- Strict limited to only 1.3 version of standard (no plan for support for older version)
- Only support TLS_CHACHA20_POLY1305_SHA256 ciphersuite 
- Only support ed25519 for SignatureScheme extensions
- Only support x25519 NamedGroup for Elliptic Curve Groups (ECDHE) key exchange
- support for server_name extension
- support key_share extension only through x25519 NamedGroup
- Doesn't support HelloRetryRequest message
- And many others stuff does not supported yet

## Testing
Testing with local openssl server 

### Create self signed certificate for openssl 
```
openssl req -new -newkey ed25519 -keyout privkey.pem -nodes -out pubcert.csr
openssl req -verify -in pubcert.csr -text -noout
openssl req -x509 -days 365 -in pubcert.csr -key privkey.pem -out pubcert.pem
```

### Test server
```bash
$openssl s_server -accept 8443 -tls1_3 -state -tlsextdebug -debug -msg -cert pubcert.pem -key privkey.pem
```

### Test client 
```bash
$openssl s_client -connect localhost:8443
```

### Run test main.v
```bash
$v run main.v 
```
