# tls13
Limited subset of TLS Protocol Version 1.3 (RFC 8446)[https://datatracker.ietf.org/doc/html/rfc8446] in pure V language for learning purposes.

## Status
> **Warning**
>
> Implementing TLS 1.3 is a hard and full of cullprits that you should aware.
> This module does not recommended for production use, its intended only for learning purposes, 

This module only support limited subset of TLS 1.3 standard.
- Client only (server maybe in plan)
- Strict limited to only 1.3 version of standard (no plan for support for older version)
- Only support TLS_CHACHA20_POLY1305_SHA256 ciphersuite 
- Only support ed25519 SignatureScheme
- Only support x25519 NamedGroup for Elliptic Curve Groups (ECDHE) key exchange
- support for server_name extension
- support key_share extension only through x25519 NamedGroup
- Dont support HelloRetryRequest
- And many others stuff does not yet supported

## Testing
Testing with local openssl serve 

Create self signed certificate for openssl 
```
openssl req -new -newkey ed25519 -keyout privkey.pem -nodes -out pubcert.csr
openssl req -verify -in pubcert.csr -text -noout
openssl req -x509 -days 365 -in pubcert.csr -key privkey.pem -out pubcert.pem
```

Test server
```bash
$openssl s_server -accept 8443 -tls1_3 -state -tlsextdebug -debug -msg -cert pubcert.pem -key privkey.pem
```


Test client 
```bash
$openssl s_client -connect localhost:8443
```

```bash
$v run main.v 
```