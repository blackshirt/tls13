# tls13
Limited subset of TLS Protocol Version 1.3 from [RFC 8446](https://datatracker.ietf.org/doc/html/rfc8446) in pure V language for learning purposes.

## Status
> [!Warning]
>
> Implementing TLS 1.3 is a hard and full of cullprits that you should aware.
> Its does not finished yet and no recommended for production use,
> Its intended only for learning purposes.
> 
> Basic of messages parsing, handshake processing, decryption/encryption record, key scheduling almost has been implemented.
> With strict and limited configuration of `openssl s_server` command for local testing below,
> It can perform full TLS 1.3 handshake phase and send application data

> [!Note]
> This module depends on some of v modules availables at this github repository.
> Install its before to run some test.

Its only supports limited subset of TLS 1.3 standard (maybe get updated in time)
- Client only (server maybe in plan)
- Strict limited to only 1.3 version of standard (no plan for support for older version)
- Only support TLS_CHACHA20_POLY1305_SHA256 ciphersuite 
- Only support ed25519 for SignatureScheme extensions
- Only support x25519 NamedGroup for Elliptic Curve Groups (ECDHE) key exchange
- support for server_name extension
- support key_share extension only through x25519 NamedGroup
- Doesn't support HelloRetryRequest message
- Doesn't support verify server Certificate, only parse it (currently, we have no armor for this)
- And many others stuff does not supported yet thats can bring to panic (error)

### File layout description
```bash
├── alert.v                    -> Basic handling and parsing TLS 1.3 Alert message
├── ciphersuite.v              -> Basic ciphersuite handling, packing and unpacking
├── ciphersuite_test.v
├── extension.v                -> Support for TLS 1.3 Extensions, some of them lives in separates files
├── extension_test.v
├── handshake.v                -> Core TLS 1.3 Handshake message handling, from packing and unpacking, validation, and general use cases
├── handshake_test.v
├── hkdf.v                     -> Hmac Key Derivation Function, used for key derivation and traffic calculation
├── keys.v                      
├── keyschedule.v              -> Key update scheduling for secret derivation and traffic keys calculation
├── keyschedule_test.v
├── keyshare.v                 -> key_share extension handling
├── keyshare_test.v
├── psk.v                      -> preshared key support (not usable currently)
├── record.v                   -> Contains fundamental TLS 1.3 record structure, basic parsing and unpacking, small utility to help serialization
├── record_test.v
├── recordlayer.v              -> High level record layer, handle encryption decryption, fragmentation (not yet ready)
├── servername.v               -> server_name extension support
├── servername_test.v
├── session.v                  -> Core TLS 1.3 client capable performing handshake and related task, write record to the wire, read record from wire.
├── session_handshaker.v       -> Core how the session performing TLS 1.3 handshake process
├── signaturescheme.v          -> signature_scheme extension support
├── signaturescheme_test.v
├── state.v                    -> Session state handling
├── supportedgroups.v          -> supported_groups extension support
├── supportedgroups_test.v
├── supportedversions.v        -> supported_versions extension support
├── supportedversions_test.v
├── transcripter.v             -> Message hash tool for hash transcripting of the handshake messages
└── version.v                  -> basic version structure represent TLS 1.3 version
```

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
or you can use cloned [`wolfssl`](https://github.com/wolfssl/wolfssl), configure the build with `--enable-tls13 --enable-curve25519 --enable-ed25519` and run example server from examples directory
```
➜ ~/wolfssl (master) $ ./examples/server/server -d -b -g -verbose -p 8443 -v 4 -c ./certs/ed25519/server-ed25519-cert.pem -k ./certs/ed25519/server-ed25519-priv.pem
```

### Test client 
```bash
$openssl s_client -connect localhost:8443
```

### Run test main.v
```bash
$v run main.v 
```

Here's some output from client 
```
$ v -d trace_ssl run src/main.v
2023-12-19 03:05:29.828695 [INFO ] Initializing TCP Connection to 127.0.0.1:8443
2023-12-19 03:05:29.829303 [INFO ] State: ts_init
2023-12-19 03:05:29.837817 [INFO ] State: ts_client_hello
2023-12-19 03:05:29.838043 [INFO ] State: ts_server_hello
2023-12-19 03:05:29.838164 [INFO ] parse_tls_message .. handshake
2023-12-19 03:05:29.838208 [INFO ] parse_server_hsk_msg..server_hello
2023-12-19 03:05:29.838242 [INFO ] parse_server_hello
2023-12-19 03:05:29.846931 [INFO ] State: ts_encrypted_extensions
2023-12-19 03:05:29.847135 [INFO ] parse_tls_message .. handshake
2023-12-19 03:05:29.847163 [INFO ] parse_server_hsk_msg..encrypted_extensions
2023-12-19 03:05:29.847200 [INFO ] State: ts_server_certificate_request
2023-12-19 03:05:29.848056 [INFO ] parse_tls_message .. handshake
2023-12-19 03:05:29.848082 [INFO ] parse_server_hsk_msg..certificate
2023-12-19 03:05:29.848272 [INFO ] State: ts_server_certificate_verify
2023-12-19 03:05:29.848491 [INFO ] parse_tls_message .. handshake
2023-12-19 03:05:29.848514 [INFO ] parse_server_hsk_msg..certificate_verify
2023-12-19 03:05:29.848557 [INFO ] State: ts_server_finished
2023-12-19 03:05:29.848750 [INFO ] parse_tls_message .. handshake
2023-12-19 03:05:29.848783 [INFO ] parse_server_hsk_msg..finished
2023-12-19 03:05:29.849881 [INFO ] State: ts_client_finished
2023-12-19 03:05:29.850375 [INFO ] Perform Session.send_client_finished_msg ...
2023-12-19 03:05:29.850569 [INFO ] State: ts_connected
2023-12-19 03:05:29.850598 [INFO ] State: ts_application_data
2023-12-19 03:05:29.850612 [INFO ] App-data
[/workspaces/doglon/src/tls13/session_common.v:133] ses.tickets: []
[src/main.v:30] request: GET / HTTP/1.1
Host: localhost:8443
2023-12-19 03:05:29.850772 [INFO ] Successfully write 59 bytes encrypted of application data
[src/main.v:46] rec.str(): TLSPlaintext:type=application_data:length=225:fragment=HTTP/1.1 200 OK
Content-Type: text/html
Connection: close
Content-Length: 141

<html>
<head>
<title>Welcome to wolfSSL!</title>
</head>
<body>
<p>wolfSSL has successfully performed handshake!</p>
</body>
</html>

2023-12-19 03:05:29.853783 [INFO ] Do Session.close
2023-12-19 03:05:29.853943 [INFO ] Successfully write alert CLOSE_NOTIFY 24 bytes
```

&copy;[blackshirt](https://github.com/blackshirt/tls13)
