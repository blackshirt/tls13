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
$openssl s_server -accept 8443 -tls1_3 -state -tlsextdebug -debug -msg -cert key/pubcert.pem -key key/privkey.pem
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
$ v run examples/main.v
2023-12-20 08:39:12.902000 [INFO ] Initializing TCP Connection to [::1]:8443
2023-12-20 08:39:12.902000 [INFO ] State: ts_init
2023-12-20 08:39:12.918000 [INFO ] State: ts_client_hello
2023-12-20 08:39:12.918000 [INFO ] State: ts_server_hello
2023-12-20 08:39:13.027000 [INFO ] parse_tls_message .. handshake
2023-12-20 08:39:13.027000 [INFO ] parse_server_hsk_msg..server_hello
2023-12-20 08:39:13.043000 [INFO ] parse_server_hello
2023-12-20 08:39:13.043000 [INFO ] State: ts_encrypted_extensions
2023-12-20 08:39:13.043000 [INFO ] parse_tls_message .. handshake
2023-12-20 08:39:13.043000 [INFO ] parse_server_hsk_msg..encrypted_extensions
2023-12-20 08:39:13.043000 [INFO ] State: ts_server_certificate_request
2023-12-20 08:39:13.043000 [INFO ] parse_tls_message .. handshake
2023-12-20 08:39:13.043000 [INFO ] parse_server_hsk_msg..certificate
2023-12-20 08:39:13.043000 [INFO ] State: ts_server_certificate_verify
2023-12-20 08:39:13.043000 [INFO ] parse_tls_message .. handshake
2023-12-20 08:39:13.043000 [INFO ] parse_server_hsk_msg..certificate_verify
2023-12-20 08:39:13.043000 [INFO ] State: ts_server_finished
2023-12-20 08:39:13.043000 [INFO ] parse_tls_message .. handshake
2023-12-20 08:39:13.043000 [INFO ] parse_server_hsk_msg..finished
2023-12-20 08:39:13.043000 [INFO ] State: ts_client_finished
2023-12-20 08:39:13.043000 [INFO ] Perform Session.send_client_finished_msg ...
2023-12-20 08:39:13.043000 [INFO ] State: ts_connected
2023-12-20 08:39:13.043000 [INFO ] State: ts_application_data
2023-12-20 08:39:13.043000 [INFO ] Reached ts_application_data
2023-12-20 08:39:15.137000 [INFO ] Successfully write 43 bytes encrypted of application data
[examples/main.v:22] ses.tickets(): [tls13.NewSessionTicket{
    tkt_lifetime: 7200
    tkt_ageadd: 588320674
    tkt_nonce: [0, 0, 0, 0, 0, 0, 0, 0]
    ticket: [168, 213, 217, 42, 45, 33, 244, 239, 193, 90, 109, 190, 182, 237, 79, 36, 118, 139, 93, 187, 247, 26, 114, 26, 95, 116, 153, 53, 141, 44, 46, 251, 237, 95, 157, 159, 34, 124, 7, 231, 153, 66, 90, 186, 68, 255, 183, 71, 176, 25, 64, 207, 205, 203, 91, 68, 37, 136, 159, 116, 18, 244, 123, 229, 8, 85, 153, 91, 126, 231, 156, 191, 80, 46, 47, 246, 224, 35, 83, 66, 63, 173, 114, 28, 248, 205, 88, 159, 109, 180, 233, 27, 108, 234, 6, 10, 18, 60, 72, 112, 255, 179, 219, 81, 52, 17, 183, 3, 24, 160, 131, 202, 162, 148, 238, 101, 103, 89, 7, 159, 171, 77, 45, 70, 216, 4, 35, 104, 236, 237, 144, 102, 114, 109, 229, 188, 68, 225, 114, 90, 17, 11, 221, 102, 136, 187, 70, 135, 191, 139, 234, 214, 40, 30, 93, 215, 169, 133, 207, 150, 238, 26, 204, 43, 225, 86, 251, 11, 115, 27, 84, 156, 239, 208, 127, 76]
    extensions: []
}, tls13.NewSessionTicket{
    tkt_lifetime: 7200
    tkt_ageadd: 2309927506
    tkt_nonce: [0, 0, 0, 0, 0, 0, 0, 1]
    ticket: [168, 213, 217, 42, 45, 33, 244, 239, 193, 90, 109, 190, 182, 237, 79, 36, 93, 36, 246, 29, 28, 213, 176, 200, 215, 253, 157, 243, 123, 39, 198, 157, 111, 178, 79, 89, 100, 57, 185, 179, 92, 224, 244, 126, 83, 240, 76, 200, 88, 131, 140, 42, 236, 134, 76, 233, 107, 135, 210, 62, 204, 119, 180, 34, 185, 180, 80, 74, 53, 236, 204, 109, 195, 228, 62, 38, 1, 221, 126, 108, 239, 19, 36, 11, 63, 113, 25, 73, 153, 106, 114, 250, 125, 203, 72, 99, 161, 174, 225, 244, 30, 60, 28, 137, 78, 35, 55, 207, 246, 54, 252, 91, 198, 46, 195, 207, 88, 90, 110, 40, 13, 146, 108, 75, 253, 117, 20, 224, 13, 215, 133, 103, 2, 216, 52, 183, 75, 38, 145, 125, 90, 146, 62, 166, 104, 23, 229, 52, 167, 228, 230, 19, 141, 173, 16, 136, 120, 10, 46, 18, 1, 230, 223, 156, 58, 168, 152, 31, 63, 255, 95, 194, 214, 93, 10, 60, 205, 250, 7, 198, 15, 71, 49, 249, 205, 116, 114, 193, 139, 254, 228, 24]
    extensions: []
}]
2023-12-20 08:39:15.137000 [INFO ] Do Session.close
2023-12-20 08:39:15.137000 [INFO ] Successfully write alert CLOSE_NOTIFY 24 bytes
```

If we see on the `openssl s_server` console command, we saw output that verifies what's going on 
```bash
read from 0x2309a1049d0 [0x2309a16cc38] (38 bytes => 38 (0x26))
0000 - df 2a 17 3d 1f 69 f3 61-2e 2e a6 c0 c6 82 67 61   .*.=.i.a......ga
0010 - 63 ce 11 f4 16 0b 0c 9b-64 55 7d 76 22 e1 ab 44   c.......dU}v"..D
0020 - 78 56 30 7b 2a d1                                 xV0{*.
<<< TLS 1.3 [length 0001]
    17
Test data for TLS 1.3read from 0x2309a1049d0 [0x2309a16cc33] (5 bytes => 5 (0x5))
0000 - 17 03 03 00 13                                    .....
<<< ??? [length 0005]
    17 03 03 00 13
read from 0x2309a1049d0 [0x2309a16cc38] (19 bytes => 19 (0x13))
0000 - 4a 59 d5 44 85 7e db dc-5b 0c 43 5d 00 c8 90 d7   JY.D.~..[.C]....
0010 - b9 2e 5e                                          ..^
<<< TLS 1.3 [length 0001]
    15
<<< TLS 1.3, Alert [length 0002], warning close_notify
    01 00
SSL3 alert read:warning:close notify
DONE
shutting down SSL
CONNECTION CLOSED
```

&copy;[blackshirt](https://github.com/blackshirt/tls13)
