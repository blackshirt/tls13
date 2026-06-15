module main

import os
import log
import tls13

struct ClientConfig {
mut:
	address     string = 'localhost:8443'
	server_name string
	message     string = 'Test data for TLS 1.3'
	http_path   string
	read_reply  bool = true
	read_all    bool
	show_tickets bool = true
	compat      bool
}

fn usage() {
	println('TLS 1.3 client demo')
	println('')
	println('Usage:')
	println('  v run main.v [options]')
	println('')
	println('Options:')
	println('  --connect host:port       TCP endpoint to connect to (default: localhost:8443)')
	println('  --servername name        SNI hostname to send in ClientHello')
	println('  --message text           Application data to send after the handshake')
	println('  --http path              Send a simple HTTP/1.1 GET for path instead of --message')
	println('  --no-read                Do not wait for application data after writing')
	println('  --read-all               Keep reading application data until close_notify/EOF')
	println('  --no-tickets             Do not print received NewSessionTicket messages')
	println('  --compat                 Enable TLS 1.3 middlebox compatibility mode')
	println('  --help                   Show this help')
}

fn parse_args(args []string) !ClientConfig {
	mut cfg := ClientConfig{}
	mut i := 1
	for i < args.len {
		arg := args[i]
		if arg == '--help' || arg == '-h' {
			usage()
			exit(0)
		} else if arg.starts_with('--connect=') {
			cfg.address = arg['--connect='.len..]
		} else if arg == '--connect' {
			i++
			if i >= args.len {
				return error('--connect requires a value')
			}
			cfg.address = args[i]
		} else if arg.starts_with('--servername=') {
			cfg.server_name = arg['--servername='.len..]
		} else if arg == '--servername' {
			i++
			if i >= args.len {
				return error('--servername requires a value')
			}
			cfg.server_name = args[i]
		} else if arg.starts_with('--message=') {
			cfg.message = arg['--message='.len..]
		} else if arg == '--message' {
			i++
			if i >= args.len {
				return error('--message requires a value')
			}
			cfg.message = args[i]
		} else if arg.starts_with('--http=') {
			cfg.http_path = arg['--http='.len..]
		} else if arg == '--http' {
			i++
			if i >= args.len {
				return error('--http requires a value')
			}
			cfg.http_path = args[i]
		} else if arg == '--no-read' {
			cfg.read_reply = false
		} else if arg == '--read-all' {
			cfg.read_all = true
		} else if arg == '--no-tickets' {
			cfg.show_tickets = false
		} else if arg == '--compat' {
			cfg.compat = true
		} else {
			if arg.starts_with('-') {
				return error('unknown option: ${arg}')
			}
			cfg.address = arg
		}
		i++
	}
	return cfg
}

fn host_from_address(address string) string {
	if address.starts_with('[') {
		end := address.index(']') or { return address }
		return address[1..end]
	}
	parts := address.split(':')
	if parts.len > 1 {
		return parts[0]
	}
	return address
}

fn application_payload(cfg ClientConfig) []u8 {
	if cfg.http_path.len == 0 {
		return cfg.message.bytes()
	}
	host := if cfg.server_name.len > 0 { cfg.server_name } else { host_from_address(cfg.address) }
	path := if cfg.http_path.starts_with('/') { cfg.http_path } else { '/${cfg.http_path}' }
	request := 'GET ${path} HTTP/1.1\r\nHost: ${host}\r\nUser-Agent: tls13-v-client\r\nConnection: close\r\n\r\n'
	return request.bytes()
}

fn run() ! {
	cfg := parse_args(os.args)!
	server_name := if cfg.server_name.len > 0 { cfg.server_name } else { host_from_address(cfg.address) }
	opt := tls13.Options{
		server_name: server_name
		compat:      cfg.compat
	}

	log.info('Connecting to ${cfg.address} with SNI ${server_name}')
	mut ses := tls13.dial(cfg.address, opt)!
	defer {
		ses.close() or { log.warn('close failed: ${err}') }
	}
	if !ses.connected() {
		return error('TLS session did not reach application data state')
	}
	log.info('TLS 1.3 handshake completed')

	payload := application_payload(cfg)
	written := ses.write_application_data(payload)!
	log.info('Wrote ${written} encrypted bytes')

	if cfg.read_reply {
		for {
			reply := ses.read_application_data()!
			if reply.len == 0 {
				log.info('Peer closed application data stream')
				break
			}
			print(reply.bytestr())
			if !cfg.read_all {
				break
			}
		}
	}

	if cfg.show_tickets {
		tickets := ses.tickets()
		log.info('Received ${tickets.len} session ticket(s)')
		dump(tickets)
	}
}

fn main() {
	run() or {
		eprintln('tls13 client failed: ${err}')
		eprintln('Use --help for usage.')
		exit(1)
	}
}
