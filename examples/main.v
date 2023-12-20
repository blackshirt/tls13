module main

import log
import net
import blackshirt.tls13

fn main() {
	mut conn := net.dial_tcp('localhost:8443')!
	log.info('Initializing TCP Connection to ${conn.peer_ip()!}')
	opt := tls13.Options{}
	mut ses := tls13.new_session(mut conn, opt)!

	// perform TLS 1.3 handshake
	ses.do_full_handshake()!
	ses.do_post_handshake()!

	data := 'Test data for TLS 1.3'.bytes()
	n := ses.write_application_data(data)!
	log.info('Successfully write ${n} bytes encrypted of application data')

	// check we gets session tickets
	dump(ses.tickets())
	// close underlying socket
	// ses.close()! internally sent close_notify alert to the peer
	ses.close()!
}
