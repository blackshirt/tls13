module main

import log
import net
import strings
import tls13

fn main() {
	// mut conn := net.dial_tcp('tls13.1d.pw:443')!
	mut conn := net.dial_tcp('localhost:8443')!
	log.info('Initializing TCP Connection to ${conn.peer_ip()!}')
	opt := tls13.Options{}
	mut ses := tls13.new_session(conn, opt)!

	ses.do_handshake()!

	mut sb := strings.new_builder(1024)
	defer {
		unsafe { sb.free() }
	}
	sb.write_string('GET ')
	sb.write_string('/')
	sb.write_string(' HTTP/1.1\r\nHost: ')
	sb.write_string('tls13.1d.pw')
	sb.write_string(':')
	sb.write_string('443\n')

	gets := sb.str()
	dump(gets)
	data := gets.bytes()
	n := ses.write_application_data(data)!
	log.info('Successfully write ${n} bytes encrypted of application data')

	// this read newsessionticket mesasge from server
	// _, rec := ses.read_raw_record()!
	// pxt, _ := ses.decrypt(rec)!
	// dump(pxt)
	// assert pxt.ctn_type == .handshake
	// hsk := tls13.Handshake.unpack(pxt.fragment)!
	// dump(hsk)
	// assert hsk.msg_type == .new_session_ticket

	// close underlying socket
	// ses.close()! internally sent close_notify alert to the peer
	ses.close()!
}
