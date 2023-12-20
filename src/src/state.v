module tls13

// TLS 1.3 client state
enum TlsState {
	ts_closed                     = 0
	ts_init                       = 1
	ts_client_hello               = 2
	ts_early_data                 = 3
	ts_server_hello               = 4
	ts_server_hello_2             = 5
	ts_change_cipher_spec         = 6 // ccs is ignored in TLS 1.3
	ts_encrypted_extensions       = 7
	ts_server_certificate_request = 8
	ts_server_certificate         = 9
	ts_server_certificate_verify  = 10
	ts_server_finished            = 11
	ts_endof_early_data           = 12
	ts_client_certificate         = 13
	ts_client_certificate_verify  = 14
	ts_client_finished            = 15
	ts_key_update                 = 16
	ts_connected                  = 17 // intermediate state
	ts_application_data           = 18
	ts_closing                    = 19
}

// tls_state returns current session state
fn (ses Session) tls_state() TlsState {
	return ses.tstate
}

// on_closed_state returns true if session in .ts_closed state
fn (ses Session) on_closed_state() bool {
	return ses.tls_state() == .ts_closed
}

// on_closing_state returns true if session in ongoing to .ts_closing state
fn (ses Session) on_closing_state() bool {
	return ses.tls_state() == .ts_closing
}

// change_tls_state does transition to `to` state
fn (mut ses Session) change_tls_state(to TlsState) {
	if ses.tstate == to {
		return
	}
	ses.tstate = to
}

// reset_tls_state resets back Session state to .ts_closed
fn (mut ses Session) reset_tls_state() {
	ses.change_tls_state(.ts_closed)
}
