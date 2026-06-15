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

// can_transition_tls_state reports whether the client state machine permits from -> to.
fn can_transition_tls_state(from TlsState, to TlsState) bool {
	if from == to {
		return true
	}
	// Fatal alerts and local teardown may close from any state.
	if to == .ts_closed {
		return true
	}
	match from {
		.ts_closed {
			return to == .ts_init
		}
		.ts_init {
			return to == .ts_client_hello
		}
		.ts_client_hello {
			return to == .ts_server_hello || to == .ts_server_hello_2
		}
		.ts_server_hello {
			return to == .ts_client_hello || to == .ts_encrypted_extensions || to == .ts_closing
		}
		.ts_server_hello_2 {
			return to == .ts_encrypted_extensions || to == .ts_closing
		}
		.ts_encrypted_extensions {
			return to == .ts_server_certificate_request || to == .ts_server_finished
		}
		.ts_server_certificate_request {
			return to == .ts_server_certificate || to == .ts_server_certificate_verify
		}
		.ts_server_certificate {
			return to == .ts_server_certificate_verify
		}
		.ts_server_certificate_verify {
			return to == .ts_server_finished
		}
		.ts_server_finished {
			return to == .ts_client_certificate || to == .ts_client_finished
		}
		.ts_client_certificate {
			return to == .ts_client_certificate_verify || to == .ts_client_finished
		}
		.ts_client_certificate_verify {
			return to == .ts_client_finished
		}
		.ts_client_finished {
			return to == .ts_connected
		}
		.ts_connected {
			return to == .ts_application_data
		}
		.ts_application_data {
			return to == .ts_key_update || to == .ts_closing
		}
		.ts_key_update {
			return to == .ts_application_data
		}
		.ts_closing {
			return to == .ts_closed
		}
		.ts_early_data {
			return to == .ts_endof_early_data || to == .ts_server_hello
		}
		.ts_endof_early_data {
			return to == .ts_server_finished
		}
		.ts_change_cipher_spec {
			return to == .ts_server_hello || to == .ts_encrypted_extensions
		}
	}
}

// require_tls_state validates that the session is currently in one of the expected states.
fn (ses Session) require_tls_state(expected []TlsState, context string) ! {
	if ses.tls_state() in expected {
		return
	}
	return error('${context}: bad state ${ses.tls_state()}, expected ${expected}')
}

// transition_tls_state validates and applies a state transition.
fn (mut ses Session) transition_tls_state(to TlsState) ! {
	from := ses.tstate
	if !can_transition_tls_state(from, to) {
		return error('illegal TLS state transition ${from} -> ${to}')
	}
	ses.tstate = to
}

// change_tls_state does transition to `to` state.
// Internal callers historically used this infallible helper, so it panics on
// invalid transitions instead of silently corrupting the state machine.
fn (mut ses Session) change_tls_state(to TlsState) {
	if ses.tstate == to {
		return
	}
	ses.transition_tls_state(to) or { panic(err) }
}

// reset_tls_state resets back Session state to .ts_closed
fn (mut ses Session) reset_tls_state() {
	ses.change_tls_state(.ts_closed)
}
