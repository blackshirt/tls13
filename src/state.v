module tls13

// Tls 1.3 client state
enum State {
	closed               = 0
	init                 = 1
	start                = 2
	wait_sh              = 3
	wait_ee              = 4
	wait_cert_or_certreq = 5 // wait for Certificate or CertificateRequest
	wait_certificate     = 6
	wait_certverify      = 7
	wait_finished        = 8
	end_early_data       = 9
	connected            = 10
	application_data     = 11
}

pub fn (s State) str() string {
	match s {
		.closed { return 'CLOSED' }
		.init { return 'INIT' }
		.start { return 'START' }
		.wait_sh { return 'WAIT_FOR_SERVERHELLO' }
		.wait_ee { return 'WAIT_FOR_ENCRYPTED_EXTENSIONS' }
		.wait_cert_or_certreq { return 'WAIT_FOR_CERT_OR_CERTREQUEST' }
		.wait_certificate { return 'WAIT_FOR_CERTIFICATE' }
		.wait_certverify { return 'WAIT_FOR_CERT_VERIFY' }
		.wait_finished { return 'WAIT_FOR_FINISHED' }
		.end_early_data { return 'END_OF_EARLY_DATA' }
		.connected { return 'CONNECTED' }
		.application_data { return 'APPLICATION_DATA' }
	}
}

// Session state routines
//		
// state returns the current state of the Session
// TODO: for support concurrent access, add locking necessarily
pub fn (ses Session) state() State {
	return ses.state
}

fn (ses Session) state_is_closed() bool {
	return ses.state() == .closed
}

// change_to_state sets current state of the Session to new state
fn (mut ses Session) change_to_state(new_state State) {
	// if current state match with provided new state,
	// just do nothing, otherwise, set state to new state.
	if ses.state() == new_state {
		return
	}

	ses.state = new_state
}

// protection_is_active tells whether this tls context has an encryption
// or decryption should be performed or not. For TLS 1.3, after the client
// receives ServerHello message, encryption mechanism should be in active state onward.
fn (mut ses Session) protection_is_active() bool {
	return int(ses.state()) >= int(State.wait_ee)
}

// hsk_started tells whether handshake has been started
fn (mut ses Session) hsk_started() bool {
	return int(ses.state()) >= int(State.start)
}

// hsk_not_finished returns false if the Session is not in .connected state
fn (mut ses Session) hsk_not_finished() bool {
	return ses.hsk_started() && ses.state() != .connected
}

fn (mut ses Session) hsk_not_completed() bool {
	return ses.hsk_started() && int(ses.state()) < int(State.application_data)
}

// reset_state resets Session state to .closed state
fn (mut ses Session) reset_state() {
	ses.change_to_state(.closed)
}
