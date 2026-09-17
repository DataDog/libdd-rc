package libddrcffi

// connLifecycle tracks whether a Connection has been marked as connected
// and/or closed, and centralizes the guard checks Connected/Close/Recv need
// before crossing the FFI boundary.
//
// rc-x509-client panics rather than reporting an error when it is driven out
// of order, which would abort the host process, so these transitions are
// checked here first. Callers are expected to serialize access (Connection
// does so by holding its own mutex across every method below).
type connLifecycle struct {
	closed    bool
	connected bool
}

// markConnected transitions to connected, or reports why it cannot.
func (l *connLifecycle) markConnected() error {
	if l.closed {
		return ErrConnectionClosed
	}
	if l.connected {
		return ErrConnectionAlreadyConnected
	}
	l.connected = true
	return nil
}

// markClosed transitions to closed, or reports that it already was.
// wasConnected reports whether markConnected had previously succeeded,
// which callers need to decide whether rc_conn_disconnected may be called:
// doing so without a prior Connected is a protocol error.
func (l *connLifecycle) markClosed() (wasConnected bool, err error) {
	if l.closed {
		return false, ErrConnectionClosed
	}
	wasConnected = l.connected
	l.closed = true
	return wasConnected, nil
}

// checkRecvable reports whether Recv may proceed.
func (l *connLifecycle) checkRecvable() error {
	if l.closed {
		return ErrConnectionClosed
	}
	if !l.connected {
		return ErrConnectionNotConnected
	}
	return nil
}
